use anyhow::{Context, Result, bail};
use libloading::{Library, Symbol};
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::time::Instant;

const PTX: &str = concat!(include_str!("../kernels/saxpy.ptx"), "\0");

type Dev = c_int;
type Ctx = *mut c_void;
type Module = *mut c_void;
type Function = *mut c_void;
type DevPtr = u64;

pub struct Cuda {
    lib: Library,
    // Keeps the preloaded libcrypto resident; declared after `lib` so it
    // drops after libcuda.
    _libcrypto: Option<libloading::os::unix::Library>,
    ctx: Ctx,
    pub device: String,
}

// The raw context pointer is only ever used under the owner's mutex.
unsafe impl Send for Cuda {}

fn check(step: &str, code: c_int) -> Result<()> {
    if code != 0 {
        bail!("{step}: CUDA_ERROR {code}");
    }
    Ok(())
}

macro_rules! sym {
    ($lib:expr, $name:literal, $ty:ty) => {{
        let s: Symbol<$ty> = unsafe { $lib.get($name) }
            .with_context(|| format!("libcuda has no {}", String::from_utf8_lossy($name)))?;
        s
    }};
}

/// A device allocation, freed on drop. Every exit path from a function
/// holding one, including an early `?`, releases the buffer.
struct DevAlloc<'a> {
    cuda: &'a Cuda,
    ptr: DevPtr,
}

impl<'a> DevAlloc<'a> {
    fn new(cuda: &'a Cuda, bytes: usize) -> Result<Self> {
        let ptr = cuda.alloc(bytes)?;
        Ok(Self { cuda, ptr })
    }
}

impl Drop for DevAlloc<'_> {
    fn drop(&mut self) {
        self.cuda.free(self.ptr);
    }
}

/// A loaded module, unloaded on drop.
struct ModuleGuard<'a> {
    cuda: &'a Cuda,
    module: Module,
}

impl<'a> ModuleGuard<'a> {
    fn load(cuda: &'a Cuda, ptx: &str) -> Result<Self> {
        let load = sym!(
            cuda.lib,
            b"cuModuleLoadData",
            unsafe extern "C" fn(*mut Module, *const c_void) -> c_int
        );
        let mut module: Module = std::ptr::null_mut();
        check("cuModuleLoadData", unsafe {
            load(&mut module, ptx.as_ptr().cast())
        })?;
        Ok(Self { cuda, module })
    }

    fn function(&self, name: &CStr) -> Result<Function> {
        let get_fn = sym!(
            self.cuda.lib,
            b"cuModuleGetFunction",
            unsafe extern "C" fn(*mut Function, Module, *const c_char) -> c_int
        );
        let mut func: Function = std::ptr::null_mut();
        check("cuModuleGetFunction", unsafe {
            get_fn(&mut func, self.module, name.as_ptr())
        })?;
        Ok(func)
    }
}

impl Drop for ModuleGuard<'_> {
    fn drop(&mut self) {
        self.cuda.unload(self.module);
    }
}

impl Cuda {
    pub fn open() -> Result<Self> {
        // In confidential-computing mode libcuda dlopens a pkcs11 OpenSSL
        // shim needing libcrypto.so.3, but only driver libraries are
        // injected into this volume; preload our own into the global scope
        // so the shim's NEEDED entry resolves without a search path.
        let _libcrypto = match option_env!("CUDA_PROBE_LIBCRYPTO") {
            Some(path) => Some(
                unsafe {
                    libloading::os::unix::Library::open(
                        Some(path),
                        libloading::os::unix::RTLD_NOW | libloading::os::unix::RTLD_GLOBAL,
                    )
                }
                .context("dlopen libcrypto")?,
            ),
            None => None,
        };
        let lib = unsafe { Library::new("libcuda.so.1") }.context("dlopen libcuda.so.1")?;
        let init = sym!(lib, b"cuInit", unsafe extern "C" fn(c_uint) -> c_int);
        check("cuInit", unsafe { init(0) })?;
        let mut dev: Dev = 0;
        let get = sym!(
            lib,
            b"cuDeviceGet",
            unsafe extern "C" fn(*mut Dev, c_int) -> c_int
        );
        check("cuDeviceGet", unsafe { get(&mut dev, 0) })?;
        let mut name = [0 as c_char; 128];
        let get_name = sym!(
            lib,
            b"cuDeviceGetName",
            unsafe extern "C" fn(*mut c_char, c_int, Dev) -> c_int
        );
        check("cuDeviceGetName", unsafe {
            get_name(name.as_mut_ptr(), 128, dev)
        })?;
        let device = unsafe { CStr::from_ptr(name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let mut ctx: Ctx = std::ptr::null_mut();
        let create = sym!(
            lib,
            b"cuCtxCreate_v2",
            unsafe extern "C" fn(*mut Ctx, c_uint, Dev) -> c_int
        );
        check("cuCtxCreate", unsafe { create(&mut ctx, 0, dev) })?;
        Ok(Self {
            lib,
            _libcrypto,
            ctx,
            device,
        })
    }

    fn bind(&self) -> Result<()> {
        let set = sym!(
            self.lib,
            b"cuCtxSetCurrent",
            unsafe extern "C" fn(Ctx) -> c_int
        );
        check("cuCtxSetCurrent", unsafe { set(self.ctx) })
    }

    fn alloc(&self, bytes: usize) -> Result<DevPtr> {
        let f = sym!(
            self.lib,
            b"cuMemAlloc_v2",
            unsafe extern "C" fn(*mut DevPtr, usize) -> c_int
        );
        let mut p: DevPtr = 0;
        check("cuMemAlloc", unsafe { f(&mut p, bytes) })?;
        Ok(p)
    }

    fn free(&self, p: DevPtr) {
        if let Ok(f) = unsafe {
            self.lib
                .get::<unsafe extern "C" fn(DevPtr) -> c_int>(b"cuMemFree_v2")
        } {
            unsafe { f(p) };
        }
    }

    fn unload(&self, m: Module) {
        if let Ok(f) = unsafe {
            self.lib
                .get::<unsafe extern "C" fn(Module) -> c_int>(b"cuModuleUnload")
        } {
            unsafe { f(m) };
        }
    }

    fn h2d<T>(&self, dst: DevPtr, src: &[T]) -> Result<()> {
        let f = sym!(
            self.lib,
            b"cuMemcpyHtoD_v2",
            unsafe extern "C" fn(DevPtr, *const c_void, usize) -> c_int
        );
        check("cuMemcpyHtoD", unsafe {
            f(dst, src.as_ptr().cast(), std::mem::size_of_val(src))
        })
    }

    fn d2h<T>(&self, dst: &mut [T], src: DevPtr) -> Result<()> {
        let f = sym!(
            self.lib,
            b"cuMemcpyDtoH_v2",
            unsafe extern "C" fn(*mut c_void, DevPtr, usize) -> c_int
        );
        check("cuMemcpyDtoH", unsafe {
            f(dst.as_mut_ptr().cast(), src, std::mem::size_of_val(dst))
        })
    }

    /// y = 3x + y over n floats with x[i] = i, y[i] = 2i; every y[i] must be
    /// exactly 5i (all values stay below 2^24, so f32 is exact).
    pub fn saxpy(&self, n: u32) -> Result<bool> {
        self.bind()?;
        let module = ModuleGuard::load(self, PTX)?;
        let name = CString::new("saxpy")?;
        let func = module.function(&name)?;

        let x: Vec<f32> = (0..n).map(|i| i as f32).collect();
        let mut y: Vec<f32> = (0..n).map(|i| 2.0 * i as f32).collect();
        let bytes = n as usize * 4;
        let dx = DevAlloc::new(self, bytes)?;
        let dy = DevAlloc::new(self, bytes)?;
        self.h2d(dx.ptr, &x)?;
        self.h2d(dy.ptr, &y)?;
        let mut a: f32 = 3.0;
        let (mut px, mut py, mut pn) = (dx.ptr, dy.ptr, n);
        let mut params: [*mut c_void; 4] = [
            (&mut a as *mut f32).cast(),
            (&mut px as *mut DevPtr).cast(),
            (&mut py as *mut DevPtr).cast(),
            (&mut pn as *mut u32).cast(),
        ];
        let launch = sym!(
            self.lib,
            b"cuLaunchKernel",
            unsafe extern "C" fn(
                Function,
                c_uint,
                c_uint,
                c_uint,
                c_uint,
                c_uint,
                c_uint,
                c_uint,
                *mut c_void,
                *mut *mut c_void,
                *mut *mut c_void,
            ) -> c_int
        );
        let block = 256u32;
        check("cuLaunchKernel", unsafe {
            launch(
                func,
                n.div_ceil(block),
                1,
                1,
                block,
                1,
                1,
                0,
                std::ptr::null_mut(),
                params.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        })?;
        let sync = sym!(
            self.lib,
            b"cuCtxSynchronize",
            unsafe extern "C" fn() -> c_int
        );
        check("cuCtxSynchronize", unsafe { sync() })?;
        self.d2h(&mut y, dy.ptr)?;
        Ok(y.iter().enumerate().all(|(i, v)| *v == 5.0 * i as f32))
    }

    /// Round trip of `mib` MiB through the (encrypted, bounce-buffered) PCIe
    /// path. Returns (h2d MiB/s, d2h MiB/s, contents equal).
    pub fn bandwidth(&self, mib: usize) -> Result<(f64, f64, bool)> {
        self.bind()?;
        let bytes = mib << 20;
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let src: Vec<u64> = (0..bytes / 8)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            })
            .collect();
        let mut back = vec![0u64; src.len()];
        let d = DevAlloc::new(self, bytes)?;
        let t = Instant::now();
        self.h2d(d.ptr, &src)?;
        let up = mib as f64 / t.elapsed().as_secs_f64();
        let t = Instant::now();
        self.d2h(&mut back, d.ptr)?;
        let down = mib as f64 / t.elapsed().as_secs_f64();
        Ok((up, down, src == back))
    }
}
