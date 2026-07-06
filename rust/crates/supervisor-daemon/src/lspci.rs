//! lspci GPU inventory, a literal port of src/aleph/vm/resources.py.
//!
//! Same invocation (`lspci -mmnnn` for the listing, `lspci -s <addr> -nnk`
//! for the per-device kernel driver check), same field extraction, same
//! vfio-pci requirement, same vendor whitelist (NVIDIA/AMD/Intel; any other
//! vendor on a vfio-bound GPU is an error, as in Python where
//! get_vendor_name raises ValueError). Like the Python pool, the inventory
//! is collected once at daemon startup and only when ENABLE_GPU_SUPPORT is
//! set.

use std::collections::HashSet;
use std::process::Command;

use crate::error::DaemonError;

/// A GPU as lspci reports it. Field order matters: it is the
/// pydantic model_dump / JSON key order of the Python GpuDevice
/// (vendor, device_name, device_class, pci_host, device_id), carried
/// verbatim in HostInfo.gpu_inventory_json.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct GpuDevice {
    /// Vendor name on the whitelist: "NVIDIA", "AMD" or "Intel".
    pub vendor: String,
    /// Card name as lspci prints it, e.g. "GB202 [GeForce RTX 5090]".
    pub device_name: String,
    /// PCI device class: "0300" (VGA compatible) or "0302" (3D controller).
    pub device_class: String,
    /// PCI address, e.g. "06:00.0".
    pub pci_host: String,
    /// vendor:device ids, e.g. "10de:2b85".
    pub device_id: String,
}

impl GpuDevice {
    /// VGA compatible controllers (0300) support the QEMU x-vga parameter;
    /// 3D controllers (0302) do not. Mirrors GpuDevice.has_x_vga_support.
    pub fn supports_x_vga(&self) -> bool {
        self.device_class == "0300"
    }
}

/// resources.py is_gpu_device_class: the two GPU classes of
/// https://admin.pci-ids.ucw.cz/read/PD/03 the network supports.
fn is_gpu_device_class(device_class: &str) -> bool {
    device_class == "0300" || device_class == "0302"
}

/// resources.py get_vendor_name: whitelisted vendors by PCI vendor id.
fn get_vendor_name(vendor_id: &str) -> Result<&'static str, DaemonError> {
    match vendor_id {
        "10de" => Ok("NVIDIA"),
        "1002" => Ok("AMD"),
        "8086" => Ok("Intel"),
        _ => Err(DaemonError::IncompatibleGpuVendor),
    }
}

/// resources.py is_kernel_enabled_gpu: the device must be bound to the
/// vfio-pci kernel driver to be attachable to a QEMU guest.
fn is_kernel_enabled_gpu(pci_host: &str) -> Result<bool, DaemonError> {
    let output = Command::new("lspci")
        .args(["-s", pci_host, "-nnk"])
        .output()
        .map_err(|error| {
            DaemonError::Lspci(format!("failed to run lspci -s {pci_host} -nnk: {error}"))
        })?;
    if !output.status.success() {
        return Err(DaemonError::Lspci(format!(
            "lspci -s {pci_host} -nnk exited with {}",
            output.status
        )));
    }
    let details = String::from_utf8_lossy(&output.stdout);
    Ok(details
        .split('\n')
        .any(|line| line == "\tKernel driver in use: vfio-pci"))
}

/// resources.py parse_gpu_device_info: one line of `lspci -mmnnn` output.
/// Returns None for devices that are not vfio-bound whitelisted GPUs. The
/// driver check is injected so the parser is testable against fixtures.
pub fn parse_gpu_device_info(
    line: &str,
    is_kernel_enabled_gpu: &mut dyn FnMut(&str) -> Result<bool, DaemonError>,
) -> Result<Option<GpuDevice>, DaemonError> {
    let malformed = || DaemonError::Lspci(format!("unparseable lspci -mmnnn line: {line:?}"));

    // pci_host, device = line.split(' "', maxsplit=1)
    let (pci_host, device) = line.split_once(" \"").ok_or_else(malformed)?;

    // The driver check runs before the class check, exactly like Python.
    if !is_kernel_enabled_gpu(pci_host)? {
        return Ok(None);
    }

    // device_class, device_vendor, device_info = device.split('" "', maxsplit=2)
    let mut parts = device.splitn(3, "\" \"");
    let device_class_field = parts.next().ok_or_else(malformed)?;
    let device_vendor = parts.next().ok_or_else(malformed)?;
    let device_info = parts.next().ok_or_else(malformed)?;

    // device_class = device_class.split("[", maxsplit=1)[1][:-1]
    // strip_suffix, not a byte-index slice: a `[:-1]`-style `&s[..len - 1]`
    // panics when the last character is multibyte.
    let (_, class_id) = device_class_field.split_once('[').ok_or_else(malformed)?;
    let device_class = class_id.strip_suffix(']').ok_or_else(malformed)?;
    if !is_gpu_device_class(device_class) {
        return Ok(None);
    }

    // vendor, vendor_id = device_vendor.rsplit(" [", maxsplit=1); vendor_id = vendor_id[:-1]
    let (_, vendor_id_raw) = device_vendor.rsplit_once(" [").ok_or_else(malformed)?;
    let vendor_id = vendor_id_raw.strip_suffix(']').ok_or_else(malformed)?;
    let vendor_name = get_vendor_name(vendor_id)?;

    // device_name = device_info.split('"', maxsplit=1)[0]
    let device_name_field = device_info.split('"').next().unwrap_or(device_info);
    // device_name, model_id = device_name.rsplit(" [", maxsplit=1); model_id = model_id[:-1]
    let (device_name, model_id_raw) = device_name_field.rsplit_once(" [").ok_or_else(malformed)?;
    let model_id = model_id_raw.strip_suffix(']').ok_or_else(malformed)?;

    Ok(Some(GpuDevice {
        vendor: vendor_name.to_string(),
        device_name: device_name.to_string(),
        device_class: device_class.to_string(),
        pci_host: pci_host.to_string(),
        device_id: format!("{vendor_id}:{model_id}"),
    }))
}

/// Parse a full `lspci -mmnnn` listing. Deduplicates like the Python set()
/// but keeps lspci order (Python's set iteration order is arbitrary; the
/// agent treats the inventory as a set).
pub fn parse_lspci_output(
    output: &str,
    is_kernel_enabled_gpu: &mut dyn FnMut(&str) -> Result<bool, DaemonError>,
) -> Result<Vec<GpuDevice>, DaemonError> {
    let mut seen = HashSet::new();
    let mut devices = Vec::new();
    for line in output.split('\n').filter(|line| !line.is_empty()) {
        if let Some(device) = parse_gpu_device_info(line, is_kernel_enabled_gpu)?
            && seen.insert(device.clone())
        {
            devices.push(device);
        }
    }
    Ok(devices)
}

/// resources.py get_gpu_devices: the real inventory.
pub fn get_gpu_devices() -> Result<Vec<GpuDevice>, DaemonError> {
    let output = Command::new("lspci")
        .arg("-mmnnn")
        .output()
        .map_err(|error| DaemonError::Lspci(format!("failed to run lspci -mmnnn: {error}")))?;
    if !output.status.success() {
        return Err(DaemonError::Lspci(format!(
            "lspci -mmnnn exited with {}",
            output.status
        )));
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    parse_lspci_output(&listing, &mut is_kernel_enabled_gpu)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real lines captured from `lspci -mmnnn`.
    const HOST_BRIDGE_LINE: &str = r#"00:00.0 "Host bridge [0600]" "Advanced Micro Devices, Inc. [AMD] [1022]" "Starship/Matisse Root Complex [1480]" -p00 "ASUSTeK Computer Inc. [1043]" "Device [8808]""#;
    const NVIDIA_VGA_LINE: &str = r#"06:00.0 "VGA compatible controller [0300]" "NVIDIA Corporation [10de]" "GB202 [GeForce RTX 5090] [2b85]" -ra1 -p00 "ZOTAC International (MCO) Ltd. [19da]" "Device [1761]""#;
    const NVIDIA_3D_LINE: &str = r#"41:00.0 "3D controller [0302]" "NVIDIA Corporation [10de]" "GA100 [A100 PCIe 40GB] [20f1]" -ra1 "NVIDIA Corporation [10de]" "Device [145f]""#;

    fn vfio_everywhere(_: &str) -> Result<bool, DaemonError> {
        Ok(true)
    }

    #[test]
    fn vga_gpu_line_is_parsed_field_for_field() {
        let device = parse_gpu_device_info(NVIDIA_VGA_LINE, &mut vfio_everywhere)
            .unwrap()
            .unwrap();
        assert_eq!(device.pci_host, "06:00.0");
        assert_eq!(device.vendor, "NVIDIA");
        // The inner [GeForce ...] bracket stays in the name; only the
        // trailing [2b85] id is split off (Python rsplit " [" behavior).
        assert_eq!(device.device_name, "GB202 [GeForce RTX 5090]");
        assert_eq!(device.device_class, "0300");
        assert_eq!(device.device_id, "10de:2b85");
        assert!(device.supports_x_vga());
    }

    #[test]
    fn three_d_controller_has_no_x_vga_support() {
        let device = parse_gpu_device_info(NVIDIA_3D_LINE, &mut vfio_everywhere)
            .unwrap()
            .unwrap();
        assert_eq!(device.device_class, "0302");
        assert_eq!(device.device_id, "10de:20f1");
        assert_eq!(device.device_name, "GA100 [A100 PCIe 40GB]");
        assert!(!device.supports_x_vga());
    }

    #[test]
    fn non_gpu_class_is_skipped() {
        let parsed = parse_gpu_device_info(HOST_BRIDGE_LINE, &mut vfio_everywhere).unwrap();
        assert_eq!(parsed, None);
    }

    #[test]
    fn gpu_without_vfio_driver_is_skipped() {
        let mut no_vfio = |_: &str| Ok(false);
        let parsed = parse_gpu_device_info(NVIDIA_VGA_LINE, &mut no_vfio).unwrap();
        assert_eq!(parsed, None);
    }

    #[test]
    fn driver_check_runs_before_the_class_check_like_python() {
        let mut checked: Vec<String> = Vec::new();
        let mut recording = |pci: &str| {
            checked.push(pci.to_string());
            Ok(false)
        };
        parse_gpu_device_info(HOST_BRIDGE_LINE, &mut recording).unwrap();
        assert_eq!(checked, vec!["00:00.0".to_string()]);
    }

    #[test]
    fn full_listing_only_yields_vfio_gpus() {
        let listing = format!("{HOST_BRIDGE_LINE}\n{NVIDIA_VGA_LINE}\n{NVIDIA_3D_LINE}\n");
        let mut only_the_vga = |pci: &str| Ok(pci == "06:00.0");
        let devices = parse_lspci_output(&listing, &mut only_the_vga).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].pci_host, "06:00.0");
    }

    #[test]
    fn incompatible_vendor_is_an_error_like_python() {
        let line = r#"07:00.0 "VGA compatible controller [0300]" "Matrox Electronics Systems Ltd. [102b]" "MGA G200e [0522]" "" """#;
        let error = parse_gpu_device_info(line, &mut vfio_everywhere).unwrap_err();
        assert!(matches!(error, DaemonError::IncompatibleGpuVendor));
    }

    #[test]
    fn multibyte_characters_never_panic_the_parser() {
        // lspci output is arbitrary bytes decoded lossily; a field whose last
        // character is multibyte used to panic the old `&s[..len - 1]`
        // slicing on a char boundary. Malformed bracket fields must instead
        // surface as a clean parse error.
        let truncated_class = "06:00.0 \"VGA compatible controller [030é\" \"NVIDIA Corporation [10de]\" \"GB202 [2b85]\" -ra1";
        let error = parse_gpu_device_info(truncated_class, &mut vfio_everywhere).unwrap_err();
        assert!(error.to_string().contains("unparseable"));

        let truncated_model = "06:00.0 \"VGA compatible controller [0300]\" \"NVIDIA Corporation [10de]\" \"GB202 [2b8\u{FFFD}\" -ra1";
        let error = parse_gpu_device_info(truncated_model, &mut vfio_everywhere).unwrap_err();
        assert!(error.to_string().contains("unparseable"));

        // A well-formed line with multibyte characters in the card name
        // parses fine, the characters preserved.
        let accented_name = "06:00.0 \"VGA compatible controller [0300]\" \"NVIDIA Corporation [10de]\" \"Café édition [2b85]\" -ra1";
        let device = parse_gpu_device_info(accented_name, &mut vfio_everywhere)
            .unwrap()
            .unwrap();
        assert_eq!(device.device_name, "Café édition");
        assert_eq!(device.device_id, "10de:2b85");
    }

    #[test]
    fn inventory_json_matches_python_model_dump_key_order() {
        let device = parse_gpu_device_info(NVIDIA_VGA_LINE, &mut vfio_everywhere)
            .unwrap()
            .unwrap();
        let json = serde_json::to_string(&vec![device]).unwrap();
        assert_eq!(
            json,
            r#"[{"vendor":"NVIDIA","device_name":"GB202 [GeForce RTX 5090]","device_class":"0300","pci_host":"06:00.0","device_id":"10de:2b85"}]"#
        );
    }
}
