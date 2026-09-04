{ pkgs, lib, gpuKernel, ... }:

# The NVIDIA driver pieces the confidential-GPU guest ships.
#
# Kernel side: the open kernel modules built against gpuKernel, nvidia.ko and
# nvidia-uvm.ko only (no drm/modeset: headless compute guest; no peermem).
# GSP firmware is mandatory for CC mode and comes from the driver archive's
# firmware output.
#
# User side: the RAW driver libraries, extracted straight from the .run
# archive with no ELF patching. nixpkgs' `out` patches interpreters and
# rpaths to the nix glibc, which would drag a second libc into whatever
# workload dlopens libcuda. Raw libraries link against the loading
# process's own libc (they only reference old glibc symbol versions), which
# is exactly how the NVIDIA container toolkit hands them to containers.
let
  nvidiaPkgs = (pkgs.linuxKernel.packagesFor gpuKernel).nvidiaPackages.production;
  version = nvidiaPkgs.version;
  # NV_EXCLUDE_KERNEL_MODULES has to be a single space-separated value
  # ("nvidia-drm nvidia-modeset nvidia-peermem"); nixpkgs' generic builder
  # word-splits the (unquoted) `makeFlags` string when it builds the make
  # invocation's argument array, so a makeFlags entry with embedded spaces
  # gets torn into three separate make command-line words, and make reads
  # the 2nd/3rd as goals ("No rule to make target 'nvidia-modeset'") instead
  # of part of the assignment. A plain derivation attribute becomes an
  # exported environment variable instead (no re-splitting by the builder),
  # and the Makefile's `$(filter-out $(NV_EXCLUDE_KERNEL_MODULES), ...)`
  # (kernel-open/Makefile) picks up make's environment the normal way.
  open = nvidiaPkgs.open.overrideAttrs (old: {
    NV_EXCLUDE_KERNEL_MODULES = "nvidia-drm nvidia-modeset nvidia-peermem";
  });
  modDir = "${open}/lib/modules/${gpuKernel.modDirVersion}/kernel/drivers/video";
  modules = pkgs.runCommand "nvidia-open-modules-${version}" { nativeBuildInputs = [ pkgs.xz ]; } ''
    mkdir -p $out
    for m in nvidia nvidia-uvm; do
      if [ -f ${modDir}/$m.ko.xz ]; then xz -d -k -c ${modDir}/$m.ko.xz > $out/$m.ko
      elif [ -f ${modDir}/$m.ko ]; then cp ${modDir}/$m.ko $out/$m.ko
      else echo "missing $m.ko in ${modDir}" >&2; exit 1; fi
    done
  '';
  firmware = nvidiaPkgs.firmware;
  # The compute + attestation userland, raw. Wildcards keep the list honest
  # across driver bumps (a renamed library fails the ls, not the boot).
  #
  # nativeBuildInputs: the .run archive is a makeself shell script. NVIDIA
  # switched its payload compression to zstd for driver >= 530 (595.71.05
  # here), so the extractor needs zstd on PATH in addition to bash/tar/xz;
  # verified with `sh $src --list`, which fails with "zstd: cannot execute:
  # required file not found" if zstd is missing.
  userland = pkgs.runCommand "nvidia-userland-raw-${version}" {
    nativeBuildInputs = [ pkgs.bash pkgs.gnutar pkgs.xz pkgs.zstd ];
  } ''
    mkdir -p $out
    sh ${nvidiaPkgs.src} --extract-only --target src
    cd src
    for lib in libcuda.so.${version} libnvidia-ml.so.${version} libnvidia-ptxjitcompiler.so.${version} \
               libnvidia-nvvm.so.${version} libnvidia-gpucomp.so.${version} libnvidia-pkcs11-openssl3.so.${version}; do
      cp "$lib" $out/
      base=$(echo $lib | sed 's/\.so\..*$/.so/')
      ln -s $lib $out/$base.1
      ln -s $lib $out/$base
    done
    cp nvidia-smi $out/
    chmod 755 $out/nvidia-smi
  '';
in
{ inherit modules firmware userland version; }
