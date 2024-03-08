{ modulesPath, pkgs, config, lib,... }:
let
  myPythonEnv = (
    pkgs.python311.withPackages(ps: with ps; [
      ( callPackage ./aleph-vm.nix {} )
    ])
  );

  vmlinux = pkgs.fetchurl {
    url = "https://ipfs.aleph.cloud/ipfs/bafybeiaj2lf6g573jiulzacvkyw4zzav7dwbo5qbeiohoduopwxs2c6vvy";
    sha256 = "sha256-8jo6yMdVa7h3owBZ6aaxQ7mXGkg5RwoAjnjiYF77ZrY=";
  };

  runtime = pkgs.fetchurl {
    url = "https://ipfs.aleph.cloud/ipfs/bafybeibmbjwdh6o4wc3cjk5trgbu6lemq35ycuv2hnxk63u5egsb5ovkve";
    sha256 = "sha256-8jo6yMdVa7h3owBZ6aaxQ7mXGkg5RwoAjnjiYF77ZrY=";
  };

#  dockerImage = pkgs.dockerTools.pullImage {
#    imageName = "docker.io/alephim/vm-connector:alpha";
#    sha256 = "sha256-8jo6yMdVa7h3owBZ6aaxQ7mXGkg5RwoAjnjiYF77ZrY=";
#    imageDigest = "sha256-of-the-image";
#  };
in
{
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];
  boot.initrd.availableKernelModules =
    [ "ata_piix" "uhci_hcd" "virtio_pci" "sr_mod" "virtio_blk" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ "kvm-intel" ];
  boot.extraModulePackages = [ ];

  nixpkgs.localSystem.system = "x86_64-linux";
  virtualisation.cores = 4;
  virtualisation.memorySize = 4096;
  virtualisation.diskSize = 4096;
#  virtualisation.interfaces.enp5s0.assignIP = true;
  virtualisation.forwardPorts = [
    { from = "host"; host.port = 4020; guest.port = 4020; }
  ];

  users.users = {
    root = {
      initialPassword = "toor";
    };
    jailman = {
      group = "jailman";
      isSystemUser = true;
    };
  };
  users.groups.jailman.members = [ "jailman" ];
  services.getty.autologinUser = "root";

  services.openssh.enable = true;

  services.ndppd.enable = true;
  services.redis.servers."aleph-vm".enable = true;

#  networking.nftables.enable = true;

  environment = {
    shellAliases = {
      orchestrator = "python -m aleph.vm.orchestrator";
      check-nftables = "python -m nftables";
      check = "curl -i http://localhost:4020/status/check/fastapi";
      clone = "git clone https://github.com/aleph-im/aleph-vm.git";
      j = "journalctl -u aleph-vm-supervisor -f";
    };
  };

  systemd.services.aleph-vm-supervisor = {
    description = "Aleph.im VM Orchestrator";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${myPythonEnv}/bin/python -m aleph.vm.orchestrator";
      Restart = "always";
      User = "root";
    };
    environment = {
      LD_LIBRARY_PATH = "/run/current-system/sw/lib";
      ALEPH_VM_FIRECRACKER_PATH = "/run/current-system/sw/bin/firecracker";
      ALEPH_VM_JAILER_PATH = "/run/current-system/sw/bin/jailer";
      ALEPH_VM_LINUX_PATH = vmlinux;
      ALEPH_VM_SUPERVISOR_HOST = "0.0.0.0";
      PYTHONPATH = "${myPythonEnv}/lib/";
      PATH= lib.mkForce "/run/current-system/sw/bin";
      };
  };

  virtualisation = {
    docker = {
      enable = true;

      # Required for containers under podman-compose to be able to talk to each other.
      #defaultNetwork.dnsname.enable = true;
    };
    oci-containers.backend = "docker";
    oci-containers.containers = {
      vm-connector = {
        image = "docker.io/alephim/vm-connector:alpha";
        autoStart = true;
        ports = [ "4021:4021" ];
      };
    };
  };

  environment.systemPackages = with pkgs; [

    helix
    vim

    which
    git
    redis
    acl
    curl
    squashfsTools
    debootstrap
    firecracker
    ndppd
    cloud-utils

    myPythonEnv
  ];

  # Symlink the file from variable `runtime` above to /var/cache/aleph-vm/vm/runtime. It is not in /etc
  # because it is not a configuration file. Therefore environment.etc is not suitable.
#  environment.pathsToLink = {
#    "/var/cache/aleph-vm/vm/runtime/f873715dc2feec3833074bd4b8745363a0e0093746b987b4c8191268883b2463" = runtime;
#  };

  environment.sessionVariables = rec {
    LD_LIBRARY_PATH = "/run/current-system/sw/lib";
    ALEPH_VM_FIRECRACKER_PATH = "/run/current-system/sw/bin/firecracker";
    ALEPH_VM_JAILER_PATH = "/run/current-system/sw/bin/jailer";
    ALEPH_VM_LINUX_PATH = vmlinux;
    ALEPH_VM_SUPERVISOR_HOST = "0.0.0.0";
    PYTHONPATH = "${myPythonEnv}/lib/";
  };

  system.stateVersion = "22.11";
}
