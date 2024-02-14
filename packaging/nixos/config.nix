{ modulesPath, pkgs, config,... }:
let
  myPythonEnv = (
      pkgs.python311.withPackages(ps: with ps; [
        aiohttp
        msgpack
        aiodns
        sqlalchemy
        setproctitle
        psutil
        packaging
        py-cpuinfo
        jsonschema
        pydantic

        ( callPackage ./default.nix {} )

        (
          buildPythonPackage rec {
            pname = "aleph-message";
            version = "0.4.2";
            src = fetchPypi {
              inherit pname version;
              sha256 = "sha256-bfqsYb7IY7vWNfItTdcASBKBiAln7JjmZgWDdbCMPSM=";
            };
            doCheck = false;
            propagatedBuildInputs = [
              pkgs.python311Packages.pydantic
            ];
          }
        )
      ])
    );

  vmlinux = pkgs.fetchurl {
    url = "https://ipfs.aleph.cloud/ipfs/bafybeiaj2lf6g573jiulzacvkyw4zzav7dwbo5qbeiohoduopwxs2c6vvy";
    sha256 = "sha256-8jo6yMdVa7h3owBZ6aaxQ7mXGkg5RwoAjnjiYF77ZrY=";
  };
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
  services.redis.enable = true;

#  networking.nftables.enable = true;

  environment = {
    shellAliases = {
      orchestrator = "python -m aleph.vm.orchestrator";
      check-nftables = "python -m nftables";
      check = "curl -i http://localhost:4020/status/check/fastapi";
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

    git
    redis
    acl
    curl
    squashfsTools
    debootstrap
    vim
    firecracker
    ndppd
    cloud-utils

    myPythonEnv
  ];

  environment.sessionVariables = rec {
    ALEPH_VM_SETUP = "git clone https://github.com/aleph-im/aleph-vm.git";
    LD_LIBRARY_PATH = "/run/current-system/sw/lib";
    ALEPH_VM_FIRECRACKER_PATH = "/run/current-system/sw/bin/firecracker";
    ALEPH_VM_JAILER_PATH = "/run/current-system/sw/bin/jailer";
    ALEPH_VM_LINUX_PATH = vmlinux;
    ALEPH_VM_SUPERVISOR_HOST = "0.0.0.0";
    PYTHONPATH = "${myPythonEnv}/lib/";
  };

  system.stateVersion = "22.11";
}
