{ modulesPath, pkgs, config,... }:
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

#  networking.nftables.enable = true;

  environment = {
    shellAliases = {
      orchestrator = "python -m aleph.vm.orchestrator";
      check-nftables = "python -m nftables";
    };
  };

  virtualisation = {
    podman = {
      enable = true;

      # Create a `docker` alias for podman, to use it as a drop-in replacement
      dockerCompat = true;

      # Required for containers under podman-compose to be able to talk to each other.
      #defaultNetwork.dnsname.enable = true;
    };
    oci-containers.backend = "podman";
    oci-containers.containers = {
      vm-connector = {
        image = "docker.io/alephim/vm-connector:alpha";
        autoStart = true;
        ports = [ "4021:4021" ];
      };
    };
  };

  environment.systemPackages = with pkgs; [

    ( callPackage ./default.nix {} )

    helix

    git
    redis
    acl
    curl
    squashfsTools
    debootstrap
    vim
    firecracker
    nftables
    (
      python311.withPackages(ps: with ps; [
        aiohttp
        msgpack
        aiodns
        sqlalchemy
        setproctitle
        aioredis
        psutil
        packaging
        py-cpuinfo
        nftables
        jsonschema
        pydantic
        (
          buildPythonPackage rec {
            pname = "aleph-message";
            version = "0.4.0";
            src = fetchPypi {
              inherit pname version;
              sha256 = "sha256-a1yyiRUjcaER2JXxPAKPLQMoVlpWq3SbXB+XzBbvDvU=";
            };
            doCheck = false;
            propagatedBuildInputs = [
              pkgs.python311Packages.pydantic
            ];
          }
        )
      ])
    )
  ];

  environment.sessionVariables = rec {
    ALEPH_VM_SETUP = "git clone https://github.com/aleph-im/aleph-vm.git";
    LD_LIBRARY_PATH = "/run/current-system/sw/lib";
  };

  system.stateVersion = "22.11";
}
