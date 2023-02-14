{
  test1 = {pkgs, config, ...}:
    {
      services.openssh.enable = true;
      users = {
        mutableUsers = false;
        extraUsers = { 
          root = {
            #hashedPassword = "sP8WwxnEYVRHvUVFEU.loePBt7Mz2XkRGTMGpzx05OD";
          };
        };
      }; 
      environment.systemPackages = with pkgs; [
        git
        redis
        acl
        curl
        squashfsTools
        debootstrap
        vim
        nftables
        (
          python310.withPackages(ps: with ps; [
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
                version = "0.3.0";
                src = fetchPypi {
                  inherit pname version;
                  sha256 = "sha256-8dr9Kh7LFDgQs43ffgtjCyTS1Q3Y3zy8o0m8SUAQKSc=";
                };
                doCheck = false;
                propagatedBuildInputs = [
                  # Specify dependencies
                  pkgs.python3Packages.pydantic
                ];
              }
            )
          ])
        )
      ];

      nixpkgs.localSystem.system = "x86_64-linux";
      virtualisation.cores = 4;
      virtualisation.memorySize = 8192;
      virtualisation.forwardPorts = [
        { from = "host"; host.port = 4020; guest.port = 4020; }
      ];
    };
}
