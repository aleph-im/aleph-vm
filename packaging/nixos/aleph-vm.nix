let
  unstable = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") {};
in
{
  python311,
  pkgs,
}:

  python311.pkgs.buildPythonPackage rec {
    pname = "aleph-vm";
    version = "0.4.0";
    src = ../..;
    format = "pyproject";
    #src = fetchPypi {
    #  inherit pname version;
    #  sha256 = "sha256-0aozmQ4Eb5zL4rtNHSFjEynfObUkYlid1PgMDVmRkwY=";
    #};
    doCheck = true;
    nativeBuildInputs = [
      pkgs.git
    ];
    propagatedBuildInputs = [
      pkgs.git
      pkgs.which
      pkgs.git
      pkgs.redis
      pkgs.acl
      pkgs.curl
      pkgs.squashfsTools
      pkgs.debootstrap
      pkgs.firecracker
      pkgs.ndppd
      pkgs.cloud-utils

      # Versions from nixpkgs
      pkgs.python311Packages.aiodns
      pkgs.python311Packages.aiohttp
      pkgs.python311Packages.aiohttp-cors
      pkgs.python311Packages.aiosqlite
      pkgs.python311Packages.alembic
      pkgs.python311Packages.cryptography
      pkgs.python311Packages.dbus-python
      pkgs.python311Packages.eth-account
      pkgs.python311Packages.eth-hash
      pkgs.python311Packages.eth-typing
      pkgs.python311Packages.hatch-vcs
      pkgs.python311Packages.hatchling
      pkgs.python311Packages.jsonschema
      pkgs.python311Packages.msgpack
      pkgs.python311Packages.nftables
      pkgs.python311Packages.packaging
      pkgs.python311Packages.psutil
      pkgs.python311Packages.py-cpuinfo
      pkgs.python311Packages.pydantic
      pkgs.python311Packages.pyyaml
      pkgs.python311Packages.schedule
      pkgs.python311Packages.setproctitle
      pkgs.python311Packages.setuptools
      pkgs.python311Packages.sqlalchemy
      pkgs.python311Packages.systemd

      # Specific versions from PyPI
      aioredis
      aleph-message
      jwskate
      nftablesPyPI
      qmp
      superfluid
    ];

    aleph-message = python311.pkgs.buildPythonPackage rec {
      pname = "aleph-message";
      version = "0.4.4";
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-0WKvQpVd8hWezks+fdeYpMtzCqCtsYtP2aVTiQcltQg=";
      };
      doCheck = false;
      propagatedBuildInputs = [
        pkgs.python311Packages.pydantic
      ];
    };

    nftablesPyPI = python311.pkgs.buildPythonPackage rec {
      pname = "pip-nftables";
      version = "1.0.2.post1";
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-tArdoUWQz5ofgsmvW5ofV9UfobWOUfdDqY/4pjrldOQ=";
      };
    };

    qmp = python311.pkgs.buildPythonPackage rec {
      pname = "qmp";
      version = "1.1.0";
      format = "pyproject";
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-pk/LIHncc6hd6w1opmbtzzmZb1naPBwZlMCGeVbd+9w=";
      };
      propagatedBuildInputs = [
        python311.pkgs.setuptools
      ];
    };

    superfluid = python311.pkgs.buildPythonPackage rec {
      pname = "superfluid";
      version = "0.2.1";
      src = /home/sepal/Repos/aleph-im/superfluid.py;
      propagatedBuildInputs = [
        python311.pkgs.setuptools
        decouple
        pkgs.python311Packages.web3
      ];
    };

    decouple = python311.pkgs.buildPythonPackage rec {
      pname = "python-decouple";
      version = "3.8";
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-um4mV9TzduzEb3ejphXgWNk7peRlwBu+Vyib+3zOaA8=";
      };
    };

    jwskate = python311.pkgs.buildPythonPackage rec {
      pname = "jwskate";
      version = "0.11.1";
      pyproject = true;
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-NTVLSHyOg1/dV77+pek+nlL+JYadiE/HZFEdIgYeZoU=";
      };

      propagatedBuildInputs = [
        pkgs.python311Packages.hatchling
        pkgs.python311Packages.hatch-vcs
        binapy
      ];
    };

    binapy = python311.pkgs.buildPythonPackage rec {
      pname = "binapy";
      version = "0.8.0";
      pyproject = true;
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-VwxQmNQvA3/7PS5WOZjzz/aa0lyh9D+cOBVDLczQgjM=";
      };

      propagatedBuildInputs = [
        pkgs.python311Packages.poetry-core
      ];
    };

    aioredis = python311.pkgs.buildPythonPackage rec {
      pname = "aioredis";
      version = "1.3.1";
      pyproject = true;
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-FfivMLBEx3Gu5nh+XsJGlMBIGEx7nlTDtgx1CkuTJzo=";
      };

      propagatedBuildInputs = [
        python311.pkgs.setuptools
      ];
    };
  }
