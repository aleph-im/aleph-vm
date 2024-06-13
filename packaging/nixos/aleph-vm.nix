let
  unstable = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") {};
in
{
  python312,
  pkgs,
}:

  python312.pkgs.buildPythonPackage rec {
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
      pkgs.acl
      pkgs.cloud-utils
      pkgs.curl
      pkgs.debootstrap
      pkgs.firecracker
      pkgs.git
      pkgs.git
      pkgs.hatch
      pkgs.ndppd
      pkgs.redis
      pkgs.squashfsTools

      # Versions from nixpkgs
      pkgs.python312Packages.aiodns
      pkgs.python312Packages.aiohttp
      pkgs.python312Packages.aiohttp-cors
      pkgs.python312Packages.aiosqlite
      pkgs.python312Packages.alembic
      pkgs.python312Packages.cryptography
      pkgs.python312Packages.dbus-python
      pkgs.python312Packages.eth-account
      pkgs.python312Packages.eth-hash
      pkgs.python312Packages.eth-typing
      pkgs.python312Packages.hatch-vcs
      pkgs.python312Packages.hatchling
      pkgs.python312Packages.jsonschema
      pkgs.python312Packages.msgpack
      pkgs.python312Packages.nftables
      pkgs.python312Packages.packaging
      pkgs.python312Packages.psutil
      pkgs.python312Packages.py-cpuinfo
      pkgs.python312Packages.pydantic
      pkgs.python312Packages.pyroute2
      pkgs.python312Packages.pyyaml
      pkgs.python312Packages.schedule
      pkgs.python312Packages.setproctitle
      pkgs.python312Packages.setuptools
      pkgs.python312Packages.sqlalchemy
      pkgs.python312Packages.systemd

      # Test dependencies
      pkgs.python312Packages.pytest
      pkgs.python312Packages.pytest-cov
      pkgs.python312Packages.pytest-asyncio
      pkgs.python312Packages.pytest-mock

      # Specific versions from PyPI
      aioredis
      aleph-message
      jwskate
      nftablesPyPI
      qmp
      superfluid
    ];

    aleph-message = python312.pkgs.buildPythonPackage rec {
      pname = "aleph-message";
      version = "0.4.4";
      src = python312.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-0WKvQpVd8hWezks+fdeYpMtzCqCtsYtP2aVTiQcltQg=";
      };
      doCheck = false;
      propagatedBuildInputs = [
        pkgs.python312Packages.pydantic
      ];
    };

    nftablesPyPI = python312.pkgs.buildPythonPackage rec {
      pname = "pip-nftables";
      version = "1.0.2.post1";
      src = python312.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-tArdoUWQz5ofgsmvW5ofV9UfobWOUfdDqY/4pjrldOQ=";
      };
    };

    qmp = python312.pkgs.buildPythonPackage rec {
      pname = "qmp";
      version = "1.1.0";
      format = "pyproject";
      src = python312.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-pk/LIHncc6hd6w1opmbtzzmZb1naPBwZlMCGeVbd+9w=";
      };
      propagatedBuildInputs = [
        python312.pkgs.setuptools
      ];
    };

    superfluid = python312.pkgs.buildPythonPackage rec {
      pname = "superfluid";
      version = "0.2.1";
      src = /home/sepal/Repos/aleph-im/superfluid.py;
      propagatedBuildInputs = [
        python312.pkgs.setuptools
        decouple
        pkgs.python312Packages.web3
      ];
    };

    decouple = python312.pkgs.buildPythonPackage rec {
      pname = "python-decouple";
      version = "3.8";
      src = python312.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-um4mV9TzduzEb3ejphXgWNk7peRlwBu+Vyib+3zOaA8=";
      };
    };

    jwskate = python312.pkgs.buildPythonPackage rec {
      pname = "jwskate";
      version = "0.11.1";
      pyproject = true;
      src = python312.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-NTVLSHyOg1/dV77+pek+nlL+JYadiE/HZFEdIgYeZoU=";
      };

      propagatedBuildInputs = [
        pkgs.python312Packages.hatchling
        pkgs.python312Packages.hatch-vcs
        binapy
      ];
    };

    binapy = python312.pkgs.buildPythonPackage rec {
      pname = "binapy";
      version = "0.8.0";
      pyproject = true;
      src = python312.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-VwxQmNQvA3/7PS5WOZjzz/aa0lyh9D+cOBVDLczQgjM=";
      };

      propagatedBuildInputs = [
        pkgs.python312Packages.poetry-core
      ];
    };

    aioredis = python312.pkgs.buildPythonPackage rec {
      pname = "aioredis";
      version = "1.3.1";
      pyproject = true;
      src = python312.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-FfivMLBEx3Gu5nh+XsJGlMBIGEx7nlTDtgx1CkuTJzo=";
      };

      propagatedBuildInputs = [
        python312.pkgs.setuptools
      ];
    };
  }
