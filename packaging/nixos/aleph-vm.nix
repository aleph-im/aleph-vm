let
  unstable = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") {};
in
{
  python312,
  pkgs,
}:

  python312.pkgs.buildPythonPackage rec {
    pname = "aleph-vm";
    version = "0.4.1";
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
      # pkgs.hatch
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
      # pkgs.python312Packages.eth-account
      pkgs.python312Packages.eth-hash
      pkgs.python312Packages.eth-typing
      pkgs.python312Packages.hatch-vcs
      pkgs.python312Packages.hatchling
      pkgs.python312Packages.jsonschema
      pkgs.python312Packages.msgpack
      pkgs.python312Packages.jwcrypto
      pkgs.python312Packages.nftables
      pkgs.python312Packages.packaging
      pkgs.python312Packages.psutil
      pkgs.python312Packages.py-cpuinfo
      pkgs.python312Packages.pydantic_1
      pkgs.python312Packages.pyroute2
      pkgs.python312Packages.pyyaml
      pkgs.python312Packages.schedule
      pkgs.python312Packages.setproctitle
      pkgs.python312Packages.setuptools
      pkgs.python312Packages.sqlalchemy
      pkgs.python312Packages.systemd
      pkgs.python312Packages.sentry-sdk

      # Test dependencies
      pkgs.python312Packages.pytest
      pkgs.python312Packages.pytest-cov
      pkgs.python312Packages.pytest-asyncio
      pkgs.python312Packages.pytest-mock

      # Specific versions from PyPI
      aioredis
      aleph-message
      # jwskate
      nftablesPyPI
      qmp
      superfluid
      python-cpuid
    ];

    aleph-message = python312.pkgs.buildPythonPackage rec {
      pname = "aleph-message";
      version = "0.4.8";
      src = python312.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-Q6aWhAeZtgNpXJ0YT4xEtZLqzWpQI/3dg7nVrzC1/RM=";
      };
      doCheck = false;
      propagatedBuildInputs = [
        pkgs.python312Packages.pydantic_1
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
      #src = /home/sepal/Repos/aleph-im/superfluid.py;
      src = pkgs.fetchgit {
        url = "https://github.com/aleph-im/superfluid.py";
        rev = "ddf95fe13ebc30e631d005ce8b1cde260ab7be8c";
        hash = "sha256-IQBSj9hD+1W/sJjw6IuCVbp59s9bboPQFfyTI73FNnc=";
      };
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

    python-cpuid = python312.pkgs.buildPythonPackage rec {
      pname = "python_cpuid";
      version = "0.1.1";
      src = python312.pkgs.fetchPypi {
        pname = "python_cpuid";
        inherit version;
        sha256 = "sha256-CSrfDVZ6LOBo8Q/1sLCFsb4jz6SsWsaJC8lrTxU5q78="; # 0.1.1
        # sha256 = "sha256-mMamlO36fCwhmaJ8iF1p10XawRB//CFCA7BzccKSycQ="; # 0.1.0
      };
      propagatedBuildInputs = [
        # python312.pkgs.setuptools
      ];
    };

    # jwskate = python312.pkgs.buildPythonPackage rec {
    #   pname = "jwskate";
    #   version = "0.11.1";
    #   pyproject = true;
    #   src = python312.pkgs.fetchPypi {
    #     inherit pname version;
    #     sha256 = "sha256-NTVLSHyOg1/dV77+pek+nlL+JYadiE/HZFEdIgYeZoU=";
    #   };

    #   propagatedBuildInputs = [
    #     pkgs.python312Packages.hatchling
    #     pkgs.python312Packages.hatch-vcs
    #     pkgs.python312Packages.cryptography
    #     binapy
    #   ];
    # };

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
        pkgs.python312Packages.typing-extensions
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
        python312.pkgs.async-timeout
        python312.pkgs.hiredis
      ];
    };
  }
