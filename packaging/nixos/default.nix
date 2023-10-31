let
  unstable = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") {};
in
{
  python311,
  pkgs
}:

  python311.pkgs.buildPythonPackage rec {
    pname = "aleph-vm";
    version = "0.3.0";
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
      # Specify dependencies
      #pkgs.python3Packages.numpy
      pkgs.git
      pkgs.python311Packages.setuptools
      pkgs.python311Packages.hatchling
      pkgs.python311Packages.hatch-vcs
      pkgs.python311Packages.nftables

      pkgs.python311Packages.aiohttp
#      unstable.python311Packages.eth-account
    ];

    eth-utils = python311.pkgs.buildPythonPackage rec {
      pname = "eth-utils";
      version = "2.3.0";
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-CFtC9XRfRtIqGG+9hz159mp5FxwC7M14eS0d3dZy8yQ=";
      };
      propagatedBuildInputs = [ pkgs.python311Packages.cytoolz eth-hash ];
    };

    eth-hash = python311.pkgs.buildPythonPackage rec {
      pname = "eth-hash";
      version = "0.5.2";
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-G18Q7Kd2XMOF4UMO78XO1uLkY7sY0TZVEOLlOcGm/k4=";
      };

      propagatedBuildInputs = [ pkgs.python311Packages.cryptography ];
    };

    eth-typing = python311.pkgs.buildPythonPackage rec {
      pname = "eth-typing";
      version = "3.2.2";
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-l7oPg9p88dNmj27VSYPyEWgHbFUnYr9eBtSiCSGHfz8=";
      };
    };

    eth-account = python311.pkgs.buildPythonPackage rec {
      pname = "eth-account";
      version = "0.9.0";
      src = python311.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-X2bst7xSVpkk369Kmt1QGxwqSQHux048BZjNJtCXF3c";
      };
      propagatedBuildInputs = [ eth-utils eth-hash ];
    };
  }
