let
  unstable = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") {};
in
{
  python311,
  pkgs
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
      # Specify dependencies
      #pkgs.python3Packages.numpy
      pkgs.git
      pkgs.python311Packages.setuptools
      pkgs.python311Packages.hatchling
      pkgs.python311Packages.hatch-vcs
      pkgs.python311Packages.nftables
      pkgs.python311Packages.pyyaml

      pkgs.python311Packages.aiohttp
      pkgs.python311Packages.eth-hash
      pkgs.python311Packages.eth-account
      pkgs.python311Packages.eth-typing
    ];
  }
