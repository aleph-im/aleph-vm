{ 
  python3
}:

  python3.pkgs.buildPythonPackage rec {
    pname = "vm_supervisor";
    version = "1.8.3";
    src = ../../vm_supervisor;
    #src = fetchPypi {
    #  inherit pname version;
    #  sha256 = "sha256-0aozmQ4Eb5zL4rtNHSFjEynfObUkYlid1PgMDVmRkwY=";
    #};
    doCheck = false;
    propagatedBuildInputs = [
      # Specify dependencies
      #pkgs.python3Packages.numpy
    ];
  }
