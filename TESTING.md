# Testing aleph-vm

This proedure describes how to run tests on a local system.

Tests also run on GitHub Actions via [the following workflow](./.github/workflows/test-on-droplets-matrix.yml).

Since these tests create block devices and manipulate network interfaces, they need to run as root.
If you are not comfortable with this, run them in a virtual machine.

## 1. Clone this repository

```shell
git clone https://github.com/aleph-im/aleph-vm.git
```

## 2. Install [hatch](https://hatch.pypa.io/), the project manager

Since installing tools globally is not recommended, we will install `hatch`
 in a dedicated virtual environment. Alternatives include using [pipx](https://pipx.pypa.io)
or your distribution.

```shell
python3 -m venv /opt/venv
source /opt/venv/bin/activate

# Inside the venv
pip install hatch
```

## 3. Initialize hatch for running the tests

It is required that the testing virtual environment relies on system packages
for `nftables` instead of the package obtained from `salsa.debian.org` as defined in 
[pyproject.toml](./pyproject.toml).

Create the testing virtual environment:
```shell
hatch env create testing
```

Obtain the path to the testing virtual environment. 
```
hatch run testing:which python
```

Locate the file named `pyvenv.cfg` in your virtual environment.
Edit it to use system site packages:
```
vim /root/.local/share/hatch/env/virtual/aleph-vm/i5XWCcQ_/testing/pyvenv.cfg
```

Set `include-system-site-packages` to `true`.

Remove the Python library `nftables` from the `hatch` virtual environment:
```shell
hatch run testing:pip uninstall nftables
```

## 4. Run tests

```shell
hatch run testing:test
```
