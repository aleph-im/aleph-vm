# Testing aleph-vm

In order to run tests locally, follow the following procedure:

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
