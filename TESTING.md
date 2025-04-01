# Testing aleph-vm

This procedure describes how to run tests on a dev system. See the dev setup section of the README first.

Tests also run on GitHub Actions via [the following workflow](./.github/workflows/test-using-pytest.yml).

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


## 4. Run tests

```shell
hatch run testing:test
```


## Debugging the tests
Some tricks and options that might help debugging problematic tests.

Only launch pytest with a test name and more verbose debugging
```shell
hatch run testing:pytest -vv --log-level=DEBUG --full-trace -o log_cli=true -k <TEST NAME>
```


Specify `--capture=no` to pytest so it launch. This way you get the full output, including firecracker logs

## Debugging runtimes
If the error is in the runtime:
Modify the #!  to pass the -v option to python, which will print all the debugging info
`#!/usr/bin/python3 -vOO`

To have these modification take effect you need to rebuild the runtime file using `create_disk_image.sh` as _root_

```shell
sudo bash create_disk_image.sh
```

Don't forget to have the print system log option set `ALEPH_VM_PRINT_SYSTEM_LOGS=1`

`aleph-debian-12-python` is used in test_create_execution