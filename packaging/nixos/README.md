Run with

## Build a system image

In this example, we build a Qcow2 virtual machine using `-f vm` and launch 
immediately after build it using `--run`.
```shell
nixos-generate -f vm -c config.nix --run
```

## Run the orchestrator

In a terminal, run the VM orchestrator.
> ℹ️ The `orchestrator` command is a shell alias to `python -m aleph.vm.orchestrator`.

```shell
$ orchestrator
```

## Test the orchestrator

> ℹ️ The `check-fastapi` command is a shell alias to `curl -i http://127.0.0.1:4020/status/check/fastapi`.

In another terminal, call the FastAPI checks using an HTTP request.
```shell
check-fastapi
````

## Cleanup

In case you used a Qcow2 virtual machine, remove all state using:
```shell
rm nixos.qcow2
```
