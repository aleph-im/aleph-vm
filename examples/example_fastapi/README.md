Publish using:

```shell
 aleph program upload ../aleph-vm/examples/example_fastapi main:app \
  --persistent-volume "persistence=host,size_mib=1,mount=/var/lib/example,name=increment-storage,comment=Persistence"
```
