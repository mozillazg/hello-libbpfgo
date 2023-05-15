https://mozillazg.com/2022/05/ebpf-libbpfgo-get-container-info-via-process-info.rst.html

## Usage

build:

```
$ make
```

run:

```
$ sudo microk8s start

$ kubectl run test --image docker.io/calico/node:v3.19.1 \
    -- sh -c 'while true; do ls > /dev/null && sleep 10; done'

$ sudo ./main

$ kubectl delete pod test
$ sudo microk8s stop
```
