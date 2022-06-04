

## Usage

build:

```
$ make
```

run:

```
$ kubectl run test --image docker.io/calico/node:v3.19.1 \
    -- sh -c 'while true; do ls > /dev/null && sleep 10; done'

$ sudo ./main

$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```
