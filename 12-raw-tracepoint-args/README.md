
https://mozillazg.com/2022/05/ebpf-libbpf-raw-tracepoint-common-questions.html

## Usage

build:

```
$ make
```

run:

```
$ sudo ./main

$ touch a.txt
$ chmod 600 a.txt

$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```
