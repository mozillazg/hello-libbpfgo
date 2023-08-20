# hello-libbpfgo

[![Build examples](https://github.com/mozillazg/hello-libbpfgo/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/mozillazg/hello-libbpfgo/actions/workflows/build.yml)

Examples for libbpf and libbpfgo.

https://mozillazg.com/tag/libbpf.html


## setup develop env

```
$ vagrant up
```

## Program Types

+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| Program Type                            | Attach Type                          | ELF Section Name        | Examples  | Sleepable |
+=========================================+======================================+=========================+===========+===========+
| `BPF_PROG_TYPE_CGROUP_DEVICE`           | `BPF_CGROUP_DEVICE`                  | `cgroup/dev`            |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_CGROUP_SKB`              |                                      | `cgroup/skb`            |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET_EGRESS`             | `cgroup_skb/egress`     |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET_INGRESS`            | `cgroup_skb/ingress`    |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_CGROUP_SOCKOPT`          | `BPF_CGROUP_GETSOCKOPT`              | `cgroup/getsockopt`     |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_SETSOCKOPT`              | `cgroup/setsockopt`     |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`        | `BPF_CGROUP_INET4_BIND`              | `cgroup/bind4`          |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET4_CONNECT`           | `cgroup/connect4`       |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET4_GETPEERNAME`       | `cgroup/getpeername4`   |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET4_GETSOCKNAME`       | `cgroup/getsockname4`   |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET6_BIND`              | `cgroup/bind6`          |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET6_CONNECT`           | `cgroup/connect6`       |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET6_GETPEERNAME`       | `cgroup/getpeername6`   |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET6_GETSOCKNAME`       | `cgroup/getsockname6`   |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_UDP4_RECVMSG`            | `cgroup/recvmsg4`       |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_UDP4_SENDMSG`            | `cgroup/sendmsg4`       |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_UDP6_RECVMSG`            | `cgroup/recvmsg6`       |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_UDP6_SENDMSG`            | `cgroup/sendmsg6`       |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_CGROUP_SOCK`             | `BPF_CGROUP_INET4_POST_BIND`         | `cgroup/post_bind4`     |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET6_POST_BIND`         | `cgroup/post_bind6`     |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET_SOCK_CREATE`        | `cgroup/sock_create`    |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `cgroup/sock`           |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_CGROUP_INET_SOCK_RELEASE`       | `cgroup/sock_release`   |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_CGROUP_SYSCTL`           | `BPF_CGROUP_SYSCTL`                  | `cgroup/sysctl`         |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_EXT`                     |                                      | `freplace+`[^1]         |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_FLOW_DISSECTOR`          | `BPF_FLOW_DISSECTOR`                 | `flow_dissector`        |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_KPROBE`                  |                                      | `kprobe+`[^2]           |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `kretprobe+`[^3]        |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `ksyscall+`[^4]         |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | > `kretsyscall+`[^5]    |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `uprobe+`[^6]           |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `uprobe.s+`[^7]         |           | Yes       |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `uretprobe+`[^8]        |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `uretprobe.s+`[^9]      |           | Yes       |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `usdt+`[^10]            |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_TRACE_KPROBE_MULTI`             | `kprobe.multi+`[^11]    |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `kretprobe.multi+`[^12] |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_LIRC_MODE2`              | `BPF_LIRC_MODE2`                     | `lirc_mode2`            |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_LSM`                     | `BPF_LSM_CGROUP`                     | `lsm_cgroup+`           |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_LSM_MAC`                        | `lsm+`[^13]             |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `lsm.s+`[^14]           |           | Yes       |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_LWT_IN`                  |                                      | `lwt_in`                |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_LWT_OUT`                 |                                      | `lwt_out`               |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_LWT_SEG6LOCAL`           |                                      | `lwt_seg6local`         |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_LWT_XMIT`                |                                      | `lwt_xmit`              |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_PERF_EVENT`              |                                      | `perf_event`            |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE` |                                      | `raw_tp.w+`[^15]        |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `raw_tracepoint.w+`     |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_RAW_TRACEPOINT`          |                                      | `raw_tp+`[^16]          |[e12] [e13]|           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `raw_tracepoint+`       |[e12] [e13]|           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_SCHED_ACT`               |                                      | `action`                |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_SCHED_CLS`               |                                      | `classifier`            |[e21] [e25]|           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `tc`                    |[e21] [e25]|           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_SK_LOOKUP`               | `BPF_SK_LOOKUP`                      | `sk_lookup`             |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_SK_MSG`                  | `BPF_SK_MSG_VERDICT`                 | `sk_msg`                |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_SK_REUSEPORT`            | `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` | `sk_reuseport/migrate`  |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_SK_REUSEPORT_SELECT`            | `sk_reuseport`          |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_SK_SKB`                  |                                      | `sk_skb`                |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_SK_SKB_STREAM_PARSER`           | `sk_skb/stream_parser`  |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_SK_SKB_STREAM_VERDICT`          | `sk_skb/stream_verdict` |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_SOCKET_FILTER`           |                                      | `socket`                |[e18] [e19] |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_SOCK_OPS`                | `BPF_CGROUP_SOCK_OPS`                | `sockops`               |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_STRUCT_OPS`              |                                      | `struct_ops+`           |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_SYSCALL`                 |                                      | `syscall`               |           | Yes       |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_TRACEPOINT`              |                                      | `tp+`[^17]              |  [e04] [e07] [e14]|           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `tracepoint+`[^18]      | [e04] [e07] [e14] |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_TRACING`                 | `BPF_MODIFY_RETURN`                  | `fmod_ret+`[^19]        |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `fmod_ret.s+`[^20]      |           | Yes       |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_TRACE_FENTRY`                   | `fentry+`[^21]          |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `fentry.s+`[^22]        |           | Yes       |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_TRACE_FEXIT`                    | `fexit+`[^23]           |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `fexit.s+`[^24]         |           | Yes       |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_TRACE_ITER`                     | `iter+`[^25]            |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `iter.s+`[^26]          |           | Yes       |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_TRACE_RAW_TP`                   | `tp_btf+`[^27]          |[e16] [e17]|           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
| `BPF_PROG_TYPE_XDP`                     | `BPF_XDP_CPUMAP`                     | `xdp.frags/cpumap`      |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `xdp/cpumap`            |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_XDP_DEVMAP`                     | `xdp.frags/devmap`      |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `xdp/devmap`            |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         | `BPF_XDP`                            | `xdp.frags`             |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+
|                                         |                                      | `xdp`                   |           |           |
+-----------------------------------------+--------------------------------------+-------------------------+-----------+-----------+

**Footnotes**

[^1]: The `fentry` attach format is `fentry[.s]/<function>`.

[^2]: The `kprobe` attach format is `kprobe/<function>[+<offset>]`. Valid characters for `function` are `a-zA-Z0-9_.` and `offset` must be a valid non-negative integer.

[^3]: The `kprobe` attach format is `kprobe/<function>[+<offset>]`. Valid characters for `function` are `a-zA-Z0-9_.` and `offset` must be a valid non-negative integer.

[^4]: The `ksyscall` attach format is `ksyscall/<syscall>`.

[^5]: The `ksyscall` attach format is `ksyscall/<syscall>`.

[^6]: The `uprobe` attach format is `uprobe[.s]/<path>:<function>[+<offset>]`.

[^7]: The `uprobe` attach format is `uprobe[.s]/<path>:<function>[+<offset>]`.

[^8]: The `uprobe` attach format is `uprobe[.s]/<path>:<function>[+<offset>]`.

[^9]: The `uprobe` attach format is `uprobe[.s]/<path>:<function>[+<offset>]`.

[^10]: The `usdt` attach format is `usdt/<path>:<provider>:<name>`.

[^11]: The `kprobe.multi` attach format is `kprobe.multi/<pattern>` where `pattern` supports `*` and `?` wildcards. Valid characters for pattern are `a-zA-Z0-9_.*?`.

[^12]: The `kprobe.multi` attach format is `kprobe.multi/<pattern>` where `pattern` supports `*` and `?` wildcards. Valid characters for pattern are `a-zA-Z0-9_.*?`.

[^13]: The `lsm` attachment format is `lsm[.s]/<hook>`.

[^14]: The `lsm` attachment format is `lsm[.s]/<hook>`.

[^15]: The `raw_tp` attach format is `raw_tracepoint[.w]/<tracepoint>`.

[^16]: The `raw_tp` attach format is `raw_tracepoint[.w]/<tracepoint>`.

[^17]: The `tracepoint` attach format is `tracepoint/<category>/<name>`.

[^18]: The `tracepoint` attach format is `tracepoint/<category>/<name>`.

[^19]: The `fentry` attach format is `fentry[.s]/<function>`.

[^20]: The `fentry` attach format is `fentry[.s]/<function>`.

[^21]: The `fentry` attach format is `fentry[.s]/<function>`.

[^22]: The `fentry` attach format is `fentry[.s]/<function>`.

[^23]: The `fentry` attach format is `fentry[.s]/<function>`.

[^24]: The `fentry` attach format is `fentry[.s]/<function>`.

[^25]: The `iter` attach format is `iter[.s]/<struct-name>`.

[^26]: The `iter` attach format is `iter[.s]/<struct-name>`.

[^27]: The `fentry` attach format is `fentry[.s]/<function>`.

[e04]: https://github.com/mozillazg/hello-libbpfgo/tree/master/04-tracepoint
[e07]: https://github.com/mozillazg/hello-libbpfgo/tree/master/07-tracepoint-args
[e12]: https://github.com/mozillazg/hello-libbpfgo/tree/master/12-raw-tracepoint-args
[e13]: https://github.com/mozillazg/hello-libbpfgo/tree/master/13-raw-tracepoint-args-sched_switch
[e14]: https://github.com/mozillazg/hello-libbpfgo/tree/master/14-tracepoint-args-sched_switch
[e16]: https://github.com/mozillazg/hello-libbpfgo/tree/master/16-btf-raw-tracepoint-args
[e17]: https://github.com/mozillazg/hello-libbpfgo/tree/master/17-btf-raw-tracepoint-args-sched_switch
[e18]: https://github.com/mozillazg/hello-libbpfgo/tree/master/18-socket-filter-capture-icmp-traffic-kernel-parse
[e19]: https://github.com/mozillazg/hello-libbpfgo/tree/master/19-socket-filter-capture-icmp-traffic-userspace-parse
[e20]: https://github.com/mozillazg/hello-libbpfgo/tree/master/20-socket-filter-capture-icmp-traffic-kernel-parse-without-llvm-load
[e21]: https://github.com/mozillazg/hello-libbpfgo/tree/master/21-tc-parse-packet-with-bpf_skb_load_bytes
[e25]: https://github.com/mozillazg/hello-libbpfgo/tree/master/25-tc-parse-packet-with-direct-memory-access

