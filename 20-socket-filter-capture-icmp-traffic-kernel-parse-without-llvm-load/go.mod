module github.com/mozillazg/hello-libbpfgo/19-socket-filter-capture-icmp-traffic-kernel-parse

go 1.17

require (
	github.com/aquasecurity/libbpfgo v0.2.5-libbpf-0.7.0
	golang.org/x/net v0.0.0-20220630215102-69896b714898
)

require golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect

replace github.com/aquasecurity/libbpfgo => ../libbpfgo/
