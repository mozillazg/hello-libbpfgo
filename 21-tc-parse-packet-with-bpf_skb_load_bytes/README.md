


## Usage

build:

```
$ make
```

run:

```
$ make run

$ printf 'HTTP/1.1 200 OK\nContent-Length: 0\n\n' |nc -l 9090 &

$ curl http://127.0.0.1:9090

$ make cat
```
