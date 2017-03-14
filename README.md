Prototype interface for examining core files.
The goal is to build a tool for understanding OOMs.
This is a WIP. See corefile/doc.go for known bugs and TODOs.

Quick start:

```
$ cd examples
$ ulimit -c unlimited
$ go build -o httpleak httpleak.go
$ GOTRACEBACK=crash ./httpleak
$ go run github.com/tombergan/goheapdump/heapcheck ./core ./httpleak
$ go run github.com/tombergan/goheapdump/heapview ./core ./httpleak
```
