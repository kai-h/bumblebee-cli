package main

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=v0.1.0" .
var version = "dev"
