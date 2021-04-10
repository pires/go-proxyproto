package main

import (
	"log"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

func main() {
	// Create a listener
	addr := "localhost:9876"
	list, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("couldn't listen to %q: %q\n", addr, err.Error())
	}

	// Wrap listener in a proxyproto listener
	proxyListener := &proxyproto.Listener{Listener: list}
	defer proxyListener.Close()

	// Wait for a connection and accept it
	conn, err := proxyListener.Accept()
	defer conn.Close()

	// Print connection details
	if conn.LocalAddr() == nil {
		log.Fatal("couldn't retrieve local address")
	}
	log.Printf("local address: %q", conn.LocalAddr().String())

	if conn.RemoteAddr() == nil {
		log.Fatal("couldn't retrieve remote address")
	}
	log.Printf("remote address: %q", conn.RemoteAddr().String())
}
