package main

import (
	"log"
	"net"
	"net/http"
	"time"

	"github.com/pires/go-proxyproto"
)

// TODO: add httpclient example

func main() {
	server := http.Server{
		Addr: ":8080",
		ConnState: func(c net.Conn, s http.ConnState) {
			if s == http.StateNew {
				log.Printf("[ConnState] %s -> %s", c.LocalAddr().String(), c.RemoteAddr().String())
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[Handler] remote ip %q", r.RemoteAddr)
		}),
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		panic(err)
	}

	proxyListener := &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: 10 * time.Second,
	}
	defer proxyListener.Close()

	server.Serve(proxyListener)
}
