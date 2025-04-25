package tproxy

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestTProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start TCP server: %v", err)
	}
	defer ln.Close()

	gotCh := make(chan string)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			addr, err := OriginalDestnation(conn.(*net.TCPConn))
			if err != nil {
				t.Fatal(err)
			}
			gotCh <- addr.String()
			conn.Close()
			return
		}
	}()

	p, err := NewTProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	serverAddr := ln.Addr().String()

	_, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	portNum, err := strconv.ParseInt(port, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = p.Local(int(portNum), 53, "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}

	want := "8.8.8.8:53"
	conn, err := net.Dial("tcp4", want)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var got string

	select {
	case got = <-gotCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
