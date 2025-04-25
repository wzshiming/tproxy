package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"

	"github.com/wzshiming/tproxy"
)

var (
	dns string
)

func init() {
	flag.StringVar(&dns, "d", "", "dns server")
	flag.Parse()
}

func main() {
	logger := log.New(os.Stderr, "[tproxy] ", log.LstdFlags)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logger.Fatalf("Failed to start TCP server: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				logger.Println(err)
				return
			}
			addr, err := tproxy.OriginalDestnation(conn.(*net.TCPConn))
			if err != nil {
				logger.Println(conn.RemoteAddr(), err)
				conn.Close()
			} else {
				logger.Println(conn.RemoteAddr(), "->", addr)
				go func() {
					defer conn.Close()
					dialer := &net.Dialer{
						Control: tproxy.Control,
					}
					r, err := dialer.Dial("tcp", addr.String())
					if err != nil {
						logger.Println(err)
						return
					}
					defer r.Close()

					err = tunnel(context.Background(), conn, r)
					if err != nil {
						logger.Println(err)
						return
					}
				}()
			}
		}
	}()

	p, err := tproxy.NewTProxy(nil)
	if err != nil {
		logger.Fatalf("Failed to start TProxy: %v", err)
	}
	defer p.Close()

	serverAddr := ln.Addr().String()
	_, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		logger.Fatalf("Failed to split server address: %v", err)
	}
	portNum, err := strconv.ParseInt(port, 0, 0)
	if err != nil {
		logger.Fatalf("Failed to parse port number: %v", err)
	}
	dHost, dPort, _ := net.SplitHostPort(dns)

	dPortNum, _ := strconv.ParseInt(dPort, 0, 0)

	err = p.Local(int(portNum), int(dPortNum), dHost)
	if err != nil {
		logger.Fatalf("Failed to start local: %v", err)
	}

	// Create a channel to receive OS signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	// Wait for signal
	<-sigCh
	logger.Println("Received interrupt signal, shutting down...")
}

// tunnel create tunnels for two io.ReadWriteCloser
func tunnel(ctx context.Context, c1, c2 io.ReadWriteCloser) error {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(c1, c2)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(c2, c1)
		errCh <- err
	}()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
