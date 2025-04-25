//go:build !linux && !darwin
// +build !linux,!darwin

package tproxy

import (
	"fmt"
	"net"
	"syscall"
)

func Control(network, address string, c syscall.RawConn) error {
	return nil
}
func OriginalDestnation(conn *net.TCPConn) (net.Addr, error) {
	return nil, fmt.Errorf("unsupported yet")
}
