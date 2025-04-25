package tproxy

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	ip4tSoOriginalDst   = 0x50
	ip6tSoOriginalDst   = 0x50
	sizeofSockaddrInet  = 0x10
	sizeofSockaddrInet6 = 0x1c
)

func Control(network, address string, c syscall.RawConn) error {
	var err error
	c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 0)
	})
	return err
}

func OriginalDestnation(conn *net.TCPConn) (net.Addr, error) {
	f, err := conn.File()
	if err != nil {
		return nil, err
	}

	fd := f.Fd()

	la, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("failed to get local address")
	}

	var level, name int
	var b []byte
	if la.IP.To4() != nil {
		level = syscall.IPPROTO_IP
		name = ip4tSoOriginalDst
		b = make([]byte, sizeofSockaddrInet)
	} else if la.IP.To16() != nil {
		level = syscall.IPPROTO_IPV6
		name = ip6tSoOriginalDst
		b = make([]byte, sizeofSockaddrInet6)
	} else {
		return nil, fmt.Errorf("invalid IP address")
	}

	l := uint32(len(b))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(level), uintptr(name),
		uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&l)), 0)
	if errno != 0 {
		return nil, errno
	}

	od := new(net.TCPAddr)
	switch len(b) {
	case sizeofSockaddrInet:
		od.IP = make(net.IP, net.IPv4len)
		copy(od.IP, b[4:8])
		od.Port = int(b[2])<<8 + int(b[3])
	case sizeofSockaddrInet6:
		od.IP = make(net.IP, net.IPv6len)
		copy(od.IP, b[8:24])
		od.Port = int(b[2])<<8 + int(b[3])
	default:
		return nil, fmt.Errorf("invalid address length")
	}

	return od, nil
}
