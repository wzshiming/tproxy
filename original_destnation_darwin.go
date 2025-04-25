package tproxy

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

const (
	// https://github.com/apple/darwin-xnu/blob/master/bsd/net/pfvar.h#L158
	_PF_OUT = 2
	// https://github.com/apple/darwin-xnu/blob/master/bsd/net/pfvar.h#L2096
	_DIOCNATLOOK = 3226747927
)

func Control(network, address string, c syscall.RawConn) error {
	return nil
}

func OriginalDestnation(conn *net.TCPConn) (net.Addr, error) {
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, errors.New("failed to get client address")
	}
	la, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, errors.New("failed to get bind address")
	}

	f, err := getDevFd()
	if err != nil {
		return nil, err
	}
	fd := f.Fd()

	pnl := new(pfioc_natlook)
	pnl.direction = _PF_OUT
	pnl.proto = syscall.IPPROTO_TCP

	if ra.IP.To4() != nil {
		copy(pnl.saddr[:4], ra.IP.To4())
		copy(pnl.daddr[:4], la.IP.To4())
		pnl.af = syscall.AF_INET
	} else if ra.IP.To16() != nil {
		copy(pnl.saddr[:], ra.IP)
		copy(pnl.daddr[:], la.IP)
		pnl.af = syscall.AF_INET6
	}

	// Set ports
	cport := make([]byte, 2)
	binary.BigEndian.PutUint16(cport, uint16(ra.Port))
	copy(pnl.sxport[:], cport)

	lport := make([]byte, 2)
	binary.BigEndian.PutUint16(lport, uint16(la.Port))
	copy(pnl.dxport[:], lport)

	// Do lookup
	err = ioctl(fd, _DIOCNATLOOK, unsafe.Pointer(pnl))
	if err != nil {
		return nil, err
	}

	// Get redirected address
	rport := make([]byte, 2)
	copy(rport, pnl.rdxport[:2])
	port := int(binary.BigEndian.Uint16(rport))

	od := new(net.TCPAddr)
	od.Port = port
	if pnl.af == syscall.AF_INET {
		od.IP = make(net.IP, net.IPv4len)
		copy(od.IP, pnl.rdaddr[:4])
	} else {
		od.IP = make(net.IP, net.IPv6len)
		copy(od.IP, pnl.rdaddr[:])
	}

	return od, nil
}

// opened /dev/pf
var pf *os.File
var pfLock *sync.Mutex = new(sync.Mutex)

func getDevFd() (*os.File, error) {
	const pfDev = "/dev/pf"
	pfLock.Lock()
	defer pfLock.Unlock()
	if pf == nil {
		f, err := os.OpenFile(pfDev, os.O_RDWR, 0644)
		if err != nil {
			return nil, err
		}
		pf = f
	}
	return pf, nil
}

// https://github.com/apple/darwin-xnu/blob/master/bsd/net/pfvar.h#L1773
type pfioc_natlook struct {
	saddr, daddr, rsaddr, rdaddr        [16]byte
	sxport, dxport, rsxport, rdxport    [4]byte
	af, proto, proto_variant, direction uint8
}

func ioctl(fd uintptr, cmd uintptr, ptr unsafe.Pointer) error {
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, uintptr(ptr)); err != 0 {
		return err
	}
	return nil
}
