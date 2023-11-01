//go:build !debug && linux

package main

/*
#include <sys/socket.h>
*/
import "C"
import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80

var byteOrder binary.ByteOrder

func init() {
	var x uint16 = 0xAA00
	if *(*byte)(unsafe.Pointer(&x)) == 0x00 {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}
}

func ntohs(s uint16) uint16 {
	return byteOrder.Uint16([]byte{byte(s >> 8), byte(s)})
}

func getOriginalDestination(c *net.TCPConn) (origin string, err error) {
	file, err := c.File()
	if err != nil {
		return
	}
	defer file.Close()
	fd := file.Fd()

	var addr syscall.RawSockaddrInet4
	addrLen := C.socklen_t(unsafe.Sizeof(addr))
	err = getsockopt(fd, syscall.SOL_IP, soOriginalDst, unsafe.Pointer(&addr), &addrLen)
	if err != nil {
		return
	}
	origin = (&net.TCPAddr{IP: net.IP(addr.Addr[:]), Port: int(ntohs(addr.Port))}).String()
	localAddr := c.LocalAddr().String()
	if origin == localAddr {
		err = fmt.Errorf("received non REDIRECTed traffic to %s from %s, discarding", localAddr, c.RemoteAddr().String())
		return
	}
	return
}

func getsockopt(s uintptr, level uintptr, optname uintptr, optval unsafe.Pointer, optlen *C.socklen_t) (err error) {
	_, _, e := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT, s, level, optname,
		uintptr(optval), uintptr(unsafe.Pointer(optlen)), 0)
	if e != 0 {
		return e
	}
	return
}
