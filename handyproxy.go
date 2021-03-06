// +build linux

package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

/*
#include <sys/socket.h>
*/
import "C"

var version = "master"

const _SO_ORIGINAL_DST = 80

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

var localPort = flag.Int("local-port", 8443, "local port to listen on for REDIRECTed traffic")
var upstreamProxy = flag.String("upstream-proxy", "localhost:3128", "upstream proxy to CONNECT to")
var versionFlag = flag.Bool("version", false, "show version information")
var dialTimeout = flag.Duration("dial-timeout", 3*time.Minute, "timeout for connections to the proxy")

func main() {

	flag.Parse()

	fmt.Println("HandyProxy", version)
	if *versionFlag {
		return
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", *localPort))
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Listening for TCP traffic on port %d and sending it to %s\n", *localPort, *upstreamProxy)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn.(*net.TCPConn))
	}
}

func setupConnectUpstream(origin string) (c *net.TCPConn, err error) {
	var pipe *net.TCPConn

	defer func() {
		if err != nil && pipe != nil {
			pipe.Close()
		}
	}()

	pipe0, err := net.DialTimeout("tcp4", *upstreamProxy, *dialTimeout)
	if err != nil {
		return
	}
	pipe = pipe0.(*net.TCPConn)

	connectReq, err := http.NewRequest("CONNECT", "http://"+origin, nil)
	if err != nil {
		return
	}
	if err = connectReq.Write(pipe); err != nil {
		return
	}
	connectRsp, err := http.ReadResponse(bufio.NewReader(pipe), connectReq)
	if err != nil {
		return
	}
	defer connectRsp.Body.Close()
	_, err = io.CopyN(ioutil.Discard, connectRsp.Body, connectRsp.ContentLength)
	if err != nil {
		return
	}
	if connectRsp.StatusCode/100 != 2 {
		err = fmt.Errorf("CONNECT to proxy %s for origin %s returned status code %d instead of 2xx",
			*upstreamProxy, origin, connectRsp.StatusCode)
		return
	}

	return pipe, nil
}

func handleConnection(c *net.TCPConn) {
	origin, err := getOriginalDestination(c)
	if err != nil {
		c.Close()
		log.Println(err)
		return
	}
	pipe, err := setupConnectUpstream(origin)
	if err != nil {
		c.Close()
		log.Println(err)
		return
	}
	handleTunnel(c, pipe)
}

func handleTunnel(in, out *net.TCPConn) {
	var wg sync.WaitGroup
	copier := func(dst, src *net.TCPConn) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.CloseWrite()
	}
	wg.Add(2)
	go copier(in, out)
	go copier(out, in)
	wg.Wait()
	in.Close()
	out.Close()
}

func getOriginalDestination(c *net.TCPConn) (origin string, err error) {
	file, err := c.File()
	if err != nil {
		return
	}
	defer file.Close()
	fd := file.Fd()

	var addr syscall.RawSockaddrInet4
	len := C.socklen_t(unsafe.Sizeof(addr))
	err = getsockopt(fd, syscall.SOL_IP, _SO_ORIGINAL_DST, unsafe.Pointer(&addr), &len)
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
