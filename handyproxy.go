package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/binary-manu/handyproxy/hostname"
)

var version = "master"

var localPort = flag.Int("local-port", 8443, "local port to listen on for REDIRECTed traffic")
var upstreamProxy = flag.String("upstream-proxy", "localhost:3128", "upstream proxy to CONNECT to")
var versionFlag = flag.Bool("version", false, "show version information")
var dialTimeout = flag.Duration("dial-timeout", 3*time.Minute, "timeout for connections to the proxy")
var sniffTimeOut = flag.Duration("sniff-timeout", 0, "maximum acceptable delay for hostname sniffing (0 -> disable)")
var sniffMaxBytes = flag.Uint64("sniff-max-bytes", 16384, "maximum number of bytes used for hostname sniffing")

func main() {

	flag.Parse()

	fmt.Println("HandyProxy", version)
	if *versionFlag {
		return
	}

	if *sniffMaxBytes > ((1 << 63) - 1) {
		log.Fatalln("-sniff-max-bytes value is too big")
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
	_, err = io.CopyN(io.Discard, connectRsp.Body, connectRsp.ContentLength)
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
	defer c.Close()

	origin, err := getOriginalDestination(c)
	if err != nil {
		log.Println(err)
		return
	}

	var hostSniffer *hostname.HostNameSniffer
	if *sniffTimeOut > 0 {
		hostSniffer = hostname.NewSniffer(
			hostname.WithMaxData(int64(*sniffMaxBytes)),
			hostname.WithTimeout(*sniffTimeOut),
			hostname.WithSnifferStrategy(hostname.HTTPSniffer()),
			hostname.WithSnifferStrategy(hostname.TLSSniffer()),
		)
		hostName, err := hostSniffer.SniffHostName(c)
		if err == nil {
			origin = hostName
			log.Printf("Extracted hostname for client connection %s: %s", c.RemoteAddr().String(), hostName)
		} else {
			log.Printf("Hostname extraction failed for client connection %s: %s", c.RemoteAddr().String(), err)
		}
	}

	pipe, err := setupConnectUpstream(origin)
	if err != nil {
		log.Println(err)
		return
	}
	defer pipe.Close()

	if hostSniffer != nil {
		_, err = hostSniffer.GetBufferedData().WriteTo(pipe)
		if err != nil {
			return
		}
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
}
