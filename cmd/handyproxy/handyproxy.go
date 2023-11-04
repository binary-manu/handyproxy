package main

import (
	"bufio"
	"errors"
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

type options struct {
	LocalPort     *int
	UpstreamProxy *string
	VersionFlag   *bool
	DialTimeout   *time.Duration
	SniffTimeout  *time.Duration
	SniffMaxBytes *int64
}

type hostNameSnifferFactory struct {
	hostNameSnifferFactoryInterface
}

type hostNameSnifferFactoryInterface interface {
	NewHostNameSniffer() *hostname.Sniffer
}

type nullHostNameSnifferFactory struct{}

func (factory *nullHostNameSnifferFactory) NewHostNameSniffer() *hostname.Sniffer {
	return hostname.NewNullSniffer()
}

type parallelHostNameSnifferFactory struct {
	opts *options
}

func (factory *parallelHostNameSnifferFactory) NewHostNameSniffer() *hostname.Sniffer {
	return hostname.NewParallelSniffer(
		hostname.WithParallelMaxData(*factory.opts.SniffMaxBytes),
		hostname.WithParallelTimeout(*factory.opts.SniffTimeout),
		hostname.WithParallelSnifferStrategy(hostname.NewHTTPSnifferStrategy()),
		hostname.WithParallelSnifferStrategy(hostname.NewTLSSnifferStrategy()),
	)
}

func newHostNameSnifferFactoryFromOptions(opts *options) *hostNameSnifferFactory {
	if *opts.SniffTimeout < 0 {
		return &hostNameSnifferFactory{&nullHostNameSnifferFactory{}}
	} else {
		return &hostNameSnifferFactory{&parallelHostNameSnifferFactory{opts}}
	}
}

type connectionContext struct {
	Opts            *options
	C               *net.TCPConn
	HostNameSniffer *hostname.Sniffer
}

func main() {
	options := options{
		LocalPort:     flag.Int("local-port", 8443, "local port to listen on for REDIRECTed traffic"),
		UpstreamProxy: flag.String("upstream-proxy", "localhost:3128", "upstream proxy to CONNECT to"),
		VersionFlag:   flag.Bool("version", false, "show version information"),
		DialTimeout:   flag.Duration("dial-timeout", 3*time.Minute, "timeout for connections to the proxy"),
		SniffTimeout: flag.Duration("sniff-timeout", -1,
			fmt.Sprintf("maximum acceptable delay for hostname sniffing (<0 -> disable, =0 -> %v)", hostname.SniffDefaultTimeout)),
		SniffMaxBytes: flag.Int64("sniff-max-bytes", hostname.SniffDefaultMaxData,
			"maximum number of bytes used for hostname sniffing (<= 0 -> use default)"),
	}
	flag.Parse()

	fmt.Println("HandyProxy", version)
	if *options.VersionFlag {
		return
	}

	hostNameSnifferFactory := newHostNameSnifferFactoryFromOptions(&options)

	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", *options.LocalPort))
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Listening for TCP traffic on port %d and sending it to %s\n", *options.LocalPort, *options.UpstreamProxy)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(&connectionContext{
			Opts:            &options,
			C:               conn.(*net.TCPConn),
			HostNameSniffer: hostNameSnifferFactory.NewHostNameSniffer(),
		})
	}
}

func setupConnectUpstream(ctx *connectionContext, origin string) (c *net.TCPConn, err error) {
	var pipe *net.TCPConn

	defer func() {
		if err != nil && pipe != nil {
			_ = pipe.Close()
		}
	}()

	pipe0, err := net.DialTimeout("tcp4", *ctx.Opts.UpstreamProxy, *ctx.Opts.DialTimeout)
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

	// From RFC9110:
	// Any 2xx (Successful) response indicates that the sender (and all inbound
	// proxies) will switch to tunnel mode immediately after the response header
	// section; data received after that header section is from the server identified
	// by the request target. Any response other than a successful response indicates
	// that the tunnel has not yet been formed.

	// So, if we get a 2xx and have read all headers, rest of the data must come
	// from the origin, so don't try to read the body. Otherwise, we have an
	// error, and that may have a body, but we do not care about it.

	if connectRsp.StatusCode/100 != 2 {
		err = fmt.Errorf("CONNECT to proxy %s for origin %s returned status code %d instead of 2xx",
			*ctx.Opts.UpstreamProxy, origin, connectRsp.StatusCode)
		return
	}

	return pipe, nil
}

func handleConnection(ctx *connectionContext) {
	defer ctx.C.Close()

	origin, err := getOriginalDestination(ctx.C)
	if err != nil {
		log.Println(err)
		return
	}

	hostName, err := ctx.HostNameSniffer.SniffHostName(ctx.C)
	if err == nil {
		origin = hostName
		log.Printf("Extracted hostname for client connection %s: %s", ctx.C.RemoteAddr().String(), hostName)
	} else {
		log.Printf("Hostname extraction failed for client connection %s: %s", ctx.C.RemoteAddr().String(), err)
		if errors.As(err, new(*hostname.FatalError)) {
			return
		}
	}

	pipe, err := setupConnectUpstream(ctx, origin)
	if err != nil {
		log.Println(err)
		return
	}
	defer pipe.Close()

	_, err = ctx.HostNameSniffer.GetBufferedData().WriteTo(pipe)
	if err != nil {
		return
	}
	handleTunnel(ctx.C, pipe)
}

func handleTunnel(in, out *net.TCPConn) {
	var wg sync.WaitGroup
	copier := func(dst, src *net.TCPConn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = dst.CloseWrite()
	}
	wg.Add(2)
	go copier(in, out)
	go copier(out, in)
	wg.Wait()
}
