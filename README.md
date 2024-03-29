# HandyProxy

HandyProxy is an extremely simple TCP traffic forwarder, working as a
transparent proxy. It intercepts traffic meant for remote machines and
then forwards it to the final destination via an upstream HTTP proxy by
making [HTTP `CONNECT`][http-connect] requests.  Its main goal is to
provide hosts behind HTTP proxies access to such services without
reconfiguration, easing bulk migrations from environments with direct
Internet access to environments behind a proxy.

It is a Linux-only application, as it depends on Linux-specific system
calls to handle incoming traffic. It is also meant to be used together
with netfilter rules to capture HTTP(S) traffic.

It currently only supports IPv4.

## How does it work?

HandyProxy listens for TCP traffic on a configurable port. Every time a
new connection arrives, it tries to determine if such connection was
direct, or if it is actually traffic for another machine that was
redirected to HandyProxy via a `DNAT`/`REDIRECT` rule. This is possible
thanks to a [Linux system call][get-original-dst] which returns the
original destination for `DNAT`ed traffic.

Direct connections are discarded. For other connections, it sends an
HTTP `CONNECT` request to the configured upstream proxy, asking it to
open a tunnel to the orginal destination. From this point on, traffic is
simply copied between the incoming connection and the proxy, in both
directions.

## Why do I need it?

Suppose you have a system (let's call this system A) behind a
traditional modem/router doing masquerading and connecting directly to
the internet.  This system can connect to any remote HTTP(S) sites.

Now the system is moved behind an (unauthenticated) HTTP proxy. In order
to get internet connectivity, clients must now [modify HTTP
requests][mitmproxy] to cope with the proxy. For plain HTTP, this means
that the origin server name must be added to the request; for HTTPS
traffic, a `CONNECT` request must be made to open a tunnel to the origin
server and allow TLS packets to flow unmodified.

_Any_ tools issuing HTTP(S) requests on A, such as your
browser, your package manager, Docker and containerized apps, must be
configured to use a proxy. With many machines and many different places
where this must be configured, it gets out of hand pretty quickly,
even when using automation tools like Ansible.

Another approach is possible: if all traffic produced by A must flow
through a second system doing the routing (let's call it R), R could
be configured to act as a transparent proxy. Rather than simply
forwarding HTTP(S) traffic to the next hop, it can intercept it and pass
it to HandyProxy. HandyProxy will then open a connection to the HTTP
proxy, ask it to open a tunnel to the real destination, and forward the
traffic.

This way, system A does not need any proxy configuration and can still
issue normal HTTP(S) requests, whose TCP fragments are targeting port
80/443 of the origin server. It is HandyProxy that will take care of
doing the `CONNECT` requests to the proxy.

If it is not possible to install HandyProxy on R, A itself could host
it and have its own `OUTPUT` traffic `REDIRECT`ed by netfilter rather
than `FORWARD`ed traffic. Of course, installing HandyProxy on a router
machine means that it can handle traffic produced by all
nodes on the subnets this router serves.

## Quirks

Currently, HTTP and HTTPS connection are treated uniformly: HandyProxy
always opens a tunnel using a `CONNECT` request, even for nonencrypted
traffic. This works as long as the proxy accepts `CONNECT` requests to
both port 80 and 443.

As a consequence of this design, HandyProxy does not need to inspect the traffic
it forwards in any way (but see [hostname sniffing](#hostname-sniffing)). It can
therefore handle non-HTTP traffic using ports different than 80/443, as long as
the proxy is willing to satisfy a `CONNECT` to that port.

## Authentication

It is unlikely than a network employing a proxy will have it
unauthenticated: credentials will be needed when sending HTTP `CONNECT`
requests. HandyProxy does not support authenticated requests, and it
need not. [cNTLM][cntlm] is a well-know tool that offers an
unauthenticated HTTP proxy interface, automatically adding credentials
before forwarding them to the real proxy. It can be used as HandyProxy's
upstream proxy to add credentials and it will, in turn, contact the real
proxy.

One word of caution: if a single instance of HandyProxy can serve
multiple hosts, then _all_ traffic will be routed to the same cNTLM
instance and will, therefore, use the same credentials. Unless all
machines are under the responsibility of a single entity to which the
credentials belong, this may cause unwanted activities being recorded by
the proxy as performed by the entity whose credentials are stored in
cNTLM. However, a host can run multiple instances of HandyProxy, each
one configured with a different cNTLM upstream and port, and then each
host's traffic can be redirected to a different port using multiple
netfilter rules.

## Hostname sniffing

<a name="hostname-sniffing"></a>

handyproxy (since version 0.2.1) can try to sniff the original host name of the
target machine from the first bytes of the client data.

### General idea

Since we work as a transparent proxy, the client never explicitly performs
operations as if it was connecting to a proxy. It just resolves the target
hostname locally (thus potentially using local sources like
`/etc/hosts`) and then sends out packets acxcording to its own routing
table. When this traffic hits handyproxy (which could run on the same
system as the client or on another machine) there are no longer any
references to the original hostname. If these were proxy requests, the
client would have sent the full target hostname and let the proxy
resolve it by itself. But this is not the case.

However, some protocols do embed the target hostname into the first
bytes of the data stream sent from the client. For exemple, HTTP
requests have the `Host` header, while TLS has the `SNI` (Server Name
Indication) extension. Thus, it is possible to recover this information
by looking at the first byte of the connection, before actually
forwarding it to the target. Depending on whether an hostname is
recovered or not, handyproxy will issue requests to the upstream proxy
using either an hostname or an IP address.

This feature is useful in a number of circumstances:

* your proxy is using access control lists to filter traffic and refuses
  to allow traffic to plain IP destinations;
* you want more descriptive logs on your proxy.

However, the actual feasability of this scan relies on the type of
traffic.  if there's no reference to the original hostname in the data
stream, this cannot work. 

At the moment handyproxy can sniff HTTP and TLS connections to recover the
hostname, provided these carry the appropriate headers/extensions.  Both
scanners run in parallel if possible. There is currently no way to restrict
scanners to a specific set of destination ports (for example, apply the HTTP
sniffing only to packets targeting remote port 80/TCP).

Hostname sniffing is disabled by default, to keep the behaviour of previous
handyproxy versions. To enable it, you have to set a non-negative sniff timeout
(a value of 0 applies the default of 1s, see below).

### Timeout and data limit

So we want to analyze the first bytes sent on an incoming
connection. But there are a couple of challenges.

First, since we must delay the forwarding of data until we have
recovered a hostname (or failed to do do), all incoming data must be
buffered.  We must put an upper limit on this amount, to avoid using an
excessive amount of memory.

Second, the sniffing delay introduces latency in the connection. We don't want
clients to have to wait more than it is reasonable before bailing out and just
using the IP. This is especially important for protocols that start by sending
small amounts of data that do not trigger the data size limit above and do not
contain an hostname, not to mention protocols where the server speaks first
(like SMTP). If we cannot recover the hostname within a bounded amount of time,
hust proceed with the IP.

These rules define two parameters, the `sniff timeout` and the `sniff
data limit`. Both are used to bound the space and time requirements of
the sniffing so that protocols for which this scan is meaningless incur
a limited and predictable overhead, without placing a burden on the host
memory.

By default:

* the sniff timeout is one second;
* the sniff data limit is 8192 bytes.

These can be tweaked via the CLI.

## File descriptor limit

HandyProxy can use a lot of file descriptors, since each incoming connection
requires one socket and each connection to the proxy requires an additional one.
So, to handle N connections at the same time it will use approximatley 2N
descriptors. If your default per-process soft file descriptor limit is low (1024
or so) consider increasing it.


## Putting it all together

The diagram below shows how traffic flows from a client performing an
HTTPS request to the origin server. For simplicity, local ports are
chosen sequentially starting at 20000, while in a real case they would
be random. Publicly routable addresses are taken from the `TEST-NET-1`
range of [reserved IPv4 addresses][reserved-ipv4], 192.0.2.0/24.

To emphasize modularity, all elements (HandyProxy, cNTLM and HTTP proxy)
run on their own systems, but it would be perfectly viable to colocate
some of them on the same machine.

![Packet Flow][packetflow]

## Running HandyProxy

Simply run HandyProxy on a machine routing traffic from other hosts,
giving it the local port to listen on and the upstream proxy (IP address
or domain name). It is also possible to specify a timeout to wait for
when connecting to the proxy (otherwise a reasonable default is used):

```sh
# Without hostname sniffing
$ handyproxy -local-port 8043 -upstream-proxy proxy.local -dial-timeout 25s

# With hostname sniffing
$ handyproxy -local-port 8043 -upstream-proxy proxy.local -dial-timeout 25s \
  -sniff-max-bytes 16384 -sniff-timeout 2s
```

Note that HandyProxy listens on all interfaces:

```
$ ss -tln
State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process               
LISTEN  0       4096          0.0.0.0:8043       0.0.0.0:*                           
```

After that, add netfilter rules to pass all TCP traffic to port 80 or
443 coming from the subnets to serve to the daemon (the example shows
just one port for brevity):

```sh
$ sudo iptables -t nat -A PREROUTING -i eth0 -m addrtype ! --dst-type LOCAL \
  -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8043
```

That's it! All HTTP(S) traffic coming in from `eth0` should now be
forwarded. Excluding local addresses ensures that if HandyProxy is
colocated with any application listening on port 443, `INPUT` traffic
will not undergo redirection. The rule may be tweaked to exclude
local HTTPS servers that should not be proxied, or cNTLM could be
configured to connect to them directly via its `NoProxy` directive.

If it is desired to redirect traffic produced by an host to its own
local HandyProxy instance (as an alternative to local proxy
configuration in cases where it is not possible to run HandyProxy on a
router), the rule is different since such traffic does not traverse
`PREROUTING`.  The rule should be added to the `OUTPUT` chain.

```sh
$ sudo iptables -t nat -A OUTPUT -m addrtype ! --dst-type LOCAL \
  -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8043
```

As usual, tweak it for your local needs.


[cntlm]: http://cntlm.sourceforge.net/
[packetflow]: ./docs/packetflow.png
[http-connect]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT
[get-original-dst]: https://gist.github.com/cannium/55ec625516a24da8f547aa2d93f49ecf
[mitmproxy]: https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/
[reserved-ipv4]: https://en.wikipedia.org/wiki/Reserved_IP_addresses

<!-- vi: set et sw=2 sts=-1 tw=72 fo=tronqa : -->
