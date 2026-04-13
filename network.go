//go:build linux

package main

// network.go — Virtual networking for the Sentry.
//
// The sandbox can't open real sockets — the Sentry intercepts socket(),
// connect(), read/write/close and the sendto/recvfrom/sockopt family,
// and transparently proxies outbound TCP through net.Dial connections
// the Sentry itself owns. What the guest sees as a file descriptor is a
// virtual fd in the Sentry's fdTable; the real kernel never learns that
// the guest wanted to talk to the network.
//
// The policy layer (NetPolicy) decides which (host, port) pairs the
// guest may reach. Deny wins over allow; an empty allow list means
// allow-all (matching the flag default).

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// NetRule is one CIDR:port entry from --net-allow / --net-deny.
//
// Port 0 in the rule means "all ports"; otherwise the rule matches only
// that exact TCP port. The CIDR is matched against the connect() target
// IP the guest supplies in its sockaddr_in/sockaddr_in6.
type NetRule struct {
	Net  *net.IPNet
	Port int // 0 means any port
}

// NetPolicy pairs allow and deny rules. Deny takes priority. If allows
// is empty, every destination is allowed (the default permissive stance,
// so existing samples keep working when no --net-* flag is passed).
type NetPolicy struct {
	allows []NetRule
	denies []NetRule
}

// parseNetRules parses a comma-separated list of CIDR:port rules.
//
//	"10.0.0.0/8:0"          → all ports on 10/8
//	"0.0.0.0/0:80,0.0.0.0/0:443"  → http + https anywhere
//
// A bare IP (no "/bits") is taken as /32 (or /128 for v6).
func parseNetRules(spec string) ([]NetRule, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var out []NetRule
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Split on the LAST colon so IPv6 addresses (full of colons) still parse.
		i := strings.LastIndex(entry, ":")
		if i < 0 {
			return nil, fmt.Errorf("net rule %q: missing :port", entry)
		}
		cidr, portStr := entry[:i], entry[i+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 0 || port > 65535 {
			return nil, fmt.Errorf("net rule %q: bad port", entry)
		}
		// IPv6 literals may be bracketed in [::1]/128:80 form.
		cidr = strings.TrimPrefix(strings.TrimSuffix(cidr, "]"), "[")
		if !strings.Contains(cidr, "/") {
			if ip := net.ParseIP(cidr); ip != nil {
				if ip.To4() != nil {
					cidr += "/32"
				} else {
					cidr += "/128"
				}
			}
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("net rule %q: %v", entry, err)
		}
		out = append(out, NetRule{Net: ipnet, Port: port})
	}
	return out, nil
}

// NewNetPolicy parses allow/deny specs and returns a policy. Invalid
// specs produce a parse error that main.go surfaces to the user.
func NewNetPolicy(allowSpec, denySpec string) (*NetPolicy, error) {
	allows, err := parseNetRules(allowSpec)
	if err != nil {
		return nil, fmt.Errorf("--net-allow: %v", err)
	}
	denies, err := parseNetRules(denySpec)
	if err != nil {
		return nil, fmt.Errorf("--net-deny: %v", err)
	}
	return &NetPolicy{allows: allows, denies: denies}, nil
}

func ruleMatches(r NetRule, ip net.IP, port int) bool {
	if r.Port != 0 && r.Port != port {
		return false
	}
	return r.Net.Contains(ip)
}

// Allowed reports whether (ip, port) may be dialed. Deny beats allow;
// with no allow rules set, the default is permissive.
func (p *NetPolicy) Allowed(ip net.IP, port int) bool {
	if p == nil {
		return true
	}
	for _, r := range p.denies {
		if ruleMatches(r, ip, port) {
			return false
		}
	}
	if len(p.allows) == 0 {
		return true
	}
	for _, r := range p.allows {
		if ruleMatches(r, ip, port) {
			return true
		}
	}
	return false
}

// ─── Syscall handlers ────────────────────────────────────────────────

const (
	AF_INET  = 2
	AF_INET6 = 10

	SOCK_STREAM_MASK = 0xf // low 4 bits = type; SOCK_NONBLOCK/SOCK_CLOEXEC may be OR'd in

	SO_REUSEADDR = 2
	SO_KEEPALIVE = 9
	SO_SNDBUF    = 7
	SO_RCVBUF    = 8
	SO_ERROR     = 4

	IPPROTO_TCP = 6
	TCP_NODELAY = 1
)

// sysSocket — socket(domain, type, protocol). We only promise TCP over
// IPv4/IPv6; everything else gets EAFNOSUPPORT so the guest doesn't
// silently get a virtual fd it can't use.
func (s *Sentry) sysSocket(_ int, sc SyscallArgs) uint64 {
	domain := int(sc.Args[0])
	typ := int(sc.Args[1])

	if domain != AF_INET && domain != AF_INET6 {
		return errno(syscall.EAFNOSUPPORT)
	}
	// Mask off SOCK_CLOEXEC / SOCK_NONBLOCK; we only care about the base type.
	if typ&SOCK_STREAM_MASK != syscall.SOCK_STREAM {
		return errno(syscall.EPROTONOSUPPORT)
	}

	fd := s.nextFD
	s.nextFD++
	s.fdTable[fd] = &OpenFile{
		path:       "socket",
		isSocket:   true,
		sockFamily: domain,
	}
	return uint64(fd)
}

// parseSockaddr extracts (IP, port) from a sockaddr_in or sockaddr_in6
// sitting in the guest's address space. Only AF_INET / AF_INET6 are
// accepted; anything else returns EAFNOSUPPORT.
func parseSockaddr(pid int, addr uint64, addrlen uint64) (net.IP, int, syscall.Errno) {
	if addr == 0 || addrlen < 8 {
		return nil, 0, syscall.EINVAL
	}
	if addrlen > 128 {
		addrlen = 128
	}
	buf := readFromChild(pid, addr, addrlen)
	if len(buf) < 8 {
		return nil, 0, syscall.EFAULT
	}
	family := binary.LittleEndian.Uint16(buf[0:2])
	switch family {
	case AF_INET:
		if len(buf) < 8 {
			return nil, 0, syscall.EINVAL
		}
		port := int(binary.BigEndian.Uint16(buf[2:4]))
		ip := net.IPv4(buf[4], buf[5], buf[6], buf[7])
		return ip, port, 0
	case AF_INET6:
		if len(buf) < 28 {
			return nil, 0, syscall.EINVAL
		}
		port := int(binary.BigEndian.Uint16(buf[2:4]))
		ip := make(net.IP, 16)
		copy(ip, buf[8:24])
		return ip, port, 0
	default:
		return nil, 0, syscall.EAFNOSUPPORT
	}
}

// encodeSockaddr packs an IP:port into the kernel sockaddr_in/6 layout
// so getpeername/getsockname can hand the guest something parseable.
func encodeSockaddr(ip net.IP, port int) []byte {
	if v4 := ip.To4(); v4 != nil {
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint16(buf[0:2], AF_INET)
		binary.BigEndian.PutUint16(buf[2:4], uint16(port))
		copy(buf[4:8], v4)
		return buf
	}
	buf := make([]byte, 28)
	binary.LittleEndian.PutUint16(buf[0:2], AF_INET6)
	binary.BigEndian.PutUint16(buf[2:4], uint16(port))
	copy(buf[8:24], ip.To16())
	return buf
}

// sysConnect — connect(fd, addr, addrlen). The sentry reads the target
// sockaddr, checks the policy, and if allowed dials the real connection
// itself. The net.Conn is stashed on the OpenFile so subsequent
// read/write/send/recv can use it without touching the host.
func (s *Sentry) sysConnect(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	addr := sc.Args[1]
	addrlen := sc.Args[2]

	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	if !f.isSocket {
		return errno(syscall.ENOTSOCK)
	}
	if f.conn != nil {
		return errno(syscall.EISCONN)
	}

	ip, port, eno := parseSockaddr(pid, addr, addrlen)
	if eno != 0 {
		return errno(eno)
	}

	if !s.netPolicy.Allowed(ip, port) {
		fmt.Fprintf(logWriter(), "  [sentry] connect(%s:%d) → EACCES (policy)\n", ip, port)
		return errno(syscall.EACCES)
	}

	dest := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	// Dial with a modest timeout so a slow/unreachable host doesn't hang
	// the whole sandbox forever.
	s.mu.Unlock()
	conn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	s.mu.Lock()
	if err != nil {
		fmt.Fprintf(logWriter(), "  [sentry] connect(%s) → ECONNREFUSED (%v)\n", dest, err)
		return errno(syscall.ECONNREFUSED)
	}

	// fdTable can mutate while we drop the lock for the dial; re-fetch.
	f, ok = s.fdTable[fd]
	if !ok || !f.isSocket {
		conn.Close()
		return errno(syscall.EBADF)
	}
	f.conn = conn
	f.remoteIP = ip
	f.remotePort = port
	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		f.localIP = la.IP
		f.localPort = la.Port
	}
	fmt.Fprintf(logWriter(), "  [sentry] connect fd=%d → %s ok\n", fd, dest)
	return 0
}

// sysSendto — for stream sockets we already have a connected conn, so
// the addr argument is ignored (this matches Linux kernel behaviour:
// sendto on a connected TCP socket writes to the peer regardless).
func (s *Sentry) sysSendto(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	buf := sc.Args[1]
	count := sc.Args[2]

	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	if !f.isSocket {
		return errno(syscall.ENOTSOCK)
	}
	if f.conn == nil {
		return errno(syscall.ENOTCONN)
	}
	if count == 0 {
		return 0
	}
	if count > maxTransfer {
		count = maxTransfer
	}
	data := readFromChild(pid, buf, count)
	s.mu.Unlock()
	n, err := f.conn.Write(data)
	s.mu.Lock()
	if err != nil {
		if n > 0 {
			return uint64(n)
		}
		return errno(syscall.EPIPE)
	}
	return uint64(n)
}

// sysRecvfrom — on a connected stream socket this is just a read from
// the peer. If the guest supplied a non-null addr, we fill it with the
// peer address so recvfrom-with-addr code paths keep working.
func (s *Sentry) sysRecvfrom(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	buf := sc.Args[1]
	count := sc.Args[2]
	addrPtr := sc.Args[4]
	addrLenPtr := sc.Args[5]

	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	if !f.isSocket {
		return errno(syscall.ENOTSOCK)
	}
	if f.conn == nil {
		return errno(syscall.ENOTCONN)
	}
	if count == 0 {
		return 0
	}
	if count > maxTransfer {
		count = maxTransfer
	}
	tmp := make([]byte, count)
	s.mu.Unlock()
	n, err := f.conn.Read(tmp)
	s.mu.Lock()
	if n > 0 {
		writeToChild(pid, buf, tmp[:n])
		if addrPtr != 0 && addrLenPtr != 0 {
			writePeerAddr(pid, addrPtr, addrLenPtr, f.remoteIP, f.remotePort)
		}
		return uint64(n)
	}
	if err != nil {
		return 0 // EOF / peer closed
	}
	return 0
}

func writePeerAddr(pid int, addrPtr, addrLenPtr uint64, ip net.IP, port int) {
	sa := encodeSockaddr(ip, port)
	// Respect the guest-provided addrlen cap: it passes the buffer size
	// in on entry and expects us to write back the real size.
	capBuf := readFromChild(pid, addrLenPtr, 4)
	cap32 := uint32(len(sa))
	if len(capBuf) == 4 {
		guestCap := binary.LittleEndian.Uint32(capBuf)
		if guestCap < cap32 {
			cap32 = guestCap
		}
	}
	if cap32 > 0 {
		writeToChild(pid, addrPtr, sa[:cap32])
	}
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], uint32(len(sa)))
	writeToChild(pid, addrLenPtr, out[:])
}

// sysGetpeername / sysGetsockname — return the endpoint the real
// net.Conn is bound to. Not-yet-connected sockets get ENOTCONN.
func (s *Sentry) sysGetpeername(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	if !f.isSocket {
		return errno(syscall.ENOTSOCK)
	}
	if f.conn == nil {
		return errno(syscall.ENOTCONN)
	}
	writePeerAddr(pid, sc.Args[1], sc.Args[2], f.remoteIP, f.remotePort)
	return 0
}

func (s *Sentry) sysGetsockname(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	if !f.isSocket {
		return errno(syscall.ENOTSOCK)
	}
	if f.conn == nil {
		// Unconnected — report 0.0.0.0:0 to keep glibc probes happy.
		writePeerAddr(pid, sc.Args[1], sc.Args[2], net.IPv4zero, 0)
		return 0
	}
	writePeerAddr(pid, sc.Args[1], sc.Args[2], f.localIP, f.localPort)
	return 0
}

// sysSetsockopt — quietly accept the handful of options real clients
// set on freshly-opened sockets, reject everything else. We're not a
// real stack, but we shouldn't break programs that blindly call
// setsockopt(SO_REUSEADDR, 1) before connect().
func (s *Sentry) sysSetsockopt(_ int, sc SyscallArgs) uint64 {
	level := int(sc.Args[1])
	optname := int(sc.Args[2])
	if level == syscall.SOL_SOCKET {
		switch optname {
		case SO_REUSEADDR, SO_KEEPALIVE, SO_SNDBUF, SO_RCVBUF:
			return 0
		}
	}
	if level == IPPROTO_TCP && optname == TCP_NODELAY {
		return 0
	}
	return errno(syscall.ENOPROTOOPT)
}

func (s *Sentry) sysGetsockopt(pid int, sc SyscallArgs) uint64 {
	level := int(sc.Args[1])
	optname := int(sc.Args[2])
	optval := sc.Args[3]
	optlen := sc.Args[4]

	writeZero := func() {
		if optval == 0 || optlen == 0 {
			return
		}
		lenBuf := readFromChild(pid, optlen, 4)
		var sz uint32 = 4
		if len(lenBuf) == 4 {
			if l := binary.LittleEndian.Uint32(lenBuf); l < sz {
				sz = l
			}
		}
		zero := make([]byte, sz)
		writeToChild(pid, optval, zero)
		var out [4]byte
		binary.LittleEndian.PutUint32(out[:], sz)
		writeToChild(pid, optlen, out[:])
	}

	if level == syscall.SOL_SOCKET {
		switch optname {
		case SO_REUSEADDR, SO_KEEPALIVE, SO_SNDBUF, SO_RCVBUF, SO_ERROR:
			writeZero()
			return 0
		}
	}
	if level == IPPROTO_TCP && optname == TCP_NODELAY {
		writeZero()
		return 0
	}
	return errno(syscall.ENOPROTOOPT)
}
