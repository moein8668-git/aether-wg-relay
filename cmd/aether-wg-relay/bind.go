package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
)

// ---------- SOCKS5 UDP framing (RFC 1928 section 7) ----------

// encodeUDPHeader returns RSV(2)=0 FRAG=0 ATYP DST.ADDR DST.PORT for dst.
func encodeUDPHeader(dst netip.AddrPort) []byte {
	a := dst.Addr()
	var hdr []byte
	if a.Is4() || a.Is4In6() {
		a4 := a.Unmap().As4()
		hdr = append([]byte{0, 0, 0, 1}, a4[:]...)
	} else {
		a16 := a.As16()
		hdr = append([]byte{0, 0, 0, 4}, a16[:]...)
	}
	return binary.BigEndian.AppendUint16(hdr, dst.Port())
}

// decodeUDPDatagram parses a datagram received from the SOCKS relay. Fragmented
// datagrams, domain-name sources and anything malformed are rejected.
func decodeUDPDatagram(buf []byte) (src netip.AddrPort, payload []byte, ok bool) {
	if len(buf) < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
		return netip.AddrPort{}, nil, false
	}
	switch buf[3] {
	case 1:
		a, _ := netip.AddrFromSlice(buf[4:8])
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(buf[8:10])), buf[10:], true
	case 4:
		if len(buf) < 22 {
			return netip.AddrPort{}, nil, false
		}
		a, _ := netip.AddrFromSlice(buf[4:20])
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(buf[20:22])), buf[22:], true
	}
	return netip.AddrPort{}, nil, false
}

// socksAssociate opens the TCP control connection, negotiates "no auth" and
// requests UDP ASSOCIATE. It returns the control connection and a UDP socket
// connected to the relay address. The association lives only while tcp is open.
func socksAssociate(socksAddr string) (net.Conn, *net.UDPConn, error) {
	t, err := net.DialTimeout("tcp", socksAddr, 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	fail := func(e error) (net.Conn, *net.UDPConn, error) { t.Close(); return nil, nil, e }
	t.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = t.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	r := make([]byte, 2)
	if _, err = io.ReadFull(t, r); err != nil || r[0] != 5 || r[1] != 0 {
		return fail(fmt.Errorf("socks auth: %v %v", r, err))
	}
	if _, err = t.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	h := make([]byte, 10)
	if _, err = io.ReadFull(t, h); err != nil || h[0] != 5 || h[1] != 0 || h[3] != 1 {
		return fail(fmt.Errorf("udp associate failed: %v %v", h, err))
	}
	t.SetDeadline(time.Time{})
	relayIP := net.IPv4(h[4], h[5], h[6], h[7])
	if relayIP.IsUnspecified() {
		// relay is on the SOCKS host itself
		if ta, ok := t.RemoteAddr().(*net.TCPAddr); ok {
			relayIP = ta.IP
		} else {
			relayIP = net.ParseIP("127.0.0.1")
		}
	}
	relay := &net.UDPAddr{IP: relayIP, Port: int(binary.BigEndian.Uint16(h[8:10]))}
	u, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, relay)
	if err != nil {
		return fail(err)
	}
	return t, u, nil
}

// ---------- Bind with automatic re-association ----------

// socksBind is a WireGuard conn.Bind whose only transport is a SOCKS5 UDP
// association. If the association is lost (Aether restarted or died) packets are
// dropped while a supervisor re-associates with backoff. It never sends
// directly to the peer.
type socksBind struct {
	socksAddr string

	// onRestore, if set, runs after the association is re-established so the WireGuard
	// peer can resume immediately instead of waiting for its next timer.
	onRestore func()
	firstUp   chan struct{} // closed on the first successful association
	firstOnce sync.Once

	mu   sync.Mutex
	udp  *net.UDPConn // nil while the association is down
	tcp  net.Conn
	stop chan struct{}
	wg   sync.WaitGroup

	TxPkts     atomic.Uint64
	RxPkts     atomic.Uint64
	Dropped    atomic.Uint64
	Reconnects atomic.Uint64
}

func (b *socksBind) current() *net.UDPConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.udp
}

func (b *socksBind) setAssoc(t net.Conn, u *net.UDPConn) {
	b.mu.Lock()
	b.tcp, b.udp = t, u
	b.mu.Unlock()
}

func (b *socksBind) clearAssoc() {
	b.mu.Lock()
	u, t := b.udp, b.tcp
	b.udp, b.tcp = nil, nil
	b.mu.Unlock()
	if u != nil {
		u.Close()
	}
	if t != nil {
		t.Close()
	}
}

func sleepOrStop(stop <-chan struct{}, d time.Duration) bool {
	select {
	case <-stop:
		return false
	case <-time.After(d):
		return true
	}
}

func (b *socksBind) supervise(stop <-chan struct{}) {
	defer b.wg.Done()
	backoff := time.Second
	first := true
	for {
		select {
		case <-stop:
			return
		default:
		}
		t, u, err := socksAssociate(b.socksAddr)
		if err != nil {
			log.Printf("[bind] SOCKS association failed (%v); retrying in %s, WG packets are dropped meanwhile", err, backoff)
			if !sleepOrStop(stop, backoff) {
				return
			}
			if backoff < 5*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		b.setAssoc(t, u)
		b.firstOnce.Do(func() { close(b.firstUp) })
		if first {
			log.Printf("[bind] SOCKS5 UDP association up, relay=%s", u.RemoteAddr())
			first = false
		} else {
			b.Reconnects.Add(1)
			log.Printf("[bind] SOCKS5 UDP association restored, relay=%s", u.RemoteAddr())
			if b.onRestore != nil {
				go b.onRestore()
			}
		}
		lost := make(chan struct{})
		go func() { io.Copy(io.Discard, t); close(lost) }()
		select {
		case <-stop:
			b.clearAssoc()
			return
		case <-lost:
		}
		select {
		case <-stop:
			b.clearAssoc()
			return
		default:
		}
		log.Printf("[bind] SOCKS control connection lost; association gone, dropping WG packets (no direct fallback)")
		b.clearAssoc()
		if !sleepOrStop(stop, time.Second) {
			return
		}
	}
}

func (b *socksBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.stop != nil {
		b.mu.Unlock()
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	stop := make(chan struct{})
	b.stop = stop
	b.mu.Unlock()
	b.firstUp = make(chan struct{})
	b.firstOnce = sync.Once{}
	b.wg.Add(1)
	go b.supervise(stop)
	// Give the first association a moment so WireGuard's initial handshake is not dropped.
	select {
	case <-b.firstUp:
	case <-time.After(3 * time.Second):
	}

	recv := func(pkts [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		buf := make([]byte, 4096)
		for {
			select {
			case <-stop:
				return 0, net.ErrClosed
			default:
			}
			u := b.current()
			if u == nil {
				if !sleepOrStop(stop, 100*time.Millisecond) {
					return 0, net.ErrClosed
				}
				continue
			}
			n, err := u.Read(buf)
			if err != nil {
				// socket closed by the supervisor (association lost) or by Close
				if !sleepOrStop(stop, 50*time.Millisecond) {
					return 0, net.ErrClosed
				}
				continue
			}
			src, payload, ok := decodeUDPDatagram(buf[:n])
			if !ok {
				continue
			}
			b.RxPkts.Add(1)
			sizes[0] = copy(pkts[0], payload)
			eps[0] = &conn.StdNetEndpoint{AddrPort: src}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{recv}, 0, nil
}

func (b *socksBind) Close() error {
	b.mu.Lock()
	stop := b.stop
	b.stop = nil
	b.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	b.clearAssoc()
	b.wg.Wait()
	return nil
}

func (b *socksBind) SetMark(uint32) error { return nil }
func (b *socksBind) BatchSize() int       { return 1 }

func (b *socksBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

var errAssocDown = errors.New("socks udp association down (packet dropped, no direct fallback)")

func (b *socksBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	u := b.current()
	if u == nil {
		b.Dropped.Add(uint64(len(bufs)))
		return errAssocDown
	}
	se, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	hdr := encodeUDPHeader(se.AddrPort)
	for _, p := range bufs {
		if _, err := u.Write(append(append([]byte{}, hdr...), p...)); err != nil {
			b.Dropped.Add(1)
			return err
		}
		b.TxPkts.Add(1)
	}
	return nil
}
