package main

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
)

func TestEncodeDecodeV4(t *testing.T) {
	dst := netip.MustParseAddrPort("89.39.107.113:51820")
	h := encodeUDPHeader(dst)
	want := []byte{0, 0, 0, 1, 89, 39, 107, 113, 0xca, 0x6c}
	if string(h) != string(want) {
		t.Fatalf("header %v want %v", h, want)
	}
	src, pl, ok := decodeUDPDatagram(append(h, []byte("hello")...))
	if !ok || src != dst || string(pl) != "hello" {
		t.Fatalf("decode got %v %q %v", src, pl, ok)
	}
}

func TestEncodeDecodeV6(t *testing.T) {
	dst := netip.MustParseAddrPort("[2a00:7c80:0:3ad::10]:51820")
	h := encodeUDPHeader(dst)
	if len(h) != 22 || h[3] != 4 {
		t.Fatalf("bad v6 header %v", h)
	}
	src, pl, ok := decodeUDPDatagram(append(h, 1, 2, 3))
	if !ok || src != dst || len(pl) != 3 {
		t.Fatalf("decode got %v %v %v", src, pl, ok)
	}
}

func TestDecodeRejects(t *testing.T) {
	good := append(encodeUDPHeader(netip.MustParseAddrPort("1.2.3.4:5")), 9)
	cases := map[string][]byte{
		"short":    {0, 0, 0, 1, 1, 2},
		"frag":     append([]byte{0, 0, 1}, good[3:]...),
		"rsv":      append([]byte{0, 1}, good[2:]...),
		"domain":   append([]byte{0, 0, 0, 3, 1, 'a', 0, 80}, make([]byte, 8)...),
		"v6 short": {0, 0, 0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}
	for name, c := range cases {
		if _, _, ok := decodeUDPDatagram(c); ok {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, ok := decodeUDPDatagram(good); !ok {
		t.Fatal("good rejected")
	}
}

// fakeSocks is a minimal SOCKS5 server supporting UDP ASSOCIATE. Each accepted
// control connection gets its own UDP relay socket that forwards received
// payloads (with the destination header) to got.
type fakeSocks struct {
	l    net.Listener
	got  chan []byte
	ctrl chan net.Conn
}

func newFakeSocks(t *testing.T, addr string) *fakeSocks {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSocks{l: l, got: make(chan []byte, 16), ctrl: make(chan net.Conn, 4)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSocks) serve(c net.Conn) {
	b := make([]byte, 3)
	if _, err := io.ReadFull(c, b); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	req := make([]byte, 10)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return
	}
	port := u.LocalAddr().(*net.UDPAddr).Port
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	f.ctrl <- c
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			f.got <- append([]byte{}, buf[:n]...)
			// echo back as if from the destination
			u.WriteToUDP(append(encodeUDPHeader(netip.MustParseAddrPort("9.9.9.9:53")), "pong"...), from)
		}
	}()
	io.Copy(io.Discard, c)
	u.Close()
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestReconnectAfterControlLoss(t *testing.T) {
	fs := newFakeSocks(t, "127.0.0.1:0")
	defer fs.l.Close()
	b := &socksBind{socksAddr: fs.l.Addr().String()}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ep, _ := b.ParseEndpoint("89.39.107.113:51820")

	waitFor(t, "association", func() bool { return b.current() != nil })
	if err := b.Send([][]byte{[]byte("one")}, ep); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-fs.got:
		src, pl, ok := decodeUDPDatagram(p)
		if !ok || src.String() != "89.39.107.113:51820" || string(pl) != "one" {
			t.Fatalf("relay got %v %q", src, pl)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not receive first datagram")
	}
	pkts, sizes, eps := [][]byte{make([]byte, 2000)}, make([]int, 1), make([]conn.Endpoint, 1)
	if n, err := fns[0](pkts, sizes, eps); err != nil || n != 1 || string(pkts[0][:sizes[0]]) != "pong" {
		t.Fatalf("recv n=%d err=%v %q", n, err, pkts[0][:sizes[0]])
	}

	// kill the control connection: association must be dropped, sends fail closed
	(<-fs.ctrl).Close()
	waitFor(t, "association down", func() bool { return b.current() == nil })
	if err := b.Send([][]byte{[]byte("lost")}, ep); err == nil {
		t.Fatal("send succeeded without an association")
	}
	if b.Dropped.Load() == 0 {
		t.Fatal("drop not counted")
	}

	// supervisor re-associates and traffic flows again
	waitFor(t, "re-association", func() bool { return b.current() != nil && b.Reconnects.Load() == 1 })
	if err := b.Send([][]byte{[]byte("two")}, ep); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-fs.got:
		if _, pl, _ := decodeUDPDatagram(p); string(pl) != "two" {
			t.Fatalf("relay got %q after reconnect", pl)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no datagram after reconnect")
	}
}

func TestStartsBeforeSocksAndRecovers(t *testing.T) {
	// reserve a port, leave it closed, start the bind, then bring SOCKS up
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	b := &socksBind{socksAddr: addr}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ep, _ := b.ParseEndpoint("1.2.3.4:5")
	if err := b.Send([][]byte{[]byte("x")}, ep); err == nil {
		t.Fatal("send must fail while no SOCKS server is reachable")
	}
	fs := newFakeSocks(t, addr)
	defer fs.l.Close()
	waitFor(t, "association after late SOCKS start", func() bool { return b.current() != nil })
}

func TestCloseStopsReceiveAndAllowsReopen(t *testing.T) {
	fs := newFakeSocks(t, "127.0.0.1:0")
	defer fs.l.Close()
	b := &socksBind{socksAddr: fs.l.Addr().String()}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := fns[0]([][]byte{make([]byte, 100)}, make([]int, 1), make([]conn.Endpoint, 1))
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	b.Close()
	select {
	case err := <-done:
		if err != net.ErrClosed {
			t.Fatalf("recv err = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receive func did not stop on Close")
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	b.Close()
}
