// aether-wg-relay: userspace WireGuard (amneziawg-go with all obfuscation off = standard WG)
// whose UDP transport is a SOCKS5 UDP ASSOCIATE session to Aether. Exposes the inner tunnel as a
// local SOCKS5 CONNECT proxy. There is NO direct-UDP path: if the association is lost, sends fail.
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// ---------- config ----------

func b64hex(s string) string {
	d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(d) != 32 {
		log.Fatalf("bad key")
	}
	return hex.EncodeToString(d)
}

type wgConf struct {
	priv, pub, psk, endpoint string
	addrs                    []netip.Addr
	dns                      []netip.Addr
	allowed                  []string
	keepalive                string
}

func parseConf(path string) wgConf {
	f, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var c wgConf
	for _, ln := range strings.Split(string(f), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == '#' || ln[0] == '[' {
			continue
		}
		kv := strings.SplitN(ln, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.ToLower(strings.TrimSpace(kv[0])), strings.TrimSpace(kv[1])
		switch k {
		case "privatekey":
			c.priv = b64hex(v)
		case "publickey":
			c.pub = b64hex(v)
		case "presharedkey":
			c.psk = b64hex(v)
		case "endpoint":
			c.endpoint = v
		case "persistentkeepalive":
			c.keepalive = v
		case "allowedips":
			for _, p := range strings.Split(v, ",") {
				c.allowed = append(c.allowed, strings.TrimSpace(p))
			}
		case "address":
			for _, p := range strings.Split(v, ",") {
				pf, err := netip.ParsePrefix(strings.TrimSpace(p))
				if err == nil {
					c.addrs = append(c.addrs, pf.Addr())
				}
			}
		case "dns":
			for _, p := range strings.Split(v, ",") {
				if a, err := netip.ParseAddr(strings.TrimSpace(p)); err == nil {
					c.dns = append(c.dns, a)
				}
			}
		case "postup", "postdown", "preup", "predown":
			log.Fatalf("refusing %s in imported config", k)
		}
	}
	return c
}

// ---------- local SOCKS5 CONNECT server (exits via inner tunnel) ----------

func serveSocks(l net.Listener, tnet *netstack.Net) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(15 * time.Second))
			h := make([]byte, 2)
			if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 {
				return
			}
			io.CopyN(io.Discard, c, int64(h[1]))
			c.Write([]byte{5, 0})
			q := make([]byte, 4)
			if _, err := io.ReadFull(c, q); err != nil || q[1] != 1 {
				return
			}
			var host string
			switch q[3] {
			case 1:
				a := make([]byte, 4)
				io.ReadFull(c, a)
				host = net.IP(a).String()
			case 4:
				a := make([]byte, 16)
				io.ReadFull(c, a)
				host = net.IP(a).String()
			case 3:
				l := make([]byte, 1)
				io.ReadFull(c, l)
				d := make([]byte, l[0])
				io.ReadFull(c, d)
				host = string(d)
			default:
				return
			}
			pb := make([]byte, 2)
			io.ReadFull(c, pb)
			port := binary.BigEndian.Uint16(pb)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			up, err := tnet.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
			if err != nil {
				log.Printf("[socks] dial %s:%d failed: %v", host, port, err)
				c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			defer up.Close()
			c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			c.SetDeadline(time.Time{})
			done := make(chan struct{}, 2)
			go func() { io.Copy(up, c); done <- struct{}{} }()
			go func() { io.Copy(c, up); done <- struct{}{} }()
			<-done
		}(c)
	}
}

// version is set at build time: -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

func main() {
	confPath := flag.String("conf", "", "WireGuard .conf (original, not modified)")
	aetherSocks := flag.String("aether", "127.0.0.1:18190", "Aether SOCKS5 address")
	listen := flag.String("listen", "127.0.0.1:1817", "local SOCKS5 listen address (exit = inner WG)")
	mtu := flag.Int("mtu", 1160, "inner tunnel MTU")
	verbose := flag.Bool("v", false, "verbose wireguard logs")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("aether-wg-relay", version)
		return
	}
	if *confPath == "" {
		log.Fatal("-conf required")
	}
	c := parseConf(*confPath)
	// Aether's default is IPv4-only: query v4 resolvers first and only keep v6 ones if no v4 exists.
	var dns4 []netip.Addr
	for _, d := range c.dns {
		if d.Is4() {
			dns4 = append(dns4, d)
		}
	}
	if len(dns4) > 0 {
		c.dns = dns4
	}
	tdev, tnet, err := netstack.CreateNetTUN(c.addrs, c.dns, *mtu)
	if err != nil {
		log.Fatal(err)
	}
	bind := &socksBind{socksAddr: *aetherSocks}
	lvl := device.LogLevelError
	if *verbose {
		lvl = device.LogLevelVerbose
	}
	dev := device.NewDevice(tdev, bind, device.NewLogger(lvl, "(wg) "))
	ipc := "private_key=" + c.priv + "\npublic_key=" + c.pub + "\nendpoint=" + c.endpoint + "\n"
	if c.psk != "" {
		ipc += "preshared_key=" + c.psk + "\n"
	}
	if c.keepalive != "" {
		ipc += "persistent_keepalive_interval=" + c.keepalive + "\n"
	}
	for _, a := range c.allowed {
		ipc += "allowed_ip=" + a + "\n"
	}
	if err := dev.IpcSet(ipc); err != nil {
		log.Fatal(err)
	}
	if pk, err := hex.DecodeString(c.pub); err == nil && len(pk) == 32 {
		var npk device.NoisePublicKey
		copy(npk[:], pk)
		bind.onRestore = func() {
			if p := dev.LookupPeer(npk); p != nil {
				p.SendKeepalive() // starts a handshake if the session is stale
			}
		}
	}
	if err := dev.Up(); err != nil {
		log.Fatal(err)
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("inner WG via Aether SOCKS-UDP up; SOCKS5 exit proxy on %s (peer %s)", *listen, c.endpoint)
	go func() {
		for range time.Tick(5 * time.Second) {
			s, _ := dev.IpcGet()
			hs := ""
			for _, ln := range strings.Split(s, "\n") {
				if strings.HasPrefix(ln, "last_handshake_time_sec") || strings.HasPrefix(ln, "rx_bytes") || strings.HasPrefix(ln, "tx_bytes") {
					hs += ln + " "
				}
			}
			log.Printf("[stat] %s udp_tx=%d udp_rx=%d dropped=%d reconnects=%d", hs, bind.TxPkts.Load(), bind.RxPkts.Load(), bind.Dropped.Load(), bind.Reconnects.Load())
		}
	}()
	serveSocks(l, tnet)
}
