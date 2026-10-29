import socket, struct, sys, time

SOCKS = ("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 18190)
DNS = ("1.1.1.1", 53)

tcp = socket.create_connection(SOCKS, timeout=10)
tcp.sendall(b"\x05\x01\x00")
assert tcp.recv(2) == b"\x05\x00", "socks auth negotiation failed"
tcp.sendall(b"\x05\x03\x00\x01" + b"\x00" * 4 + b"\x00\x00")
r = tcp.recv(32)
print("associate reply:", r.hex())
assert r[1] == 0, "UDP ASSOCIATE rejected rep=%d" % r[1]
atyp = r[3]
relay = (socket.inet_ntoa(r[4:8]), struct.unpack(">H", r[8:10])[0])
if relay[0] == "0.0.0.0":
    relay = (SOCKS[0], relay[1])
print("relay:", relay)

q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(8)
hdr = b"\x00\x00\x00\x01" + socket.inet_aton(DNS[0]) + struct.pack(">H", DNS[1])
t = time.time()
u.sendto(hdr + q, relay)
d, a = u.recvfrom(4096)
print("reply from", a, "in %.0f ms" % ((time.time() - t) * 1000), "len", len(d))
assert d[:3] == b"\x00\x00\x00" and d[3] == 1
payload = d[10:]
assert payload[:2] == b"\x12\x34", "txid mismatch"
print("DNS answers:", struct.unpack(">H", payload[6:8])[0], "ip tail:", socket.inet_ntoa(payload[-4:]))
print("UDP ASSOCIATE through Aether: OK")
