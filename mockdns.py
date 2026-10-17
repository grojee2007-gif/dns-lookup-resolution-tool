"""Simulated DNS hierarchy (root, TLD, authoritative servers) on loopback addresses for testing."""
import socket, struct, threading
from dnslib_min import *

PORT = 15353


class Zone:
    def __init__(self, origin):
        self.origin, self.rec, self.deleg = fqdn(origin), {}, {}
    def add(self, name, rtype, data, ttl=3600):
        self.rec.setdefault((fqdn(name), rtype), []).append(RR(fqdn(name), rtype, ttl, data))
    def delegate(self, name, nsname, ip=None, ttl=86400):
        self.deleg.setdefault(fqdn(name), []).append((fqdn(nsname), ip, ttl))
    def soa(self):
        return self.rec[(self.origin, "SOA")]


class MockServer:
    def __init__(self, ip, zones, label, evil=False):
        self.ip, self.zones, self.label, self.evil = ip, zones, label, evil
        self.log = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.udp.bind((ip, PORT))
        self.tcp = socket.socket(); self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((ip, PORT)); self.tcp.listen(5)
        threading.Thread(target=self._udp, daemon=True).start()
        threading.Thread(target=self._tcp, daemon=True).start()

    def answer(self, m):
        qn, qt = m.qname, m.qtype
        zone = max((z for z in self.zones if qn.endswith(z.origin)), key=lambda z: len(z.origin), default=None)
        if zone is None: return dict(rcode=5)
        labels = qn.rstrip(".").split(".")                      # look for a delegation cut above qname
        for i in range(len(labels)):
            n = ".".join(labels[i:]) + "."
            if n in zone.deleg and n != zone.origin:
                ns = [RR(n, "NS", t, h) for h, _, t in zone.deleg[n]]
                glue = [RR(h, "A", t, ip) for h, ip, t in zone.deleg[n] if ip]
                if self.evil: glue.append(RR("www.example.com.", "A", 300, "6.6.6.6"))   # unrelated (poison) record
                return dict(rcode=0, authority=ns, additional=glue)
        if (qn, "CNAME") in zone.rec and qt != "CNAME": return dict(rcode=0, answers=zone.rec[(qn, "CNAME")], aa=True)
        if (qn, qt) in zone.rec: return dict(rcode=0, answers=zone.rec[(qn, qt)], aa=True)
        exists = any(k[0] == qn for k in zone.rec)
        return dict(rcode=0 if exists else 3, authority=zone.soa(), aa=True)

    def reply(self, data, tcp=False):
        m = parse(data)
        self.log.append((m.qname, m.qtype))
        a = self.answer(m)
        wire = build_response(m.id, m.qname, m.qtype, a["rcode"], a.get("answers", ()), a.get("authority", ()),
                              a.get("additional", ()), a.get("aa", False))
        if not tcp and len(wire) > 512:                              # classic UDP limit -> TC bit
            wire = build_response(m.id, m.qname, m.qtype, a["rcode"], (), (), (), a.get("aa", False), tc=True)
        return m, wire

    def _udp(self):
        while True:
            data, src = self.udp.recvfrom(4096)
            m, wire = self.reply(data)
            if self.evil:                                            # off-path attacker guesses the wrong ID first
                forged = build_response((m.id + 1) % 65536, m.qname, m.qtype, 0,
                                        [RR(m.qname, "A", 300, "6.6.6.6")], aa=True)
                self.udp.sendto(forged, src)
            self.udp.sendto(wire, src)

    def _tcp(self):
        while True:
            c, _ = self.tcp.accept()
            try:
                n = struct.unpack(">H", c.recv(2))[0]; data = c.recv(n)
                _, wire = self.reply(data, tcp=True)
                c.sendall(struct.pack(">H", len(wire)) + wire)
            finally:
                c.close()


def build_world():
    SOA = lambda o, ns: ("ns1." + o, "admin." + o, 2026101201, 3600, 600, 86400, 300)
    root = Zone(".");  root.add(".", "SOA", ("a.root-servers.test.", "nstld.test.", 1, 1800, 900, 604800, 86400))
    root.delegate("com.", "a.gtld-servers.test.", "127.0.0.3"); root.delegate("arpa.", "a.gtld-servers.test.", "127.0.0.3")
    tld = Zone("com."); tld.add("com.", "SOA", SOA("com.", None))
    tld.delegate("example.com.", "ns0.example.com.", "127.0.0.9")      # dead server listed first
    tld.delegate("example.com.", "ns1.example.com.", "127.0.0.4")
    tld.delegate("demo.com.", "ns1.example.com.")                      # glueless delegation (out-of-zone NS name)
    arpa = Zone("arpa."); arpa.add("arpa.", "SOA", SOA("arpa.", None))
    arpa.delegate("113.0.203.in-addr.arpa.", "ns1.example.com.")
    ex = Zone("example.com."); ex.add("example.com.", "SOA", SOA("example.com.", None))
    for o in ("example.com.",): ex.add(o, "NS", "ns1.example.com.")
    ex.add("ns1.example.com.", "A", "127.0.0.4")
    ex.add("example.com.", "A", "203.0.113.10"); ex.add("example.com.", "AAAA", "2001:db8::10")
    ex.add("example.com.", "MX", (10, "mail.example.com.")); ex.add("example.com.", "MX", (20, "mail2.example.com."))
    ex.add("example.com.", "TXT", ["v=spf1 mx -all"]); ex.add("mail.example.com.", "A", "203.0.113.25")
    ex.add("web.example.com.", "A", "203.0.113.10")
    ex.add("www.example.com.", "CNAME", "web.example.com."); ex.add("cdn.example.com.", "CNAME", "www.example.com.")
    for i in range(8): ex.add("long.example.com.", "TXT", ["record-%d-" % i + "x" * 60])
    dm = Zone("demo.com."); dm.add("demo.com.", "SOA", SOA("demo.com.", None))
    dm.add("demo.com.", "A", "198.51.100.7"); dm.add("shop.demo.com.", "CNAME", "www.example.com.")
    rv = Zone("113.0.203.in-addr.arpa."); rv.add("113.0.203.in-addr.arpa.", "SOA", SOA("113.0.203.in-addr.arpa.", None))
    rv.add("10.113.0.203.in-addr.arpa.", "PTR", "www.example.com.")
    servers = dict(root=MockServer("127.0.0.2", [root], "root"), tld=MockServer("127.0.0.3", [tld, arpa], "tld"),
                   auth=MockServer("127.0.0.4", [ex, dm, rv], "auth"))
    return servers
