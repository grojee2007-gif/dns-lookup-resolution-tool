"""Minimal DNS wire-format helpers: build and parse DNS messages (RFC 1035)."""
import struct, socket
from collections import namedtuple

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
RR = namedtuple("RR", "name type ttl data")
Message = namedtuple("Message", "id flags rcode aa tc qname qtype answers authority additional")


def fqdn(name):
    name = name.strip().lower()
    return name if name.endswith(".") else name + "."


class Packer:
    """Builds a message and compresses repeated names with pointers (RFC 1035 4.1.4)."""
    def __init__(self):
        self.buf = bytearray()
        self.seen = {}

    def name(self, name):
        labels = [l for l in fqdn(name).split(".") if l]
        while labels:
            key = ".".join(labels)
            if key in self.seen:
                self.buf += struct.pack(">H", 0xC000 | self.seen[key]); return
            if len(self.buf) < 0x3FFF:
                self.seen[key] = len(self.buf)
            lab = labels.pop(0).encode()
            self.buf += bytes([len(lab)]) + lab
        self.buf += b"\x00"

    def rr(self, r):
        self.name(r.name)
        self.buf += struct.pack(">HHI", TYPES[r.type], 1, r.ttl)
        lenpos = len(self.buf); self.buf += b"\x00\x00"
        d = r.data
        if r.type == "A": self.buf += socket.inet_aton(d)
        elif r.type == "AAAA": self.buf += socket.inet_pton(socket.AF_INET6, d)
        elif r.type in ("NS", "CNAME", "PTR"): self.name(d)
        elif r.type == "MX": self.buf += struct.pack(">H", d[0]); self.name(d[1])
        elif r.type == "TXT":
            for s in d:
                b = s.encode(); self.buf += bytes([len(b)]) + b
        elif r.type == "SOA":
            self.name(d[0]); self.name(d[1]); self.buf += struct.pack(">IIIII", *d[2:])
        struct.pack_into(">H", self.buf, lenpos, len(self.buf) - lenpos - 2)


def build_query(qname, qtype, qid, rd=False):
    p = Packer()
    p.buf += struct.pack(">HHHHHH", qid, 0x0100 if rd else 0, 1, 0, 0, 0)
    p.name(qname); p.buf += struct.pack(">HH", TYPES[qtype], 1)
    return bytes(p.buf)


def build_response(qid, qname, qtype, rcode, answers=(), authority=(), additional=(), aa=False, tc=False):
    p = Packer()
    flags = 0x8000 | (0x0400 if aa else 0) | (0x0200 if tc else 0) | rcode
    p.buf += struct.pack(">HHHHHH", qid, flags, 1, len(answers), len(authority), len(additional))
    p.name(qname); p.buf += struct.pack(">HH", TYPES[qtype], 1)
    for sec in (answers, authority, additional):
        for r in sec: p.rr(r)
    return bytes(p.buf)


def read_name(msg, off):
    labels, jumped, end, hops = [], False, off, 0
    while True:
        n = msg[off]
        if n & 0xC0 == 0xC0:                       # compression pointer
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            if not jumped: end = off + 2
            jumped, off, hops = True, ptr, hops + 1
            if hops > 20: raise ValueError("compression loop")
        elif n == 0:
            if not jumped: end = off + 1
            return (".".join(labels) + ".").lower() if labels else ".", end
        else:
            labels.append(msg[off + 1:off + 1 + n].decode()); off += 1 + n


def read_rr(msg, off):
    name, off = read_name(msg, off)
    t, _, ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10]); off += 10
    end, tn = off + rdlen, TYPE_NAMES.get(t)
    if tn == "A": data = socket.inet_ntoa(msg[off:end])
    elif tn == "AAAA": data = socket.inet_ntop(socket.AF_INET6, msg[off:end])
    elif tn in ("NS", "CNAME", "PTR"): data = read_name(msg, off)[0]
    elif tn == "MX": data = (struct.unpack(">H", msg[off:off + 2])[0], read_name(msg, off + 2)[0])
    elif tn == "TXT":
        data, i = [], off
        while i < end: data.append(msg[i + 1:i + 1 + msg[i]].decode()); i += 1 + msg[i]
    elif tn == "SOA":
        m, o = read_name(msg, off); r, o = read_name(msg, o)
        data = (m, r) + struct.unpack(">IIIII", msg[o:o + 20])
    else: data = msg[off:end]
    return RR(name, tn or str(t), ttl, data), end


def parse(msg):
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
    off, qname, qtype = 12, ".", "?"
    for _ in range(qd):
        qname, off = read_name(msg, off)
        qtype = TYPE_NAMES.get(struct.unpack(">H", msg[off:off + 2])[0], "?"); off += 4
    secs = []
    for count in (an, ns, ar):
        sec = []
        for _ in range(count):
            r, off = read_rr(msg, off); sec.append(r)
        secs.append(sec)
    return Message(qid, flags, flags & 0xF, bool(flags & 0x0400), bool(flags & 0x0200), qname, qtype, *secs)
