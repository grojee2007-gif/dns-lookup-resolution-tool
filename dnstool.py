"""DNS Lookup and Resolution Tool: iterative resolver with cache, TCP fallback and failover."""
import socket, struct, time, secrets, argparse, sys
from dnslib_min import *

ROOT_SERVERS = ["198.41.0.4", "193.0.14.129", "199.7.83.42", "192.5.5.241"]  # a, k, l, f root servers


def ask(ip, port, qname, qtype, timeout=1.0, rd=False, stats=None):
    """Send one query over UDP (TCP if truncated). Returns a parsed Message or raises."""
    qid = secrets.randbelow(65536)
    pkt = build_query(qname, qtype, qid, rd)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    deadline = time.time() + timeout
    try:
        s.sendto(pkt, (ip, port))
        while True:                                   # keep waiting until a *valid* reply arrives
            s.settimeout(max(0.01, deadline - time.time()))
            data, src = s.recvfrom(4096)
            if src[0] != ip or len(data) < 12: continue            # wrong source: ignore
            m = parse(data)
            if m.id != qid or m.qname != fqdn(qname) or m.qtype != qtype:      # forged / stray reply
                if stats is not None: stats['dropped'] = stats.get('dropped', 0) + 1
                continue
            break
    finally:
        s.close()
    if m.tc:                                          # truncated: repeat over TCP
        t = socket.create_connection((ip, port), timeout=timeout)
        try:
            t.sendall(struct.pack(">H", len(pkt)) + pkt)
            n = struct.unpack(">H", t.recv(2))[0]; buf = b""
            while len(buf) < n: buf += t.recv(n - len(buf))
            m = parse(buf)
        finally:
            t.close()
        m = m._replace(tc=True)
    return m


class Result:
    def __init__(self, rcode, answers, trace): self.rcode, self.answers, self.trace = rcode, answers, trace


class Resolver:
    def __init__(self, roots=ROOT_SERVERS, port=53, timeout=1.0, max_steps=16):
        self.roots, self.port, self.timeout, self.max_steps = roots, port, timeout, max_steps
        self.cache, self.ns_cache = {}, {}
        self.sent = self.hits = 0
        self.stats, self.bad = {}, {}          # stats: dropped replies; bad: failed servers -> retry-after time

    # ---- cache helpers -------------------------------------------------
    def _get(self, name, qtype):
        e = self.cache.get((name, qtype))
        if e and e[0] > time.time(): return e
        return None

    def _put(self, name, qtype, rcode, rrs, ttl):
        self.cache[(name, qtype)] = (time.time() + ttl, rcode, rrs)

    def _servers_for(self, name):
        labels = name.rstrip(".").split(".")
        for i in range(len(labels)):
            zone = ".".join(labels[i:]) + "."
            e = self.ns_cache.get(zone)
            if e and e[0] > time.time(): return zone, e[1]
        return ".", list(self.roots)

    # ---- main entry ----------------------------------------------------
    def resolve(self, name, qtype="A", trace=None, depth=0):
        name = fqdn(name)
        trace = [] if trace is None else trace
        if depth > 8: return Result(2, [], trace)
        for t in (qtype, "CNAME"):
            e = self._get(name, t)
            if e:
                self.hits += 1
                trace.append(f"cache hit for {name} {t}")
                if e[1] != 0 or e[2] == []: return Result(e[1], list(e[2]), trace)
                if t == qtype: return Result(0, list(e[2]), trace)
                tail = self.resolve(e[2][0].data, qtype, trace, depth + 1)
                return Result(tail.rcode, list(e[2]) + tail.answers, trace)
        zone, servers = self._servers_for(name)
        for _ in range(self.max_steps):
            msg = None
            now = time.time()
            for ip in sorted(servers, key=lambda i: self.bad.get(i, 0) > now):     # known-bad servers last
                try:
                    self.sent += 1; d0 = self.stats.get('dropped', 0)
                    msg = ask(ip, self.port, name, qtype, self.timeout, stats=self.stats)
                    self.bad.pop(ip, None)
                    if self.stats.get('dropped', 0) > d0:
                        trace.append(f"ignored {self.stats['dropped'] - d0} forged/mismatched reply from {ip} (wrong ID)")
                    break
                except (OSError, ValueError, IndexError):
                    self.bad[ip] = time.time() + 60
                    trace.append(f"ask {ip} for {name} {qtype} -> no valid reply (timeout), marking server bad, trying next")
            if msg is None: return Result(2, [], trace)
            if msg.rcode == 3:
                ttl = min([r.data[6] for r in msg.authority if r.type == "SOA"] or [60])
                self._put(name, qtype, 3, [], ttl)
                trace.append(f"ask {ip} for {name} {qtype} -> NXDOMAIN (authoritative)")
                return Result(3, [], trace)
            if msg.rcode != 0:
                trace.append(f"ask {ip} for {name} {qtype} -> {RCODES.get(msg.rcode, msg.rcode)}")
                return Result(2, [], trace)
            ans = [r for r in msg.answers if r.name == name]
            cn = [r for r in ans if r.type == "CNAME"]
            direct = [r for r in ans if r.type == qtype]
            if direct:
                self._put(name, qtype, 0, direct, min(r.ttl for r in direct))
                tr = " + TCP retry" if msg.tc else ""
                trace.append(f"ask {ip} for {name} {qtype} -> answer ({len(direct)} record(s)){tr}")
                return Result(0, direct, trace)
            if cn and qtype != "CNAME":
                self._put(name, "CNAME", 0, cn[:1], cn[0].ttl)
                trace.append(f"ask {ip} for {name} {qtype} -> CNAME to {cn[0].data}")
                tail = self.resolve(cn[0].data, qtype, trace, depth + 1)
                return Result(tail.rcode, cn[:1] + tail.answers, trace)
            ns = [r for r in msg.authority if r.type == "NS"]
            if msg.aa or not ns:                       # authoritative but empty: NODATA
                self._put(name, qtype, 0, [], 60)
                trace.append(f"ask {ip} for {name} {qtype} -> NODATA (name exists, no {qtype} record)")
                return Result(0, [], trace)
            new_zone = ns[0].name
            if not (name.endswith(new_zone) and len(new_zone) > len(zone)):
                trace.append(f"ask {ip} for {name} {qtype} -> bad referral to {new_zone}, ignored")
                return Result(2, [], trace)
            targets = {r.data for r in ns}
            glue = {r.name: r.data for r in msg.additional if r.type == "A" and r.name in targets}  # bailiwick filter
            ips = []
            for r in ns:
                if r.data in glue: ips.append(glue[r.data])
                else:
                    sub = self.resolve(r.data, "A", trace, depth + 1)
                    ips += [a.data for a in sub.answers if a.type == "A"]
            trace.append(f"ask {ip} for {name} {qtype} -> referral to {new_zone} ({', '.join(sorted(targets))}) servers {', '.join(ips)}")
            if not ips: return Result(2, [], trace)
            self.ns_cache[new_zone] = (time.time() + min(r.ttl for r in ns), ips)
            zone, servers = new_zone, ips
        return Result(2, [], trace)


def fmt(r):
    d = r.data
    if r.type == "MX": d = f"{d[0]} {d[1]}"
    elif r.type == "TXT": d = " ".join('"%s"' % (s if len(s) < 48 else s[:40] + "...(%d chars)" % len(s)) for s in d)
    elif r.type == "SOA": d = " ".join(map(str, d))
    return f"{r.name:<{max(24, len(r.name) + 1)}}{r.ttl:<7}IN  {r.type:<6}{d}"


def main():
    ap = argparse.ArgumentParser(description="DNS Lookup and Resolution Tool")
    ap.add_argument("name"); ap.add_argument("type", nargs="?", default="A")
    ap.add_argument("--root", action="append", help="root/start server (default: real root servers)")
    ap.add_argument("--port", type=int, default=53); ap.add_argument("--trace", action="store_true")
    a = ap.parse_args()
    res = Resolver(a.root or ROOT_SERVERS, a.port)
    t0 = time.time(); r = res.resolve(a.name, a.type.upper()); ms = (time.time() - t0) * 1000
    if a.trace:
        print(f";; ITERATIVE RESOLUTION of {fqdn(a.name)} ({a.type.upper()})")
        for i, line in enumerate(r.trace, 1): print(f"  [{i}] {line}")
    print(f";; status: {RCODES.get(r.rcode, r.rcode)}")
    if r.answers: print(";; ANSWER SECTION"); [print(fmt(x)) for x in r.answers]
    print(f";; Query time: {ms:.1f} ms | queries sent: {res.sent} | cache hits: {res.hits}")


if __name__ == "__main__":
    main()
