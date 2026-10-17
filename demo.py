import io, sys, time, contextlib, statistics, json
import dnstool
from dnstool import Resolver, fmt
from dnslib_min import RCODES
import mockdns

W = mockdns.build_world(); ROOT = ["127.0.0.2"]; P = mockdns.PORT
results = {}

def run(title, name, qtype="A", res=None, trace=True):
    res = res or Resolver(ROOT, P, timeout=0.4)
    for s in W.values(): s.log.clear()
    t0 = time.perf_counter(); r = res.resolve(name, qtype); ms = (time.perf_counter() - t0) * 1000
    out = [f"$ python dnstool.py {name} {qtype} --root 127.0.0.2 --port {P} --trace",
           f";; ITERATIVE RESOLUTION of {name if name.endswith('.') else name + '.'} ({qtype})"]
    out += [f"  [{i}] {l}" for i, l in enumerate(r.trace, 1)]
    out.append(f";; status: {RCODES.get(r.rcode, r.rcode)}")
    if r.answers: out.append(";; ANSWER SECTION"); out += [fmt(x) for x in r.answers]
    out.append(f";; Query time: {ms:.1f} ms | queries sent: {res.sent} | cache hits: {res.hits}")
    results[title] = dict(text="\n".join(out), r=r, res=res, ms=ms)
    print("\n".join(out)); print()
    return r, res

run("t1", "www.example.com", "A")
c2 = Resolver(ROOT, P, timeout=0.4)
L = [f"$ python dnstool.py example.com <TYPE> --root 127.0.0.2 --port {P}"]
for t in ["A", "AAAA", "MX", "TXT", "NS", "SOA"]:
    rr = c2.resolve("example.com", t)
    L.append(f";; example.com. {t:<5} -> {RCODES[rr.rcode]}, {len(rr.answers)} record(s)")
    L += ["   " + fmt(x) for x in rr.answers]
L.append(f";; total queries sent: {c2.sent} | cache hits: {c2.hits}")
results["t2"] = dict(text="\n".join(L), sent=c2.sent); print("\n".join(L)); print()
run("t3", "shop.demo.com", "A")
# caching: same resolver, second lookup
c = Resolver(ROOT, P, timeout=0.4)
for s in W.values(): s.log.clear()
t0 = time.perf_counter(); a = c.resolve("www.example.com", "A"); cold_ms = (time.perf_counter() - t0) * 1000; s1 = c.sent
h0 = c.hits; t0 = time.perf_counter(); tr2 = c.resolve("www.example.com", "A"); warm = (time.perf_counter() - t0) * 1000
T4 = [f"$ python dnstool.py www.example.com A    (first lookup, empty cache)",
      f";; Query time: {cold_ms:.1f} ms | queries sent: {s1} | cache hits: 0", "",
      f"$ python dnstool.py www.example.com A    (second lookup, same resolver)"]
T4 += [f"  [{i}] {l}" for i, l in enumerate(tr2.trace, 1)]
T4 += [";; ANSWER SECTION"] + [fmt(x) for x in tr2.answers]
T4.append(f";; Query time: {warm:.3f} ms | queries sent: {c.sent - s1} | cache hits: {c.hits - h0}")
results["t4"] = dict(text="\n".join(T4), cold_sent=s1, warm_sent=c.sent - s1, warm_ms=warm, cold_ms=cold_ms); print("\n".join(T4)); print()
run("t5", "nosuchhost.example.com", "A")
run("t6", "long.example.com", "TXT")
run("t7", "10.113.0.203.in-addr.arpa", "PTR")
W["tld"].evil = True
r, res = run("t8", "www.example.com", "A")
W["tld"].evil = False
results["t8b"] = dict(poison_in_cache=("6.6.6.6" in str(res.cache) + str(res.ns_cache)), dropped=res.stats.get("dropped", 0))
# performance
first = Resolver(ROOT, P, timeout=0.4); t0 = time.perf_counter(); first.resolve("cdn.example.com", "A"); first_ms = (time.perf_counter() - t0) * 1000
N = 200; cold, warm_l = [], []
for _ in range(N):
    first.cache.clear(); first.ns_cache.clear(); q0 = first.sent
    t0 = time.perf_counter(); first.resolve("cdn.example.com", "A"); cold.append((time.perf_counter() - t0) * 1000)
cold_q = first.sent - q0
for _ in range(N):
    t0 = time.perf_counter(); first.resolve("cdn.example.com", "A"); warm_l.append((time.perf_counter() - t0) * 1000)
results["perf"] = dict(first=first_ms, cold=statistics.mean(cold), warm=statistics.mean(warm_l), cold_q=cold_q, n=N)
print("PERF", results["perf"]); print("T4", results["t4"]); print("T8b", results["t8b"])
# ---- automatic pass/fail checks -------------------------------------------------
g = lambda k: results[k]["r"]
assert [a.type for a in g("t1").answers] == ["CNAME", "A"] and g("t1").answers[-1].data == "203.0.113.10"
assert results["t1"]["res"].sent == 5
assert results["t3"]["r"].rcode == 0 and len(g("t3").answers) == 3 and g("t3").answers[-1].data == "203.0.113.10"
assert results["t4"]["warm_sent"] == 0
assert g("t5").rcode == 3 and g("t5").answers == []
assert len(g("t6").answers) == 8 and "TCP retry" in "".join(g("t6").trace)
assert g("t7").answers[0].data == "www.example.com."
assert g("t8").answers[-1].data == "203.0.113.10" and not results["t8b"]["poison_in_cache"] and results["t8b"]["dropped"] >= 1
for t, n in {"A": 1, "AAAA": 1, "MX": 2, "TXT": 1, "NS": 1, "SOA": 1}.items(): assert len(c2.resolve("example.com", t).answers) == n
assert results["perf"]["warm"] < results["perf"]["cold"] < results["perf"]["first"]
print("ALL CHECKS PASSED")
import pickle
pickle.dump({k: ({kk: vv for kk, vv in v.items() if kk not in ("r", "res")}) for k, v in results.items()}, open("results.pkl", "wb"))
