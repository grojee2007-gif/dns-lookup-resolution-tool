# DNS Lookup and Resolution Tool

Iterative DNS resolver written from scratch in Python 3 (standard library only).
Computer Networks PBL, Batch 4: G.Rojee (24R11A62B2), L.Krushini (24R11A62C2)
Geethanjali College of Engineering and Technology, CSE-Cyber Security

## Features
- Builds and parses DNS packets itself (name compression, A, AAAA, NS, CNAME, SOA, PTR, MX, TXT)
- Iterative resolution: root -> TLD -> authoritative server, with step-by-step trace
- Handles CNAME chains, delegations without glue, NXDOMAIN and NODATA
- UDP with automatic TCP retry for truncated answers
- TTL cache, delegation cache and failover when a name server is dead
- Ignores forged replies (wrong ID or source) and unrelated glue records

## Files
- dnslib_min.py - DNS message codec
- dnstool.py - resolver and command-line tool
- mockdns.py - simulated root, TLD and authoritative servers (for testing)
- demo.py - runs 9 tests and prints ALL CHECKS PASSED

## Run
python demo.py

Windows: if port 5353 is blocked, set PORT = 15353 in mockdns.py.
Tests use a simulated DNS hierarchy on loopback (127.0.0.2 - 127.0.0.4), not the live Internet.