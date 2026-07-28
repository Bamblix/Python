#!/usr/bin/env python3
"""Gdzie te creds dzialaja. Wyniki lecą na ekran od razu, nie na koncu.

  ./nxcwhere.py 10.13.38.0/24 -u Kathryn.Spencer -p Chocolate1
  ./nxcwhere.py 10.13.38.49 -u jdoe -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d intercept.vl
  ./nxcwhere.py dc01.intercept.vl -u jdoe -p 'Pass!' -d intercept.vl -k --kdc dc01.intercept.vl
"""
import argparse
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

PROTOCOLS = ["smb", "ldap", "mssql", "winrm", "rdp", "ssh"]

ANSI = re.compile(r"\x1b\[[0-9;]*m")
HIT = re.compile(r"^(?P<proto>[A-Z0-9]+)\s+(?P<ip>\S+)\s+\d+\s+(?P<name>\S+)\s+"
                 r"\[\+\]\s*(?P<msg>.*)$")

TTY = sys.stdout.isatty()
G, R, Y, D, O = ("\033[1;32m", "\033[1;31m", "\033[33m", "\033[90m", "\033[0m") if TTY \
                else ("", "", "", "", "")


def parse_args():
    p = argparse.ArgumentParser(description="gdzie dzialaja creds")
    p.add_argument("target", help="IP / CIDR / FQDN / plik z hostami")
    p.add_argument("-u", "--user", required=True)
    p.add_argument("-p", "--password", default="")
    p.add_argument("-H", "--hash", default="")
    p.add_argument("-d", "--domain", default="")
    p.add_argument("-k", "--kerberos", action="store_true")
    p.add_argument("--kcache", action="store_true", help="bilet z KRB5CCNAME")
    p.add_argument("--kdc", default="", help="FQDN kontrolera domeny")
    p.add_argument("--aes", default="")
    p.add_argument("--nxc-timeout", default="15", help="timeout nxc na watek")
    p.add_argument("--timeout", type=int, default=600, help="limit na jedno sprawdzenie")
    return p.parse_args()


def auth_args(a, local):
    args = ["-u", a.user]
    if a.aes:
        args += ["--aesKey", a.aes]
    elif a.hash:
        args += ["-H", a.hash]
    elif not a.kcache:
        args += ["-p", a.password]

    if local:
        args.append("--local-auth")
    elif a.domain:
        args += ["-d", a.domain]

    if a.kerberos:
        args.append("-k")
    if a.kcache:
        args.append("--use-kcache")
    if a.kdc:
        args += ["--kdcHost", a.kdc]
    return args


def run(a, proto, local):
    cmd = ["nxc", proto, a.target] + auth_args(a, local) + \
          ["--no-progress", "--timeout", a.nxc_timeout]
    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=a.timeout)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        out = ""
    except FileNotFoundError:
        raise SystemExit("brak 'nxc' w PATH")

    rows = []
    for line in ANSI.sub("", out).splitlines():
        if m := HIT.match(line.strip()):
            rows.append((m["ip"], m["name"], proto.upper(),
                         "local" if local else "domain", m["msg"].strip()))
    return rows, time.monotonic() - t0


def ipkey(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def main():
    a = parse_args()
    krb = a.kerberos or a.kcache
    modes = (False,) if krb else (False, True)
    jobs = [(p, loc) for p in PROTOCOLS for loc in modes]
    if krb and re.match(r"^\d+\.\d+\.\d+\.\d+", a.target):
        print(f"{Y}[!] Kerberos wymaga FQDN, nie IP{O}")

    print(f"{a.user} @ {a.target}  |  {len(jobs)} sprawdzen\n")
    all_hits, done = [], 0

    with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        futs = {ex.submit(run, a, p, loc): (p, loc) for p, loc in jobs}
        for fut in as_completed(futs):
            proto, loc = futs[fut]
            mode = "local" if loc else "domain"
            rows, took = fut.result()
            done += 1
            all_hits += rows

            real = [r for r in rows if "(Guest)" not in r[4]]
            for ip, name, pr, md, msg in sorted(real, key=lambda r: ipkey(r[0])):
                admin = f"  {R}<-- ADMIN{O}" if "Pwn3d!" in msg else ""
                print(f"  {G}v{O} {ip:<16}{name:<16}{pr:<7}{md:<8}{msg}{admin}")
            tag = f"{len(real)} trafien" if real else "nic"
            print(f"{D}[{done}/{len(jobs)}] {proto.upper()} ({mode}) - {tag}, "
                  f"{took:.0f}s{O}")

    real = sorted({h for h in all_hits if "(Guest)" not in h[4]},
                  key=lambda r: (ipkey(r[0]), r[2]))
    guest = sorted({h for h in all_hits if "(Guest)" in h[4]}, key=lambda r: ipkey(r[0]))

    print()
    if not real:
        print("Nigdzie sie nie autentykuje.")
    else:
        print(f"{'IP':<16}{'HOST':<16}{'PROTO':<7}{'TRYB':<8}KONTEKST")
        print("-" * 72)
        for ip, name, pr, md, msg in real:
            admin = f"  {R}<-- ADMIN{O}" if "Pwn3d!" in msg else ""
            ctx = msg.split(":")[0]
            print(f"{G}{ip:<16}{O}{name:<16}{pr:<7}{md:<8}{ctx}{admin}")

    if guest:
        print(f"\n{Y}[!] zmapowane na Guest - to NIE jest udane logowanie:{O}")
        for ip, name, pr, md, _ in guest:
            print(f"{D}    {ip:<16}{name:<16}{pr:<7}{md}{O}")


if __name__ == "__main__":
    main()
