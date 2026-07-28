#!/usr/bin/env python3
"""Gdzie te creds dzialaja. Nic wiecej.

  ./nxcwhere.py 10.13.38.0/24 -u Kathryn.Spencer -p Chocolate1
  ./nxcwhere.py hosts.txt -u jdoe -H 31d6cfe0d16ae931b73c59d7e0c089c0
"""
import argparse
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

PROTOCOLS = ["smb", "ldap", "mssql", "winrm", "wmi", "rdp", "ssh", "ftp", "nfs", "vnc"]

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# PROTO  host  port  NAME  [+] domain\user:password (Pwn3d!)
HIT = re.compile(r"^(?P<proto>[A-Z0-9]+)\s+(?P<ip>\S+)\s+\d+\s+(?P<name>\S+)\s+"
                 r"\[\+\]\s*(?P<msg>.*)$")


def parse_args():
    p = argparse.ArgumentParser(description="gdzie dzialaja creds")
    p.add_argument("target", help="IP / CIDR / FQDN / plik z hostami")
    p.add_argument("-u", "--user", required=True)
    p.add_argument("-p", "--password", default="")
    p.add_argument("-H", "--hash", default="")
    p.add_argument("-d", "--domain", default="")
    p.add_argument("-k", "--kerberos", action="store_true", help="auth Kerberos")
    p.add_argument("--kcache", action="store_true", help="uzyj biletu z KRB5CCNAME")
    p.add_argument("--kdc", default="", help="FQDN kontrolera domeny")
    p.add_argument("--aes", default="", help="klucz AES zamiast hasla/hasha")
    p.add_argument("--timeout", type=int, default=300)
    return p.parse_args()


def auth_args(a, local):
    args = ["-u", a.user]
    if a.aes:
        args += ["--aesKey", a.aes]
    elif a.hash:
        args += ["-H", a.hash]
    else:
        args += ["-p", a.password]

    if local:
        args.append("--local-auth")          # excludes itself with -d
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
          ["--no-progress", "--timeout", "15"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=a.timeout)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        out = ""
    except FileNotFoundError:
        raise SystemExit("brak 'nxc' w PATH")

    rows = []
    for line in ANSI.sub("", out).splitlines():
        m = HIT.match(line.strip())
        if m:
            rows.append((m["ip"], m["name"], proto.upper(),
                         "local" if local else "domain", m["msg"].strip()))
    return rows


def ipkey(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def main():
    a = parse_args()
    krb = a.kerberos or a.kcache
    modes = (False,) if krb else (False, True)   # local-auth + Kerberos = contradiction
    jobs = [(p, loc) for p in PROTOCOLS for loc in modes]
    if krb and re.match(r"^\d+\.\d+\.\d+\.\d+", a.target):
        print("[!] Kerberos wymaga FQDN, nie IP - SPN buduje sie z nazwy hosta")
    print(f"[*] {a.user} @ {a.target} - {len(jobs)} sprawdzen...\n")

    with ThreadPoolExecutor(max_workers=10) as ex:
        results = ex.map(lambda j: run(a, *j), jobs)
        hits = sorted({r for rows in results for r in rows},
                      key=lambda r: (ipkey(r[0]), r[2]))

    real = [h for h in hits if "(Guest)" not in h[4]]
    guest = [h for h in hits if "(Guest)" in h[4]]

    if not real:
        print("Nigdzie sie nie autentykuje.")
    else:
        print(f"{'IP':<16}{'HOST':<18}{'PROTO':<8}{'TRYB':<9}KONTEKST")
        print("-" * 78)
        for ip, name, proto, mode, msg in real:
            admin = "  <-- ADMIN" if "Pwn3d!" in msg else ""
            ctx = msg.split(":")[0] if "\\" in msg else msg.split()[0]
            print(f"{ip:<16}{name:<18}{proto:<8}{mode:<9}{ctx}{admin}")

    if guest:
        print(f"\n[!] zmapowane na Guest (to NIE jest udane logowanie):")
        for ip, name, proto, mode, _ in guest:
            print(f"    {ip:<16}{name:<18}{proto:<8}{mode}")


if __name__ == "__main__":
    main()
