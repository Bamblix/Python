#!/usr/bin/env python3
"""Gdzie te creds dzialaja. Wyniki lecą na ekran od razu, nie na koncu.

  ./nxcwhere.py 10.13.38.0/24 -u Kathryn.Spencer -p Chocolate1
  ./nxcwhere.py 10.13.38.49 -u jdoe -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d intercept.vl
  ./nxcwhere.py dc01.intercept.vl -u jdoe -p 'Pass!' -d intercept.vl -k --kdc dc01.intercept.vl
"""
import argparse
import asyncio
import ipaddress
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

PROTOCOLS = ["smb", "ldap", "mssql", "winrm", "rdp", "ssh"]
PORTS = {"smb": 445, "ldap": 389, "mssql": 1433, "winrm": 5985, "rdp": 3389, "ssh": 22}

ANSI = re.compile(r"\x1b\[[0-9;]*m")
HIT = re.compile(r"^(?P<proto>[A-Z0-9]+)\s+(?P<ip>\S+)\s+\d+\s+(?P<name>\S+)\s+"
                 r"\[\+\]\s*(?P<msg>.*)$")

TTY = sys.stdout.isatty()
G, R, Y, D, O = ("\033[1;32m", "\033[1;31m", "\033[33m", "\033[90m", "\033[0m") if TTY \
                else ("", "", "", "", "")


def is_file(v):
    return bool(v) and Path(v).is_file()


def count_lines(v):
    return len([l for l in Path(v).read_text().splitlines() if l.strip()]) if is_file(v) else 1


def expand(target):
    """CIDR / plik / lista po przecinku / pojedynczy host -> lista hostow."""
    out = []
    for part in (x.strip() for x in target.split(",") if x.strip()):
        if Path(part).is_file():
            out += [l.strip() for l in Path(part).read_text().splitlines() if l.strip()]
        elif "/" in part:
            out += [str(i) for i in ipaddress.ip_network(part, strict=False).hosts()]
        else:
            out.append(part)
    return out


async def _scan(hosts, ports, timeout, conc):
    sem = asyncio.Semaphore(conc)

    async def one(h, prt):
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(h, prt), timeout)
                w.close()
                return h, prt
            except Exception:
                return None
    return [r for r in await asyncio.gather(*(one(h, p) for h in hosts for p in ports)) if r]


def prescan(a):
    """Zwraca {protokol: sciezka do pliku z zywymi hostami}."""
    hosts = expand(a.target)
    ports = sorted(set(PORTS.values()))
    t0 = time.monotonic()
    print(f"{D}[*] pre-skan: {len(hosts)} x {len(ports)} portow...{O}", flush=True)
    pairs = asyncio.run(_scan(hosts, ports, a.port_timeout, a.port_conc))

    by_port = {}
    for h, prt in pairs:
        by_port.setdefault(prt, []).append(h)

    tmp = Path(tempfile.mkdtemp(prefix="nxcwhere-"))
    live = {}
    for proto, prt in PORTS.items():
        hs = by_port.get(prt)
        if hs:
            f = tmp / f"{proto}.txt"
            f.write_text("\n".join(sorted(hs, key=ipkey)) + "\n")
            live[proto] = str(f)
    summary = "  ".join(f"{p.upper()}:{len(by_port.get(PORTS[p], []))}" for p in PROTOCOLS)
    print(f"{D}    {time.monotonic() - t0:.1f}s  {summary}{O}\n")
    return live


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
    p.add_argument("--nxc-threads", default="", help="nxc -t (przez VPN warto zejsc)")
    p.add_argument("--no-brute", action="store_true",
                   help="pary user:pass 1:1 zamiast kazdy z kazdym")
    p.add_argument("--fail-limit", default="", help="przerwij po N nieudanych logowaniach")
    p.add_argument("--jitter", default="", help="odstep miedzy probami, np. 2 albo 1-3")
    p.add_argument("--workers", type=int, default=0,
                   help="ile nxc naraz (przy sprayu domyslnie 1)")
    p.add_argument("--yes", action="store_true", help="nie pytaj przy sprayu")
    p.add_argument("--no-prescan", action="store_true", help="bez skanu portow")
    p.add_argument("--port-timeout", type=float, default=1.0)
    p.add_argument("--port-conc", type=int, default=500)
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

    # przy listach nxc domyslnie konczy na hoscie po pierwszym trafieniu
    if is_file(a.user) or is_file(a.password):
        args.append("--continue-on-success")
    if a.no_brute:
        args.append("--no-bruteforce")      # pary user:pass 1:1 zamiast iloczynu
    if a.fail_limit:
        args += ["--fail-limit", a.fail_limit]
    if a.jitter:
        args += ["--jitter", a.jitter]

    if a.kerberos:
        args.append("-k")
    if a.kcache:
        args.append("--use-kcache")
    if a.kdc:
        args += ["--kdcHost", a.kdc]
    return args


def run(a, proto, local):
    target = a.live.get(proto, a.target)
    cmd = ["nxc", proto, target] + auth_args(a, local) + \
          ["--no-progress", "--timeout", a.nxc_timeout] + \
          (["-t", a.nxc_threads] if a.nxc_threads else [])
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

    a.live = {} if a.no_prescan else prescan(a)
    if a.live:
        jobs = [(p, loc) for p, loc in jobs if p in a.live]
        dead = [p.upper() for p in PROTOCOLS if p not in a.live]
        if dead:
            print(f"{D}pomijam (port zamkniety wszedzie): {', '.join(dead)}{O}")
    if not jobs:
        raise SystemExit("Zaden port nie odpowiada.")

    spray = is_file(a.user) or is_file(a.password)
    workers = a.workers or (1 if spray else len(jobs))

    if spray:
        nu, np_ = count_lines(a.user), count_lines(a.password)
        nh = sum(1 for _ in Path(next(iter(a.live.values()))).read_text().splitlines()) \
            if a.live else len(expand(a.target))
        pairs = nu if a.no_brute else nu * np_
        total = pairs * nh * len(jobs)
        print(f"{Y}[!] SPRAY: {nu} userow x {np_} hasel"
              f"{' (pary 1:1)' if a.no_brute else ' (kazdy z kazdym)'}"
              f" x {nh} hostow x {len(jobs)} przebiegow{O}")
        print(f"{Y}    = do {total} prob logowania na konto/host{O}")
        print(f"{Y}    nieudane probe sumuja sie w badPwdCount niezaleznie od protokolu{O}")
        print(f"{D}    sprawdz najpierw: nxc smb <DC> -u '' -p '' --pass-pol{O}")
        print(f"{D}    workers={workers}, dodaj --fail-limit / --jitter zeby ograniczyc{O}")
        if not a.yes and sys.stdin.isatty():
            if input("    kontynuowac? [y/N] ").strip().lower() != "y":
                raise SystemExit("przerwane")
        print()

    t_start = time.monotonic()
    print(f"{a.user} @ {a.target}  |  {len(jobs)} sprawdzen\n")
    all_hits, done = [], 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
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

    print(f"\n{D}czas: {time.monotonic() - t_start:.1f}s{O}")
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
