#!/usr/bin/env python3
"""Make the Windows SCA auditpol rules independent of the OS display language.

The shipped CIS policies check audit settings with

    c:auditpol.exe /get /subcategory:"Logon" -> r:Success and Failure

which only works on an English Windows: subcategory names and the output text are
localized (Italian: "Accesso" / "Esito positivo e negativo"), so every audit check fails
elsewhere. A few names ("PNP Activity", "Audit Other Object Access Events") are not valid
auditpol names even in English.

This script rewrites only the COMMAND part of those rules. The command now:
  1. runs `auditpol /backup` to a temp CSV (columns are localized, but the subcategory GUID
     and the last column "Setting Value" 0/1/2/3 are language independent),
  2. picks the row by subcategory GUID,
  3. prints the English text the original regex expects
     (0 No Auditing, 1 Success, 2 Failure, 3 Success and Failure).
The `-> r:...` part is left untouched, so the check semantics do not change.

Usage:
  sca_localize_auditpol_rules.py <policy.yml|dir> [...]           dry run
  sca_localize_auditpol_rules.py --write <policy.yml|dir> [...]   rewrite in place
Idempotent: already converted rules are skipped. Line endings are preserved.
Re-run after every sync of the upstream policies.
"""
import argparse
import re
import sys
from pathlib import Path

# English subcategory name (as used by the CIS/Wazuh policies) -> GUID
GUIDS = {
    "Security State Change": "0CCE9210", "Security System Extension": "0CCE9211",
    "System Integrity": "0CCE9212", "IPsec Driver": "0CCE9213",
    "Other System Events": "0CCE9214", "Logon": "0CCE9215", "Logoff": "0CCE9216",
    "Account Lockout": "0CCE9217", "IPsec Main Mode": "0CCE9218",
    "IPsec Quick Mode": "0CCE9219", "IPsec Extended Mode": "0CCE921A",
    "Special Logon": "0CCE921B", "Other Logon/Logoff Events": "0CCE921C",
    "File System": "0CCE921D", "Registry": "0CCE921E", "Kernel Object": "0CCE921F",
    "SAM": "0CCE9220", "Certification Services": "0CCE9221",
    "Application Generated": "0CCE9222", "Handle Manipulation": "0CCE9223",
    "File Share": "0CCE9224", "Filtering Platform Packet Drop": "0CCE9225",
    "Filtering Platform Connection": "0CCE9226",
    "Other Object Access Events": "0CCE9227",
    "Audit Other Object Access Events": "0CCE9227",  # CIS spelling
    "Sensitive Privilege Use": "0CCE9228", "Non Sensitive Privilege Use": "0CCE9229",
    "Other Privilege Use Events": "0CCE922A", "Process Creation": "0CCE922B",
    "Process Termination": "0CCE922C", "DPAPI Activity": "0CCE922D",
    "RPC Events": "0CCE922E", "Audit Policy Change": "0CCE922F",
    "Authentication Policy Change": "0CCE9230",
    "Authorization Policy Change": "0CCE9231",
    "MPSSVC Rule-Level Policy Change": "0CCE9232",
    "Filtering Platform Policy Change": "0CCE9233",
    "Other Policy Change Events": "0CCE9234", "User Account Management": "0CCE9235",
    "Computer Account Management": "0CCE9236", "Security Group Management": "0CCE9237",
    "Distribution Group Management": "0CCE9238",
    "Application Group Management": "0CCE9239",
    "Other Account Management Events": "0CCE923A",
    "Directory Service Access": "0CCE923B", "Directory Service Changes": "0CCE923C",
    "Directory Service Replication": "0CCE923D",
    "Detailed Directory Service Replication": "0CCE923E",
    "Credential Validation": "0CCE923F",
    "Kerberos Service Ticket Operations": "0CCE9240",
    "Other Account Logon Events": "0CCE9241",
    "Kerberos Authentication Service": "0CCE9242",
    "Network Policy Server": "0CCE9243", "Detailed File Share": "0CCE9244",
    "Removable Storage": "0CCE9245", "Central Policy Staging": "0CCE9246",
    "User / Device Claims": "0CCE9247",
    "Plug and Play Events": "0CCE9248", "PNP Activity": "0CCE9248",  # CIS spelling
    "Group Membership": "0CCE9249", "Token Right Adjusted Events": "0CCE924A",
}

OLD = re.compile(
    r"""^(?P<indent>\s*-\s*)'c:auditpol(?:\.exe)?\s+/get\s+/subcategory:"(?P<name>[^"]+)"\s+->\s+(?P<rest>r:[^']*)'(?P<eol>\r?\n?)$"""
)

# YAML single-quoted scalar: every literal ' is doubled.
PS_TEMPLATE = (
    "$f=Join-Path $env:TEMP ('sca_ap_'+[guid]::NewGuid().ToString('N')+'.csv'); "
    "auditpol /backup /file:$f | Out-Null; "
    "$l=Select-String -Path $f -SimpleMatch '{guid}' | Select-Object -First 1; "
    "Remove-Item $f -Force -ErrorAction SilentlyContinue; "
    "if($l){{$v=$l.Line.Split(',')[-1].Trim(); "
    "@{{'0'='No Auditing';'1'='Success';'2'='Failure';'3'='Success and Failure'}}[$v]}}"
)


def new_rule(indent: str, guid: str, rest: str, eol: str) -> str:
    ps = PS_TEMPLATE.format(guid="{" + guid + "-69AE-11D9-BED3-505054503030}")
    cmd = 'powershell -NoProfile -Command "' + ps + '"'
    return f"{indent}'c:{cmd.replace(chr(39), chr(39) * 2)} -> {rest}'{eol}"


def convert(path: Path, write: bool):
    raw = path.read_bytes().decode("utf-8")
    out, changed, done, unmapped = [], 0, 0, set()
    for line in raw.splitlines(keepends=True):
        m = OLD.match(line)
        if not m:
            if "c:powershell" in line and "auditpol /backup" in line:
                done += 1
            out.append(line)
            continue
        guid = GUIDS.get(m["name"])
        if guid is None:
            unmapped.add(m["name"])
            out.append(line)
            continue
        out.append(new_rule(m["indent"], guid, m["rest"], m["eol"]))
        changed += 1
    if write and changed:
        path.write_bytes("".join(out).encode("utf-8"))
    return changed, done, unmapped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="rewrite files in place (default: dry run)")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()
    files = []
    for p in map(Path, args.paths):
        files += sorted(p.glob("*.yml")) if p.is_dir() else [p]
    rc = 0
    for f in files:
        changed, done, unmapped = convert(f, args.write)
        print(f"{f.name}: {'rewrote' if args.write else 'would rewrite'} {changed}, already converted {done}"
              + (f", UNMAPPED {sorted(unmapped)}" if unmapped else ""))
        rc |= bool(unmapped)
    return rc


if __name__ == "__main__":
    sys.exit(main())
