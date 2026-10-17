"""Coverage-only checks. --installed executes ONLY the hash-pinned vmrun no-arg help.

No VM operation, credential, config, log, network mutation or user directory scan.
This script is not a credentialed CLI backend for the broker.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
VMRUN = Path(r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")
VIX = VMRUN.with_name("vix.dll")
VMCLI = VMRUN.with_name("vmcli.exe")
VIX_HASH = "F2C5A2686EF8004AF4FEA1477E6CD68801B504B2B0B5EE2D286A681FB4E5727C"


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # Unknown support arguments might themselves contain a pasted secret.
        raise ValueError("invalid_support_arguments")


def commands(text):
    return re.findall(r"^([A-Za-z][A-Za-z0-9]+)\s{2,}\S", text.split("Examples:")[0], re.M)


def verify_help(text, entries):
    names = commands(text)
    expected = [row["name"] for row in entries]
    if len(names) != len(set(names)) or set(names) != set(expected):
        raise ValueError("catalog_command_drift")


def exports(data):
    pe = struct.unpack_from("<I", data, 60)[0]
    machine, nsec = struct.unpack_from("<HH", data, pe + 4)
    opt = pe + 24
    if machine != 0x14C or struct.unpack_from("<H", data, opt)[0] != 0x10B:
        raise ValueError("architecture_drift")
    size = struct.unpack_from("<H", data, pe + 20)[0]
    sections = [struct.unpack_from("<8sIIIIIIHHI", data, opt + size + i * 40) for i in range(nsec)]

    def offset(rva):
        return next(rva - s[2] + s[4] for s in sections if s[2] <= rva < s[2] + max(s[1], s[3]))

    directory = offset(struct.unpack_from("<I", data, opt + 96)[0])
    count = struct.unpack_from("<I", data, directory + 24)[0]
    table = offset(struct.unpack_from("<I", data, directory + 32)[0])
    return {
        data[offset(struct.unpack_from("<I", data, table + i * 4)[0]):].split(b"\0", 1)[0].decode("ascii")
        for i in range(count)
    }


def main():
    parser = SafeParser(description=__doc__)
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args()
    document = json.loads((ROOT / "vmrun-coverage.json").read_text(encoding="utf-8"))
    entries = document["commands"]
    expected = [row["name"] for row in entries]
    if document.get("schema") != 1 or len(expected) != 47 or len(expected) != len(set(expected)):
        raise ValueError("catalog_invalid")
    if args.installed:
        if hashlib.sha256(VMRUN.read_bytes()).hexdigest().upper() != document["installedSha256"]:
            raise ValueError("unreviewed_vmrun_binary")
        if hashlib.sha256(VMCLI.read_bytes()).hexdigest().upper() != document["vmcliSha256"]:
            raise ValueError("unreviewed_vmcli_binary")
        # Installed help is public; never execute any VM command or pass auth flags.
        reply = subprocess.run([str(VMRUN)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15, check=False)
        if len(reply.stdout) > 65536:
            raise ValueError("help_output_limit")
        verify_help(reply.stdout.decode("utf-8", errors="strict"), entries)
        data = VIX.read_bytes()
        if hashlib.sha256(data).hexdigest().upper() != VIX_HASH:
            raise ValueError("unreviewed_vix_binary")
        symbols = exports(data)
        for entry in entries:
            if entry["backend"] in ("native-vix", "native-vix-helper"):
                if not set(entry["exports"].split(",")).issubset(symbols):
                    raise ValueError("required_export_missing")
        print("PASS: installed help matches 47 commands; vmrun/vmcli pins match; required native exports present (static evidence, NOT live operations).")
    else:
        print("PASS: frozen 47-command catalog and added-command drift regression.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("FAIL: catalog/help/export drift or support check failed; no raw diagnostics emitted.", file=sys.stderr)
        sys.exit(1)
