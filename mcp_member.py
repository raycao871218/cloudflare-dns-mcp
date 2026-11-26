import argparse
import hashlib
import json
import re
import secrets

parser = argparse.ArgumentParser(description="Generate an individual Cloudflare DNS MCP credential.")
parser.add_argument("member", help="Member name or work email.")
parser.add_argument("--role", choices=("read", "write", "admin"), default="read")
args = parser.parse_args()
if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,80}", args.member):
    parser.error("Use 1–80 letters, digits, dots, underscores, hyphens or @.")

token = secrets.token_urlsafe(32)
entry = {args.member: {"sha256": hashlib.sha256(token.encode()).hexdigest(), "role": args.role}}
print("Send this token privately to " + args.member + ":")
print(token)
print("\nMerge this entry into DNS_MCP_MEMBERS on the server:")
print(json.dumps(entry, separators=(",", ":")))
