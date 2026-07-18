#!/usr/bin/env bash
# #77 SEC77b — programmatic enforcement of the role trust boundary. The field roles
# (agent, central) must NOT modify the codebase; only the developer role may edit/write
# (the skills describe this, but prose is not a control — #77 gaps 1, 8).
#
# Wire this as a Claude Code **PreToolUse hook** in the LOCAL `.claude/settings.json`
# (which is machine-specific and untracked — see the note in each role SKILL.md), e.g.:
#
#   "hooks": { "PreToolUse": [ { "matcher": "Edit|Write|MultiEdit|NotebookEdit|Bash",
#     "hooks": [ { "type": "command", "command": "scripts/role-guard.sh" } ] } ] }
#
# The active role is signalled by the CT_ROLE env var (developer|agent|central), set at
# skill launch. The hook reads the tool call as JSON on stdin; **exit 2 = BLOCK the tool**,
# exit 0 = allow. So a field role's Edit/Write — and Bash that writes files or mutates git
# (the `> file` / `tee` / `sed -i` bypass) — is denied by a shim, not by prompt compliance.
set -euo pipefail

if [ "${1:-}" = "--selftest" ]; then
  check() { # $1=role  $2=tool-call-json  $3=expected exit (0 allow / 2 block)
    CT_ROLE="$1" bash "$0" <<<"$2" >/dev/null 2>&1 && rc=0 || rc=$?
    [ "$rc" = "$3" ] || { echo "SELFTEST FAIL: role=$1 json=$2 got=$rc want=$3" >&2; exit 1; }
  }
  check agent     '{"tool_name":"Edit","tool_input":{}}'                        2
  check agent     '{"tool_name":"Write","tool_input":{}}'                       2
  check central   '{"tool_name":"MultiEdit","tool_input":{}}'                   2
  check central   '{"tool_name":"Bash","tool_input":{"command":"echo x > f"}}'  2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"sed -i s/a/b/ f"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"git commit -m x"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"ls -la && grep x f"}}' 0
  check agent     '{"tool_name":"Read","tool_input":{}}'                        0
  check developer '{"tool_name":"Edit","tool_input":{}}'                        0
  check developer '{"tool_name":"Bash","tool_input":{"command":"echo x > f"}}'  0
  echo "SELFTEST OK: field-role writes blocked; developer + read-only allowed"
  exit 0
fi

role="${CT_ROLE:-developer}"
# Only the field roles are restricted; developer (or an unset role) may edit.
case "$role" in
  agent | central) ;;
  *) exit 0 ;;
esac

CT_GUARD_INPUT="$(cat)" CT_ROLE="$role" python3 -c '
import os, sys, json, re
role = os.environ["CT_ROLE"]
try:
    data = json.loads(os.environ.get("CT_GUARD_INPUT") or "{}")
except Exception:
    data = {}
tool = data.get("tool_name", "")
ti = data.get("tool_input", {}) or {}

def block(msg):
    sys.stderr.write("CT_ROLE=%s: %s — field roles cannot modify the codebase (#77 SEC77b)\n" % (role, msg))
    sys.exit(2)

if tool in {"Edit", "Write", "MultiEdit", "NotebookEdit"}:
    block(tool + " denied")
if tool == "Bash":
    cmd = ti.get("command", "") or ""
    # Reject shell that writes files or mutates git — the ways Bash bypasses the Edit/Write deny.
    if re.search(r">>?(?![>&])|\btee\b|\bsed\b[^|]*-i|\bdd\b|\btruncate\b|\bcp\b|\bmv\b|\brm\b|git\s+(add|commit|apply|checkout|restore|reset|push|rm|mv)", cmd):
        block("Bash command writes files or mutates git")
sys.exit(0)
'
