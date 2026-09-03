#!/usr/bin/env bash
set -euo pipefail
umask 0077

readonly TARGET="/etc/tu1nz/adult-commercial-s10-2b-telegram.token"
readonly EXPECTED_USERNAME="wantmeseenbot"

fail() {
  printf 'S10_2B_SECRET_INSTALL_RED %s\n' "$1" >&2
  exit 2
}

[ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
[ "$#" -eq 0 ] || fail "USAGE"
[ -t 0 ] && [ -t 1 ] || fail "INTERACTIVE_TTY_REQUIRED"
[ -d /etc/tu1nz ] && [ ! -L /etc/tu1nz ] || fail "SECRET_DIRECTORY_UNSAFE"
[ ! -e "$TARGET" ] || fail "TARGET_ALREADY_EXISTS"

printf 'S10_2B_SECURE_TOKEN_PROMPT_READY\n'
IFS= read -r -s -p 'Dedicated Want Me Seen bot token: ' token
printf '\n'
case "$token" in
  [0-9]*:[A-Za-z0-9_-]*) ;;
  *) unset token; fail "TOKEN_FORMAT_INVALID" ;;
esac
[ "${#token}" -ge 38 ] && [ "${#token}" -le 113 ] || {
  unset token
  fail "TOKEN_FORMAT_INVALID"
}

temporary="$(mktemp /etc/tu1nz/.s10-2b-token.XXXXXX)"
cleanup() {
  unset token || true
  [ -z "${temporary:-}" ] || rm -f -- "$temporary"
}
trap cleanup EXIT
chown root:root "$temporary"
chmod 0600 "$temporary"
printf '%s\n' "$token" >"$temporary"
unset token

bot_id="$(/usr/bin/python3 - "$temporary" "$EXPECTED_USERNAME" <<'PY'
import json
import re
import sys
from pathlib import Path
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

token_path = Path(sys.argv[1])
expected_username = sys.argv[2]
token = token_path.read_text(encoding="ascii").strip()
if re.fullmatch(r"[0-9]{6,16}:[A-Za-z0-9_-]{30,96}", token) is None:
    raise SystemExit(2)

class RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise RuntimeError("redirect blocked")

try:
    opener = build_opener(ProxyHandler({}), RejectRedirect())
    request = Request(
        "https://api.telegram.org/bot" + token + "/getMe",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with opener.open(request, timeout=15) as response:
        body = response.read(1024 * 1024 + 1)
    payload = json.loads(body.decode("utf-8"))
except Exception:
    raise SystemExit(2)
result = payload.get("result") if payload.get("ok") is True else None
if not isinstance(result, dict):
    raise SystemExit(2)
bot_id = result.get("id")
checks = (
    isinstance(bot_id, int) and not isinstance(bot_id, bool),
    isinstance(result.get("username"), str)
    and result["username"].casefold() == expected_username.casefold(),
    result.get("first_name") == "Want Me Seen",
    result.get("can_join_groups") is False,
)
if not all(checks):
    raise SystemExit(2)
print(bot_id)
PY
)" || fail "BOT_IDENTITY_VALIDATION_FAILED"

case "$bot_id" in
  [1-9][0-9]*) ;;
  *) fail "BOT_IDENTITY_VALIDATION_FAILED" ;;
esac
install -o root -g root -m 0600 -- "$temporary" "$TARGET"
temporary=""
[ "$(stat -c '%a %U:%G %F %h' "$TARGET")" = "600 root:root regular file 1" ] \
  || fail "TARGET_METADATA_INVALID"
printf '{"ok":true,"safe_code":"S10_2B_TOKEN_INSTALLED","bot_id":%s}\n' "$bot_id"
