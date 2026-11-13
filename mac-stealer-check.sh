#!/bin/bash
#
# mac-stealer-check: read-only triage for macOS infostealer indicators.
# Targets the tradecraft of AMOS/Atomic, Poseidon, Cuckoo, Banshee and the
# "ClickFix" / fake-CAPTCHA campaigns that trick users into pasting commands.
#
# It never modifies, deletes, uploads or quarantines anything. It only reads
# and prints. A WARN is a lead to review, not proof of infection.
#
# License: MIT

set -u
export LC_ALL=C

VERSION="0.1.0"
DAYS=30          # look-back window for files and downloads
LOG_HOURS=24     # look-back window for the unified log
QUICK=0          # skip the slow unified-log query
COLOR=1; [ -t 1 ] || COLOR=0

usage() {
  cat <<EOF
mac-stealer-check $VERSION: read-only macOS infostealer triage

Usage: ./mac-stealer-check.sh [options]

  --days N        Look-back window for temp files and downloads (default $DAYS)
  --log-hours N   Look-back window for the unified log (default $LOG_HOURS)
  --quick         Skip the unified-log query (the slowest check)
  --no-color      Plain output (automatic when not writing to a terminal)
  -h, --help      Show this help
  -V, --version   Show version

Exit codes: 0 = no warnings, 1 = warnings to review, 2 = could not run.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --days)      DAYS="${2:?--days needs a number}"; shift ;;
    --log-hours) LOG_HOURS="${2:?--log-hours needs a number}"; shift ;;
    --quick)     QUICK=1 ;;
    --no-color)  COLOR=0 ;;
    -h|--help)   usage; exit 0 ;;
    -V|--version) echo "$VERSION"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[ "$(uname -s)" = "Darwin" ] || { echo "This tool only runs on macOS." >&2; exit 2; }
if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as your normal user, without sudo. It inspects your own account." >&2
  exit 2
fi

if [ "$COLOR" = 1 ]; then
  RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; BLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=""; YEL=""; GRN=""; BLD=""; DIM=""; RST=""
fi

WARNS=0
INFOS=0
section() { printf '\n%s== %s ==%s\n' "$BLD" "$1" "$RST"; }
warn()    { WARNS=$((WARNS + 1)); printf '  %s[WARN]%s %s\n' "$RED" "$RST" "$*"; }
info()    { INFOS=$((INFOS + 1)); printf '  %s[INFO]%s %s\n' "$YEL" "$RST" "$*"; }
ok()      { printf '  %s[ OK ]%s %s\n' "$GRN" "$RST" "$*"; }
note()    { printf '         %s%s%s\n' "$DIM" "$*" "$RST"; }
short()   { printf '%s' "$1" | tr '\n' ' ' | cut -c1-220; }

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

IP_URL='https?://([0-9]{1,3}\.){3}[0-9]{1,3}'

# One-liners stealer droppers use. Checked against shell history and scripts.
SUSPICIOUS_RE="(curl|wget)[^|;]*\\|[[:space:]]*(sudo[[:space:]]+)?(/bin/)?(ba|z)?sh|(ba|z)?sh[[:space:]]+-c[[:space:]].*(curl|wget)|base64[[:space:]]+(-d|-D|--decode)|osascript|eval[[:space:]]+\"?\\\$\\((curl|echo|base64)|xattr[[:space:]]+-[a-z]*[cdr]|spctl[[:space:]]+--(master|global)-disable|dscl[[:space:]].*-authonly|security[[:space:]]+(find-generic-password|find-internet-password|dump-keychain)|chmod[[:space:]]+\\+x[[:space:]]+/(private/)?tmp/|$IP_URL|[A-Za-z0-9+/]{100,}={0,2}"

# These stay WARN even when the URL belongs to a well-known installer.
STRONG_RE="base64[[:space:]]+(-d|-D|--decode)|osascript|dscl[[:space:]].*-authonly|security[[:space:]]+(find-generic-password|find-internet-password|dump-keychain)|spctl[[:space:]]+--(master|global)-disable|$IP_URL|[A-Za-z0-9+/]{100,}={0,2}"

# Running-process command lines (narrower: app args often contain long tokens).
PROC_RE="osascript|(curl|wget)[^|;]*\\|[[:space:]]*(ba|z)?sh|(ba|z)?sh[[:space:]]+-c[[:space:]].*(curl|wget)|base64[[:space:]]+(-d|-D|--decode)|$IP_URL|python[0-9.]*[[:space:]]+-c[[:space:]].*(base64|exec|urllib)|perl[[:space:]]+-e"

# Official install one-liners. curl|sh from these is downgraded to INFO.
# Extend this list in a pull request if you hit a false positive.
TRUSTED_INSTALLERS_RE='https://(raw\.githubusercontent\.com/(Homebrew|nvm-sh|ohmyzsh)/|brew\.sh|sh\.rustup\.rs|astral\.sh/|bun\.sh/|deno\.land/|ollama\.com/|claude\.ai/install|chatgpt\.com/codex/|antigravity\.google/|get\.pnpm\.io|install\.python-poetry\.org|opencode\.ai/install|fnm\.vercel\.app|tailscale\.com/install|get\.volta\.sh)'

# Unsigned binaries here are normal (compilers, package managers, simulators).
DEV_PATHS_RE='/(\.cargo|\.rustup|\.nvm|\.bun|\.deno|\.volta|\.pyenv|\.sdkman|\.local|\.npm|\.gradle|\.m2|\.docker|\.orbstack|\.vscode[^/]*|\.cursor[^/]*|go|node_modules|DerivedData|CoreSimulator|go-build[^/]*)/'

TEMP_PATHS_RE='^/(private/)?(tmp|var/tmp|var/folders)/|^/Users/Shared/'

# Remove loopback/LAN URLs and public DNS resolvers (curl --doh-url) so they
# don't trip the raw-IP rule.
strip_local_urls() {
  sed -E 's#https?://(127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|1\.1\.1\.1/|1\.0\.0\.1/|8\.8\.8\.8/|8\.8\.4\.4/|9\.9\.9\.9/)[^[:space:]]*##g'
}

matches() { printf '%s' "$1" | strip_local_urls | grep -qE "$2"; }

# Prints the first signing authority, or: adhoc | unsigned | unknown
signer() {
  local out
  out=$(codesign -dvv "$1" 2>&1)
  case "$out" in
    *"not signed at all"*) echo "unsigned" ;;
    *"Signature=adhoc"*)   echo "adhoc" ;;
    *Authority=*)          printf '%s\n' "$out" | sed -n 's/^Authority=//p' | head -1 ;;
    *)                     echo "unknown" ;;
  esac
}
is_untrusted_sig() { case "$1" in unsigned|adhoc|unknown) return 0 ;; esac; return 1; }

# /Applications/Foo.app/Contents/MacOS/Foo -> /Applications/Foo.app
app_root() { printf '%s\n' "$1" | sed -E 's#(\.app)/.*#\1#'; }

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

check_protections() {
  section "System protections"
  if spctl --status 2>/dev/null | grep -q "assessments enabled"; then
    ok "Gatekeeper is enabled"
  else
    warn "Gatekeeper is DISABLED. Stealers often tell victims to turn it off. Fix: sudo spctl --global-enable"
  fi
  if csrutil status 2>/dev/null | grep -q "enabled"; then
    ok "System Integrity Protection is enabled"
  else
    warn "System Integrity Protection is not fully enabled ($(csrutil status 2>/dev/null))"
  fi
}

check_processes() {
  section "Running processes"

  # 1. Suspicious command lines. Snapshot first so grep doesn't match itself.
  local snap hits pid ppid cmd n=0
  snap=$(ps -axww -o pid=,ppid=,command=)
  hits=$(printf '%s\n' "$snap" | grep -E "$PROC_RE")
  while read -r pid ppid cmd; do
    [ -z "${pid:-}" ] && continue
    if [ "$pid" = "$$" ] || [ "$ppid" = "$$" ]; then continue; fi
    matches "$cmd" "$PROC_RE" || continue
    warn "PID $pid (parent $ppid) has a suspicious command line: $(short "$cmd")"
    n=$((n + 1))
  done <<EOF
$hits
EOF
  [ "$n" -eq 0 ] && ok "No osascript, curl|sh, base64-decode or raw-IP downloads running"

  # 2. Where each running binary lives and who signed it.
  local path root sig dev_unsigned=0 checked=0 bad=0
  while read -r pid path; do
    case "$path" in /*) ;; *) continue ;; esac
    if [ ! -e "$path" ]; then
      case "$path" in
        /System/*|/usr/*|/bin/*|/sbin/*|/Library/Apple/*) ;;  # cryptex/simulator paths
        *.app/*)
          if [ -e "$(app_root "$path")" ]; then
            note "PID $pid: app was updated while running (old binary gone): $path"
          else
            warn "PID $pid runs from an app bundle that no longer exists: $path"; bad=$((bad + 1))
          fi ;;
        *) warn "PID $pid runs a binary that no longer exists on disk (self-deleted?): $path"
           bad=$((bad + 1)) ;;
      esac
      continue
    fi
    if printf '%s' "$path" | grep -qE "$TEMP_PATHS_RE"; then
      sig=$(signer "$(app_root "$path")")
      if is_untrusted_sig "$sig"; then
        warn "PID $pid runs an $sig binary from a temp/shared folder: $path"; bad=$((bad + 1))
      elif ! printf '%s' "$path" | grep -q '^/Users/Shared/'; then
        info "PID $pid runs from a temp folder (signed by $sig): $path"
      fi
      continue
    fi
    case "$path" in
      /Applications/*|"$HOME"/*) ;;
      *) continue ;;   # /System, /usr, /opt/homebrew: out of scope
    esac
    root=$(app_root "$path")
    sig=$(signer "$root")
    checked=$((checked + 1))
    if is_untrusted_sig "$sig"; then
      if printf '%s' "$root" | grep -qE "$DEV_PATHS_RE"; then
        dev_unsigned=$((dev_unsigned + 1))
      else
        warn "PID $pid runs an $sig app/binary: $root"; bad=$((bad + 1))
      fi
    fi
  done <<EOF
$(ps -axo pid=,comm= | awk '{p=$1; sub(/^[ ]*[0-9]+[ ]+/, ""); if (!seen[$0]++) print p " " $0}')
EOF
  [ "$bad" -eq 0 ] && ok "$checked third-party binaries checked: all signed, none self-deleted or running from temp"
  [ "$dev_unsigned" -gt 0 ] && note "$dev_unsigned unsigned binaries in developer-tool folders (normal for compilers/package managers)"
}

check_history() {
  section "Shell history (ClickFix / pasted commands)"
  local f files="" nfiles=0
  for f in "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.sh_history" \
           "$HOME"/.zsh_sessions/*.history "$HOME/.local/share/fish/fish_history"; do
    [ -r "$f" ] || continue
    files="$files$f
"
    nfiles=$((nfiles + 1))
  done
  if [ "$nfiles" -eq 0 ]; then
    info "No shell history files found. History that was recently wiped can itself be a sign of tampering."
    return
  fi

  local hits line
  hits=$(printf '%s' "$files" | while IFS= read -r f; do
           grep -ahE "$SUSPICIOUS_RE" "$f" 2>/dev/null
         done | sed -E 's/^: [0-9]+:[0-9]+;//; s/^- cmd: //' | sort -u)

  local n=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    matches "$line" "$SUSPICIOUS_RE" || continue
    n=$((n + 1))
    if matches "$line" "$STRONG_RE"; then
      warn "$(short "$line")"
    elif printf '%s' "$line" | grep -qE "$TRUSTED_INSTALLERS_RE"; then
      info "Official installer one-liner: $(short "$line")"
    else
      warn "$(short "$line")"
    fi
  done <<EOF
$hits
EOF
  if [ "$n" -eq 0 ]; then
    ok "No risky one-liners in $nfiles history file(s)"
  else
    note "Ask yourself: did I type or paste each WARN line, and from where? Fake CAPTCHA and"
    note "'fix your Mac' pages tell you to paste exactly this kind of command into Terminal."
  fi
}

check_temp_files() {
  section "Temp and shared folders"
  local dirs="/private/tmp /private/var/tmp /Users/Shared" f kind sig n=0
  [ -n "${TMPDIR:-}" ] && dirs="$dirs ${TMPDIR%/}"

  # Stealers stage copies of browser and keychain databases before uploading them.
  # shellcheck disable=SC2086
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    warn "Browser/keychain data found in a temp folder (staged for theft?): $f"; n=$((n + 1))
  done <<EOF
$(find $dirs -maxdepth 4 -type f \( -name 'Login Data' -o -name 'Cookies' -o -name 'Web Data' \
     -o -name '*.keychain-db' -o -name 'logins.json' -o -name 'key4.db' -o -name 'cookies.sqlite' \
     -o -name 'out.zip' \) 2>/dev/null)
EOF

  # Recently dropped executables and scripts.
  # shellcheck disable=SC2086
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    printf '%s' "$f" | grep -qE "$DEV_PATHS_RE|/Users/Shared/[^.][^/]*/.+" && continue
    kind=$(file -b "$f" 2>/dev/null)
    case "$kind" in
      *Mach-O*)
        sig=$(signer "$f")
        if is_untrusted_sig "$sig"; then
          warn "Recently created $sig executable: $f ($(stat -f %Sm "$f"))"; n=$((n + 1))
        fi ;;
      *text*|*script*)
        if grep -aqE "$SUSPICIOUS_RE" "$f" 2>/dev/null; then
          warn "Script with dropper-style commands: $f ($(stat -f %Sm "$f"))"; n=$((n + 1))
        else
          info "Recent script in temp (looked clean): $f"
        fi ;;
    esac
  done <<EOF
$(find $dirs -maxdepth 3 -type f -mtime "-$DAYS" \( -perm -u+x -o -name '*.sh' -o -name '*.command' \
     -o -name '*.scpt' -o -name '*.applescript' -o -name '*.py' \) 2>/dev/null)
EOF

  # Hidden files at the top of /Users/Shared and hidden executables in ~.
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    warn "Hidden file in a shared/home location: $f ($(file -b "$f" | cut -c1-50))"; n=$((n + 1))
  done <<EOF
$(find /Users/Shared -maxdepth 1 -type f -name '.*' ! -empty ! -name '.DS_Store' ! -name '.localized' 2>/dev/null
  find "$HOME" -maxdepth 1 -type f -name '.*' -perm -u+x 2>/dev/null)
EOF

  [ "$n" -eq 0 ] && ok "No staged browser data, unsigned droppers or hidden executables (last $DAYS days)"
}

check_known_iocs() {
  section "Known stealer artifacts"
  # File paths reported in public AMOS/Atomic write-ups. Not exhaustive: PRs welcome.
  local f n=0
  for f in "$HOME/.agent" "$HOME/.helper" "$HOME/.pass" "$HOME/.username" \
           "/Users/Shared/.agent" "/private/tmp/out.zip" \
           "$HOME/Library/LaunchAgents/com.finder.helper.plist" \
           "/Library/LaunchDaemons/com.finder.helper.plist"; do
    if [ -e "$f" ]; then
      warn "Known stealer artifact present: $f ($(stat -f %Sm "$f"))"; n=$((n + 1))
    fi
  done
  [ "$n" -eq 0 ] && ok "None of the known artifact paths exist"
}

check_persistence() {
  section "Persistence (launch items, login items, cron, shell startup)"
  local d p prog dump sig n=0 total=0
  for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
    [ -d "$d" ] || continue
    for p in "$d"/* "$d"/.*; do
      [ -f "$p" ] || continue
      case "$(basename "$p")" in .DS_Store|.localized) continue ;; esac
      total=$((total + 1))
      case "$(basename "$p")" in .*) warn "Hidden launch item: $p"; n=$((n + 1)) ;; esac
      prog=$(plutil -extract Program raw "$p" 2>/dev/null || plutil -extract ProgramArguments.0 raw "$p" 2>/dev/null)
      dump=$(plutil -p "$p" 2>/dev/null)
      if [ -z "$prog" ]; then
        note "$(basename "$p"): no program set (often a leftover stub)"
        continue
      fi
      case "$prog" in
        /bin/sh|/bin/bash|/bin/zsh|/usr/bin/osascript|/usr/bin/python3|/usr/bin/perl|/usr/bin/env)
          warn "$(basename "$p") launches an interpreter ($prog). Review: $(short "$(printf '%s' "$dump" | tr -s ' ')")"
          n=$((n + 1)); continue ;;
      esac
      if printf '%s' "$dump" | grep -qE "$SUSPICIOUS_RE|/(private/)?tmp/|/Users/Shared/\\."; then
        warn "$(basename "$p") has suspicious arguments: $(short "$(printf '%s' "$dump" | tr -s ' ')")"
        n=$((n + 1)); continue
      fi
      if [ ! -e "$prog" ]; then
        note "$(basename "$p") -> $prog (missing; stale entry)"
        continue
      fi
      sig=$(signer "$(app_root "$prog")")
      if is_untrusted_sig "$sig"; then
        warn "$(basename "$p") runs an $sig binary: $prog (plist modified $(stat -f %Sm "$p"))"; n=$((n + 1))
      else
        note "$(basename "$p") -> $sig"
      fi
    done
  done
  [ "$n" -eq 0 ] && ok "$total launch agent/daemon file(s): none unsigned, hidden or script-based"

  # Login items. Uses a timeout because macOS may show an Automation permission prompt.
  local items item
  items=$(perl -e 'alarm shift; exec @ARGV' 15 osascript -e \
    'tell application "System Events" to get the path of every login item' 2>/dev/null | perl -pe 's/, /\n/g')
  if [ -z "$items" ]; then
    note "Login items: none, or Terminal lacks Automation permission for System Events"
  else
    while IFS= read -r item; do
      [ -z "$item" ] && continue
      sig=$(signer "$item")
      if is_untrusted_sig "$sig"; then warn "Login item is $sig: $item"; n=$((n + 1))
      else note "Login item: $item -> $sig"; fi
    done <<EOF
$items
EOF
  fi

  local cron
  cron=$(crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
  if [ -n "$cron" ]; then
    while IFS= read -r line; do
      if matches "$line" "$SUSPICIOUS_RE|/(private/)?tmp/"; then warn "Suspicious crontab entry: $line"
      else info "Crontab entry: $line"; fi
    done <<EOF
$cron
EOF
  fi

  local f hit
  for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.zlogin" \
           "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile"; do
    [ -r "$f" ] || continue
    hit=$(grep -nE "curl|wget|base64|osascript|nohup|/(private/)?tmp/" "$f" 2>/dev/null)
    [ -n "$hit" ] && while IFS= read -r line; do
      warn "$(basename "$f") line $(short "$line")"
    done <<EOF
$hit
EOF
  done
}

check_network() {
  section "Outbound network connections"
  local pids pid path sig n=0 total=0
  pids=$(lsof -nP -iTCP -sTCP:ESTABLISHED -Fpn 2>/dev/null |
         awk '/^p/{pid=substr($0,2)} /^n/{a=substr($0,2); if (a !~ /->(127\.|\[::1\]|localhost)/) print pid}' |
         sort -u)
  while IFS= read -r pid; do
    [ -z "$pid" ] && continue
    path=$(ps -o comm= -p "$pid" 2>/dev/null)
    case "$path" in /System/*|/usr/*|/Library/Apple/*|"") continue ;; esac
    total=$((total + 1))
    sig=$(signer "$(app_root "$path")")
    if printf '%s' "$path" | grep -qE "$TEMP_PATHS_RE" || \
       { is_untrusted_sig "$sig" && ! printf '%s' "$path" | grep -qE "$DEV_PATHS_RE"; }; then
      warn "PID $pid ($sig) is talking to the internet: $path -> $(lsof -nP -a -p "$pid" -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1{print $9}' | head -3 | tr '\n' ' ')"
      n=$((n + 1))
    fi
  done <<EOF
$pids
EOF
  [ "$n" -eq 0 ] && ok "$total third-party process(es) online: all signed, none from temp folders"
}

check_downloads() {
  section "Recent downloads (last $DAYS days)"
  local db="$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" rows row
  if [ ! -r "$db" ]; then note "Download history database not readable"; return; fi
  rows=$(sqlite3 -separator ' | ' "$db" "select datetime(LSQuarantineTimeStamp+978307200,'unixepoch','localtime'), coalesce(LSQuarantineAgentName,'?'), coalesce(LSQuarantineDataURLString, LSQuarantineOriginURLString, '?') from LSQuarantineEvent where LSQuarantineTimeStamp+978307200 > strftime('%s','now','-$DAYS days') order by LSQuarantineTimeStamp desc limit 30;" 2>/dev/null)
  if [ -z "$rows" ]; then ok "No quarantined downloads recorded"; return; fi
  while IFS= read -r row; do
    if printf '%s' "$row" | grep -qE "$IP_URL"; then warn "Downloaded from a raw IP address: $(short "$row")"
    else note "$(short "$row")"; fi
  done <<EOF
$rows
EOF
  note "Stealers often arrive as cracked apps or fake installers (.dmg) from look-alike sites."
}

check_logs() {
  section "Unified log: osascript activity (last ${LOG_HOURS}h)"
  if [ "$QUICK" = 1 ]; then note "Skipped (--quick)"; return; fi
  local runs
  runs=$(log show --last "${LOG_HOURS}h" --style compact --predicate 'process == "osascript"' 2>/dev/null |
         grep -oE 'osascript\[[0-9]+' | sort -u | grep -c .)
  if [ "$runs" -eq 0 ]; then
    ok "osascript was not run"
  else
    info "osascript ran $runs time(s). Many apps use it legitimately (so does this tool, once per run)."
    note "The red flag is a password dialog you didn't expect, especially right after pasting a command."
  fi
}

# ---------------------------------------------------------------------------

printf '%smac-stealer-check %s%s  |  macOS %s  |  user %s  |  %s\n' \
  "$BLD" "$VERSION" "$RST" "$(sw_vers -productVersion)" "$(id -un)" "$(date '+%Y-%m-%d %H:%M')"
printf '%sRead-only: nothing is changed, deleted or sent anywhere.%s\n' "$DIM" "$RST"

check_protections
check_processes
check_history
check_temp_files
check_known_iocs
check_logs          # before persistence, which itself runs osascript
check_persistence
check_network
check_downloads

section "Summary"
if [ "$WARNS" -eq 0 ]; then
  ok "No warnings. $INFOS informational item(s)."
  exit 0
fi
printf '  %s%d warning(s)%s, %d informational item(s).\n' "$RED" "$WARNS" "$RST" "$INFOS"
note "A WARN means 'look at this', not 'you are infected'. See README.md: 'If something looks wrong'."
exit 1
