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

VERSION="0.2.0"
DAYS=30          # look-back window for files and downloads
LOG_HOURS=24     # look-back window for the unified log
QUICK=0          # skip the slow unified-log query
COLOR=1; [ -t 1 ] || COLOR=0
HTML=0
HTML_PATH=""
OPEN_HTML=1

usage() {
  cat <<EOF
mac-stealer-check $VERSION: read-only macOS infostealer triage

Usage: ./mac-stealer-check.sh [options]

  --html [FILE]   Write a formatted HTML report (and open it in your browser)
  --no-open       With --html, save the report without opening the browser
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
    --html)
      HTML=1
      if [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then
        HTML_PATH="$2"; shift
      fi ;;
    --html=*)
      HTML=1
      HTML_PATH="${1#*=}" ;;
    --no-open)   OPEN_HTML=0 ;;
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

if [ "$HTML" = 1 ]; then
  if [ -z "$HTML_PATH" ]; then
    HTML_PATH="${TMPDIR:-/tmp}"
    HTML_PATH="${HTML_PATH%/}/mac-stealer-report-$(date '+%Y%m%d-%H%M%S').html"
  fi
  html_dir=$(dirname "$HTML_PATH")
  if [ ! -d "$html_dir" ] || [ ! -w "$html_dir" ]; then
    echo "Cannot write HTML report to: $HTML_PATH (directory missing or not writable)" >&2
    exit 2
  fi
fi

if [ "$COLOR" = 1 ]; then
  RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; BLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=""; YEL=""; GRN=""; BLD=""; DIM=""; RST=""
fi

REPORT_DATA=$(mktemp "${TMPDIR:-/tmp}/mac-stealer-check.XXXXXX") || exit 2
trap 'rm -f "$REPORT_DATA"' EXIT

WARNS=0
INFOS=0
SEC_IDX=0
emit_rec() {
  local clean
  clean=$(printf '%s' "$2" | tr '\t\r\n' '   ')
  printf '%s\t%s\t%s\n' "$SEC_IDX" "$1" "$clean" >> "$REPORT_DATA"
}
section() {
  local title="$1" desc="${2:-}"
  SEC_IDX=$((SEC_IDX + 1))
  printf '%s\tSEC\t%s\t%s\n' "$SEC_IDX" "$(printf '%s' "$title" | tr '\t\r\n' '   ')" "$(printf '%s' "$desc" | tr '\t\r\n' '   ')" >> "$REPORT_DATA"
  printf '\n%s== %s ==%s\n' "$BLD" "$title" "$RST"
}
warn()    { WARNS=$((WARNS + 1)); emit_rec "WARN" "$*"; printf '  %s[WARN]%s %s\n' "$RED" "$RST" "$*"; }
info()    { INFOS=$((INFOS + 1)); emit_rec "INFO" "$*"; printf '  %s[INFO]%s %s\n' "$YEL" "$RST" "$*"; }
ok()      { emit_rec "OK" "$*"; printf '  %s[ OK ]%s %s\n' "$GRN" "$RST" "$*"; }
note()    { emit_rec "NOTE" "$*"; printf '         %s%s%s\n' "$DIM" "$*" "$RST"; }
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
  section "System protections" "Checks that Gatekeeper and System Integrity Protection (SIP) are enabled."
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
  section "Running processes" "Looks for living-off-the-land scripts, self-deleted binaries, and unsigned apps running now."

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
  section "Shell history (ClickFix / pasted commands)" "Scans zsh, bash, and fish history for pasted one-liners typical of fake-CAPTCHA attacks."
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
  section "Temp and shared folders" "Checks temp and shared folders for staged browser/keychain data, new unsigned binaries, and hidden files."
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
  section "Known stealer artifacts" "Checks for file and launch-item paths reported in public AMOS/Atomic write-ups."
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
  section "Persistence (launch items, login items, cron, shell startup)" "Audits startup items, cron jobs, and shell rc files for backdoors that survive a reboot."
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
  section "Outbound network connections" "Checks whether any unsigned binary or temp-folder process currently has an internet connection."
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
  section "Recent downloads (last $DAYS days)" "Reviews macOS Quarantine download history and flags downloads from raw IP addresses."
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
  section "Unified log: osascript activity (last ${LOG_HOURS}h)" "Counts recent AppleScript runs, which stealers use to display fake password dialogs."
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

render_html() {
  local host os_ver scan_time
  host=$(scutil --get ComputerName 2>/dev/null || hostname -s 2>/dev/null || echo "Mac")
  os_ver=$(sw_vers -productVersion)
  scan_time=$(date '+%Y-%m-%d %H:%M %Z')

  MSC_VER="$VERSION" MSC_OS="$os_ver" MSC_USER="$(id -un)" MSC_HOST="$host" \
  MSC_TIME="$scan_time" MSC_DAYS="$DAYS" MSC_HOURS="$LOG_HOURS" MSC_QUICK="$QUICK" \
  MSC_WARNS="$WARNS" MSC_INFOS="$INFOS" MSC_DATA="$REPORT_DATA" MSC_OUT="$HTML_PATH" \
  perl -e '
    use strict;
    use warnings;

    sub esc {
      my ($s) = @_;
      $s //= "";
      $s =~ s/&/&amp;/g;
      $s =~ s/</&lt;/g;
      $s =~ s/>/&gt;/g;
      $s =~ s/"/&quot;/g;
      $s =~ s/\x27/&#39;/g;
      return $s;
    }

    open my $in, "<", $ENV{MSC_DATA} or die "Cannot read report data: $!\n";
    my @sections;
    my %sec_by_id;
    while (my $line = <$in>) {
      chomp $line;
      my ($idx, $kind, $a, $b) = split(/\t/, $line, 4);
      next unless defined $idx && defined $kind;
      if ($kind eq "SEC") {
        my $sec = { id => $idx, title => $a // "", desc => $b // "", items => [], warns => 0, infos => 0, oks => 0 };
        push @sections, $sec;
        $sec_by_id{$idx} = $sec;
      } elsif (my $sec = $sec_by_id{$idx}) {
        push @{$sec->{items}}, { level => $kind, text => $a // "" };
        $sec->{warns}++ if $kind eq "WARN";
        $sec->{infos}++ if $kind eq "INFO";
        $sec->{oks}++   if $kind eq "OK";
      }
    }
    close $in;

    my $total_sec = scalar @sections;
    my $passed_sec = 0;
    my @warn_list;
    for my $s (@sections) {
      $passed_sec++ if $s->{warns} == 0;
      for my $it (@{$s->{items}}) {
        push @warn_list, { sec => $s->{title}, sec_id => $s->{id}, text => $it->{text} } if $it->{level} eq "WARN";
      }
    }

    my $warns = $ENV{MSC_WARNS} + 0;
    my $infos = $ENV{MSC_INFOS} + 0;
    my $verdict_cls = $warns > 0 ? "verdict-warn" : "verdict-ok";
    my $verdict_badge = $warns > 0 ? "Review recommended" : "All clear";
    my $verdict_title = $warns > 0
      ? "$warns " . ($warns == 1 ? "item needs" : "items need") . " your attention"
      : "No infostealer indicators found";
    my $verdict_sub = $warns > 0
      ? "A warning is a lead to check, not proof of infection. Review each item below and ask: did I run or install this myself?"
      : "All $total_sec checks completed without warnings. Remember: a clean scan lowers risk, it cannot guarantee a clean Mac.";

    my $mode = $ENV{MSC_QUICK} ? "Quick (system log skipped)" : "Full ($ENV{MSC_HOURS}h system log)";

    open my $out, ">", $ENV{MSC_OUT} or die "Cannot write $ENV{MSC_OUT}: $!\n";
    print $out <<"HTML";
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mac-stealer-check report — @{[esc($ENV{MSC_HOST})]}</title>
<style>
  :root {
    --bg: #f6f7f9; --card: #ffffff; --ink: #111827; --muted: #5b6472;
    --border: #e4e7ec; --code-bg: #f1f3f6;
    --ok-bg: #ecfdf3; --ok-fg: #067647; --ok-bd: #abefc6;
    --warn-bg: #fef3f2; --warn-fg: #b42318; --warn-bd: #fecdca;
    --info-bg: #fffaeb; --info-fg: #b54708; --info-bd: #fedf89;
    --note-fg: #475467; --accent: #2563eb;
  }
  \@media (prefers-color-scheme: dark) {
    :root {
      --bg: #0d1117; --card: #161b22; --ink: #e6edf3; --muted: #8b949e;
      --border: #30363d; --code-bg: #1f242c;
      --ok-bg: #0f291e; --ok-fg: #56d364; --ok-bd: #238636;
      --warn-bg: #321618; --warn-fg: #ff7b72; --warn-bd: #da3633;
      --info-bg: #2b210d; --info-fg: #e3b341; --info-bd: #9e6a03;
      --note-fg: #9ca3af; --accent: #58a6ff;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 28px 18px 56px;
    background: var(--bg); color: var(--ink);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif;
  }
  .wrap { max-width: 900px; margin: 0 auto; }
  header.top {
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-start;
    gap: 12px; margin-bottom: 18px;
  }
  .brand { font-size: 13px; font-weight: 600; letter-spacing: .02em; color: var(--muted); text-transform: uppercase; }
  h1 { margin: 2px 0 4px; font-size: 24px; letter-spacing: -0.02em; }
  .meta { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
  .chip {
    font-size: 12px; color: var(--muted); background: var(--card);
    border: 1px solid var(--border); border-radius: 999px; padding: 3px 10px;
  }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  button.btn {
    cursor: pointer; font: 600 13px/1 inherit; padding: 8px 12px;
    border-radius: 8px; border: 1px solid var(--border);
    background: var(--card); color: var(--ink);
  }
  button.btn:hover { border-color: var(--muted); }
  button.btn.active { background: var(--ink); color: var(--bg); border-color: var(--ink); }

  .verdict {
    border-radius: 14px; padding: 20px 22px; margin-bottom: 16px; border: 1px solid;
  }
  .verdict-ok { background: var(--ok-bg); border-color: var(--ok-bd); }
  .verdict-warn { background: var(--warn-bg); border-color: var(--warn-bd); }
  .verdict-pill {
    display: inline-block; font-size: 11px; font-weight: 700; text-transform: uppercase;
    letter-spacing: .05em; padding: 3px 9px; border-radius: 999px; margin-bottom: 8px;
  }
  .verdict-ok .verdict-pill { background: var(--ok-fg); color: #fff; }
  .verdict-warn .verdict-pill { background: var(--warn-fg); color: #fff; }
  .verdict h2 { margin: 0 0 4px; font-size: 20px; }
  .verdict p { margin: 0; color: var(--ink); opacity: .88; }

  .stats {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px;
    margin-bottom: 20px;
  }
  \@media (max-width: 640px) { .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  .stat {
    background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px;
  }
  .stat .num { font-size: 24px; font-weight: 700; line-height: 1.2; }
  .stat .lbl { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .stat.has-warn .num { color: var(--warn-fg); }

  .card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 14px; margin-bottom: 14px; overflow: hidden;
  }
  .card-hd {
    display: flex; justify-content: space-between; align-items: flex-start; gap: 12px;
    padding: 14px 18px; border-bottom: 1px solid var(--border);
  }
  .card-title { font-size: 16px; font-weight: 650; margin: 0; }
  .card-desc { font-size: 13px; color: var(--muted); margin: 3px 0 0; }
  .badge {
    flex-shrink: 0; font-size: 11px; font-weight: 700; letter-spacing: .04em;
    padding: 4px 9px; border-radius: 999px; border: 1px solid;
  }
  .b-ok   { background: var(--ok-bg); color: var(--ok-fg); border-color: var(--ok-bd); }
  .b-warn { background: var(--warn-bg); color: var(--warn-fg); border-color: var(--warn-bd); }
  .b-info { background: var(--info-bg); color: var(--info-fg); border-color: var(--info-bd); }

  .items { list-style: none; margin: 0; padding: 10px 18px 14px; display: flex; flex-direction: column; gap: 8px; }
  .item {
    display: flex; align-items: flex-start; gap: 10px; padding: 9px 11px;
    border-radius: 9px; font-size: 13.5px; border: 1px solid transparent;
  }
  .item-WARN { background: var(--warn-bg); border-color: var(--warn-bd); }
  .item-INFO { background: var(--info-bg); border-color: var(--info-bd); }
  .item-OK   { background: var(--ok-bg); border-color: var(--ok-bd); }
  .item-NOTE { padding: 3px 4px; color: var(--note-fg); font-size: 13px; }
  .tag {
    flex-shrink: 0; font: 700 11px/1.4 ui-monospace, "SF Mono", Menlo, monospace;
    padding: 1px 6px; border-radius: 5px; margin-top: 1px;
  }
  .item-WARN .tag { color: var(--warn-fg); }
  .item-INFO .tag { color: var(--info-fg); }
  .item-OK   .tag { color: var(--ok-fg); }
  .item-NOTE .tag { color: var(--muted); font-weight: 500; }
  .msg {
    min-width: 0; overflow-wrap: anywhere; word-break: break-word;
    font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12.5px; line-height: 1.5;
  }
  .item-OK .msg, .item-NOTE .msg {
    font-family: inherit; font-size: 13.5px;
  }

  .attention { border-color: var(--warn-bd); }
  .attention .card-hd { background: var(--warn-bg); }
  .att-sec { font-weight: 600; font-size: 12px; color: var(--warn-fg); display: block; margin-bottom: 2px; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
  .att-link { color: inherit; text-decoration: none; }
  .att-link:hover { text-decoration: underline; }

  details.guide { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 14px 18px; margin-top: 18px; }
  details.guide summary { cursor: pointer; font-weight: 650; font-size: 15px; }
  details.guide ol { margin: 10px 0 4px; padding-left: 20px; }
  details.guide li { margin-bottom: 6px; font-size: 14px; }

  .hidden { display: none !important; }
  footer { margin-top: 24px; font-size: 12px; color: var(--muted); text-align: center; overflow-wrap: anywhere; }
  \@media print {
    body { background: #fff; color: #000; padding: 0; }
    .actions { display: none; }
    .card, .stat, .verdict { break-inside: avoid; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div>
      <div class="brand">mac-stealer-check v@{[esc($ENV{MSC_VER})]}</div>
      <h1>macOS Infostealer Triage Report</h1>
      <div class="meta">
        <span class="chip">Mac: @{[esc($ENV{MSC_HOST})]}</span>
        <span class="chip">macOS @{[esc($ENV{MSC_OS})]}</span>
        <span class="chip">User: @{[esc($ENV{MSC_USER})]}</span>
        <span class="chip">Scanned: @{[esc($ENV{MSC_TIME})]}</span>
        <span class="chip">Mode: @{[esc($mode)]}</span>
        <span class="chip">Window: @{[esc($ENV{MSC_DAYS})]} days</span>
      </div>
    </div>
    <div class="actions">
      <button class="btn active" id="btn-all" onclick="filterCards(\x27all\x27)">All checks ($total_sec)</button>
HTML
    if ($warns > 0) {
      print $out qq{      <button class="btn" id="btn-warn" onclick="filterCards('warn')">Warnings only ($warns)</button>\n};
    }
    print $out <<"HTML";
      <button class="btn" onclick="window.print()">Print / Save PDF</button>
    </div>
  </header>

  <section class="verdict $verdict_cls">
    <div class="verdict-pill">$verdict_badge</div>
    <h2>$verdict_title</h2>
    <p>$verdict_sub</p>
  </section>

  <section class="stats">
    <div class="stat @{[$warns > 0 ? "has-warn" : ""]}"><div class="num">$warns</div><div class="lbl">Warnings to review</div></div>
    <div class="stat"><div class="num">$infos</div><div class="lbl">Informational notes</div></div>
    <div class="stat"><div class="num">$passed_sec / $total_sec</div><div class="lbl">Checks without warnings</div></div>
    <div class="stat"><div class="num">Read-only</div><div class="lbl">Nothing modified</div></div>
  </section>
HTML

    if (@warn_list) {
      print $out qq{  <section class="card attention">\n};
      print $out qq{    <div class="card-hd"><div><h3 class="card-title">Needs your attention</h3><p class="card-desc">Ask two questions for each item: Did I run or install this myself? Do I recognize the app or domain?</p></div><span class="badge b-warn">$warns WARN</span></div>\n};
      print $out qq{    <ul class="items">\n};
      for my $w (@warn_list) {
        my $sec_name = esc($w->{sec});
        my $msg = esc($w->{text});
        my $sid = esc($w->{sec_id});
        print $out qq{      <li class="item item-WARN"><span class="tag">WARN</span><div class="msg"><a class="att-link" href="#sec-$sid"><span class="att-sec">$sec_name</span></a>$msg</div></li>\n};
      }
      print $out qq{    </ul>\n  </section>\n};
    }

    for my $s (@sections) {
      my $sid = esc($s->{id});
      my $title = esc($s->{title});
      my $desc = esc($s->{desc});
      my ($bcls, $blbl, $state);
      if ($s->{warns} > 0) {
        $bcls = "b-warn"; $blbl = "$s->{warns} WARN"; $state = "warn";
      } elsif ($s->{infos} > 0) {
        $bcls = "b-info"; $blbl = "$s->{infos} INFO"; $state = "info";
      } elsif ($s->{oks} > 0) {
        $bcls = "b-ok"; $blbl = "PASS"; $state = "ok";
      } else {
        $bcls = "b-info"; $blbl = "SKIPPED"; $state = "ok";
      }

      print $out qq{  <section class="card check-card" id="sec-$sid" data-state="$state">\n};
      print $out qq{    <div class="card-hd"><div><h3 class="card-title">$title</h3><p class="card-desc">$desc</p></div><span class="badge $bcls">$blbl</span></div>\n};
      print $out qq{    <ul class="items">\n};
      for my $it (@{$s->{items}}) {
        my $lvl = $it->{level};
        my $msg = esc($it->{text});
        my $tag = $lvl eq "NOTE" ? "detail" : $lvl;
        print $out qq{      <li class="item item-$lvl"><span class="tag">$tag</span><div class="msg">$msg</div></li>\n};
      }
      print $out qq{    </ul>\n  </section>\n};
    }

    my $open_attr = $warns > 0 ? " open" : "";
    print $out <<"HTML";
  <details class="guide"$open_attr>
    <summary>What to do if something looks wrong</summary>
    <ol>
      <li><strong>Disconnect from the internet</strong> (turn Wi-Fi off) to stop any data from being uploaded.</li>
      <li><strong>Do not enter your Mac password</strong> into any unexpected popup dialog.</li>
      <li><strong>Change passwords from a different, clean device</strong> — start with email, banking, Apple ID, and exchanges, and revoke active sessions (stealers grab cookies too).</li>
      <li><strong>Move crypto</strong> from any wallet on this Mac to a fresh wallet created on a clean device.</li>
      <li><strong>Get a second opinion</strong> with Objective-See KnockKnock or Malwarebytes for Mac.</li>
      <li><strong>If infection is confirmed</strong>, back up your documents (not apps), erase the Mac, and reinstall macOS.</li>
    </ol>
  </details>

  <footer>
    Generated locally by mac-stealer-check v@{[esc($ENV{MSC_VER})]} &middot; Read-only &middot; Zero network requests &middot; Saved to @{[esc($ENV{MSC_OUT})]}
  </footer>
</div>
<script>
function filterCards(mode) {
  var cards = document.querySelectorAll(".check-card");
  for (var i = 0; i < cards.length; i++) {
    var st = cards[i].getAttribute("data-state");
    cards[i].classList.toggle("hidden", mode === "warn" && st !== "warn");
  }
  var bAll = document.getElementById("btn-all");
  var bWarn = document.getElementById("btn-warn");
  if (bAll) bAll.classList.toggle("active", mode === "all");
  if (bWarn) bWarn.classList.toggle("active", mode === "warn");
}
</script>
</body>
</html>
HTML
    close $out;
  '
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

printf '\n%s== Summary ==%s\n' "$BLD" "$RST"
if [ "$WARNS" -eq 0 ]; then
  printf '  %s[ OK ]%s No warnings across %d checks. %d informational item(s).\n' "$GRN" "$RST" "$SEC_IDX" "$INFOS"
else
  printf '  %s%d warning(s)%s, %d informational item(s) across %d checks.\n' "$RED" "$WARNS" "$RST" "$INFOS" "$SEC_IDX"
  printf '\n  %sNeeds your attention:%s\n' "$BLD" "$RST"
  awk -F'\t' '$2 == "SEC" { sec[$1] = $3 } $2 == "WARN" { printf "    - [%s] %s\n", sec[$1], $3 }' "$REPORT_DATA"
  printf '         %sA WARN means '\''look at this'\'', not '\''you are infected'\''. See README.md: '\''If something looks wrong'\''.%s\n' "$DIM" "$RST"
fi

if [ "$HTML" = 1 ]; then
  render_html
  printf '\n  %sHTML report saved:%s %s\n' "$BLD" "$RST" "$HTML_PATH"
  if [ "$OPEN_HTML" = 1 ]; then
    open "$HTML_PATH" 2>/dev/null || true
  fi
else
  printf '         %sTip: run with --html for a formatted report in your browser.%s\n' "$DIM" "$RST"
fi

[ "$WARNS" -eq 0 ] && exit 0
exit 1
