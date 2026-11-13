# mac-stealer-check

A small, **read-only** script that checks your Mac for signs of infostealer malware. It targets AMOS/Atomic, Poseidon, Cuckoo, Banshee and the "ClickFix" fake-CAPTCHA campaigns.

- **One file, no dependencies.** It uses only tools that ship with macOS.
- **Read-only.** It never changes, deletes, quarantines or uploads anything. It only prints a report.
- **No sudo.** It checks your own user account.
- **Readable.** It is about 470 lines of commented Bash. Please read it before you run it (see below).

```
== Shell history (ClickFix / pasted commands) ==
  [WARN] echo "Y3VybCBodHRwOi8v..." | base64 -d | bash
  [INFO] Official installer one-liner: curl -fsSL https://sh.rustup.rs | sh
== Known stealer artifacts ==
  [ OK ] None of the known artifact paths exist
```

## Run it

```bash
git clone https://github.com/kjwjeong/mac-stealer-check.git
cd mac-stealer-check
less mac-stealer-check.sh     # read it first
./mac-stealer-check.sh
```

> **Don't** run this (or anything else) with `curl … | bash`. That habit is exactly how these stealers get in.

Options:

| Flag | Meaning |
|---|---|
| `--quick` | Skip the unified-log query, which is the slowest check |
| `--days N` | Look-back window for temp files and downloads (default 30) |
| `--log-hours N` | Look-back window for the system log (default 24) |
| `--no-color` | Plain output. Useful for `./mac-stealer-check.sh > report.txt` |

Exit codes: `0` no warnings, `1` warnings to review, `2` could not run.

The first run may ask: *"Terminal wants to control System Events"*. That prompt comes from the login-items check. Click **Don't Allow** if you prefer. The check is then skipped and nothing else is affected.

## What it checks

| Area | What it looks for | Why |
|---|---|---|
| System protections | Gatekeeper or SIP turned off | Victims are often told to disable Gatekeeper so an unsigned app can run |
| Running processes | `osascript`, `curl … \| sh`, `base64 -d`, raw-IP downloads, `python -c` with exec/base64 | Living-off-the-land commands stealers use to drop payloads and fake password prompts |
| Running binaries | Programs running from `/tmp`, `/var/folders`, `/Users/Shared`. Binaries deleted from disk while still running. Unsigned or ad-hoc-signed apps | Droppers run from temp folders and delete themselves |
| Shell history | The same one-liners in zsh, bash and fish history, including per-session zsh history | ClickFix pages make you paste the attack into Terminal yourself |
| Temp folders | Copies of browser databases (`Login Data`, `Cookies`, `logins.json`, `key4.db`), keychain files, `out.zip`. New unsigned executables. Scripts containing dropper commands. Hidden files | Stealers gather your data into a temp folder before uploading it |
| Known artifacts | `~/.agent`, `~/.helper`, `~/.pass`, `~/.username`, `com.finder.helper.plist` and others | Paths reported in public AMOS write-ups |
| Persistence | LaunchAgents/Daemons that are unsigned, hidden, script-based or have suspicious arguments. Login items. Crontab. `.zshrc`/`.zprofile` tampering | Newer variants install a backdoor that survives reboot |
| Network | Unsigned programs, or programs running from temp folders, that have open internet connections | Data being sent out |
| Downloads | macOS download history (last 30 days). Flags downloads from raw IP addresses | Cracked apps and fake installers are the other main way in |
| System log | How often `osascript` ran | Fake "enter your password" dialogs are made with `osascript` |

### Reading the results

- **`[WARN]`** means *look at this*. It does **not** mean you are infected. Developers in particular will see some warnings, such as a `curl | bash` they ran themselves.
- **`[INFO]`** is context, for example an official installer you ran, like Homebrew or rustup.
- **`[ OK ]`** means the check found nothing.

Ask two questions about each warning: *Did I do this? Do I recognise this app?*

## If something looks wrong

1. **Disconnect from the internet** (turn Wi-Fi off). This stops more data from being sent.
2. **Don't type your Mac password** into any dialog you didn't expect.
3. **Use a different, clean device** to change your passwords. Start with email, banking, Apple ID and any crypto exchanges. Revoke active sessions where the service allows it, because stealers take session cookies, not just passwords.
4. **Move crypto** out of any wallet on this Mac (browser extensions and desktop wallets) into a fresh wallet created on a clean device.
5. Get a second opinion with a dedicated tool, such as [Objective-See's KnockKnock](https://objective-see.org/products/knockknock.html) or Malwarebytes for Mac. Or ask for help in [r/macsysadmin](https://reddit.com/r/macsysadmin) or [r/cybersecurity_help](https://reddit.com/r/cybersecurity_help). Before posting your report, remove anything private from it.
6. If you confirm an infection, the safest fix is to back up your documents (not your apps), erase the Mac and reinstall macOS.

## Limitations

- **This is a quick check, not an antivirus.** A clean result lowers the odds of infection but cannot prove the Mac is clean. Many stealers grab your data, send it and exit within a minute, leaving almost nothing behind. If you think you ran something bad, assume your passwords were taken and rotate them anyway.
- It only checks your user account. It does not read the system-wide background-items database, which needs root (`sudo sfltool dumpbtm`).
- To avoid noise, it skips unsigned binaries in developer folders (`~/.cargo`, `~/.nvm`, `node_modules`, Xcode `DerivedData`, and others). Malware could hide there too.
- The list of known artifacts is short and will go stale. Pull requests are welcome.

## Contributing

False positive or a new indicator? Open an issue or PR. Please include where the indicator comes from (a public write-up link). Run the tests before you submit:

```bash
tests/run.sh            # plants fake indicators in a throwaway HOME and checks they're caught
shellcheck mac-stealer-check.sh
```

## License

MIT
