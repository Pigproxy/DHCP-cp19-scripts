# CyberPatriot Hardening Scripts

Baseline hardening scripts for CyberPatriot practice/competition images:

| File | Target |
|---|---|
| `win10-hardening-max.ps1` | Windows 10 |
| `win11-hardening-max.ps1` | Windows 11 (includes TPM / VBS / Smart App Control checks) |
| `debian-hardening-max.sh` | Debian |
| `mint-hardening-max.sh` | Linux Mint |

All four follow the same philosophy: **back up first, report on everything, only auto-apply changes that are safe on the large majority of images, and stop to ask before anything destructive or image-specific.**

## Before you run anything

1. **Read the scoring packet / competition README for the image first.** These scripts encode generic best practice, not the exact checklist for your specific image. Where a setting could plausibly be required *off* on one image and *on* on another (SSH, WinRM, routing/`ip_forward`, NetBIOS, BitLocker, HVCI/Smart App Control), the script either leaves it alone or gates it behind a variable you set yourself — see **Configuration knobs** below.
2. **Answer the forensics questions before running the script.** Every script opens with a `FORENSICS CHECKPOINT` that pauses and waits for Enter — don't blow past it. Once you start disabling accounts, killing services, or editing configs, forensic evidence can be gone for good.
3. **Run once, read the output, then act.** These aren't fire-and-forget — several sections are audit/report-only by design (accounts, SUID files, listening ports, prohibited files) so you can review before deleting or disabling anything.
4. **Test on a snapshot or spare VM before competition day** if you haven't run a given script before.

## Running them

**Windows** (PowerShell, as Administrator):
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\win10-hardening-max.ps1      # or win11-hardening-max.ps1
```

**Linux** (as root):
```bash
sudo bash debian-hardening-max.sh      # or mint-hardening-max.sh
```

Linux firewall changes are intentionally opt-in. Review `ufw status verbose` and the scoring packet first, then run `sudo APPLY_UFW_HARDENING=1 bash debian-hardening-max.sh` (or the Mint script) only if default-deny inbound will not break required services or your remote session. The script does not automatically add service-specific allow rules because those depend on the image.


Each `[CHECKPOINT]` in the output pauses for Enter; `Ctrl+C` stops the script at that point without doing anything further. Windows scripts now verify elevation before creating the backup folder. Linux scripts check root privileges before writing under `/root` and use restrictive backup permissions.

## What gets backed up, and where

- **Windows:** `%SystemDrive%\CyberPatriot-Backup-<timestamp>\` — full `HKLM` registry export, exported security policy (`secpol-before.inf`), exported firewall config (`firewall-before.wfw`), and a CSV snapshot of every service's prior state/start type.
- **Linux:** `/root/cyberpatriot-backup-<timestamp>/` — `passwd`/`shadow`/`group`/`gshadow`, `login.defs`, `/etc/ssh`, `sudoers` + `sudoers.d`, a snapshot of enabled services and listening sockets, and (if present) `nftables.conf` and `/etc/ufw`. The backup directory and files are created with restrictive permissions (`umask 077`). Anything the script edits later (`login.defs`, `pwquality.conf`, audit rules, sysctl file) is also copied to this folder with a `.prechange` suffix immediately before it's touched.

A full transcript of the run is also saved: `hardening.log` in the same backup folder (Linux) / console output you should redirect yourself (Windows — pipe to `Tee-Object` if you want a saved log there too).

## What's applied automatically vs. only reported

**Applied automatically** (safe on the large majority of images):
- Windows Firewall enabled with default-deny inbound (Windows)
- Linux UFW is **report-only by default** to avoid accidental remote lockout; after reviewing required services and allow rules, opt in with `APPLY_UFW_HARDENING=1` (see below)
- Guest account locked/disabled
- Password length, max/min age, lockout threshold — plus, on Windows, password complexity and disabling reversible-encryption storage (via `secedit`, since `net accounts` can't set those)
- On Linux, password aging is also applied retroactively to existing UID ≥ 1000 accounts via `chage`, not just to `login.defs` for future accounts
- SMBv1 disabled, insecure guest SMB logons disabled (Windows)
- Remote Registry, Telnet disabled; RDP disabled if `$DisableRdp` is true (Windows)
- UAC hardening, anonymous SID enumeration disabled, LM hash storage disabled (Windows)
- Advanced audit policy categories + command-line process auditing enabled (Windows); `auditd` enabled with watches on `passwd`/`shadow`/`group`/`sudoers`, persisted to `/etc/audit/rules.d/` so they survive a reboot (Linux)
- Autorun/autoplay disabled, SmartScreen enabled (Windows)
- Conservative network sysctls — ICMP redirects off, reverse-path filtering on, source routing off (Linux); `net.ipv4.ip_forward` is deliberately **not** touched since routing requirements are genuinely image-specific
- `pwquality.conf` given a baseline `minlen`/complexity if one isn't already set (Linux)

**Reported only — you decide** (because the "right" answer is image-specific):
- Full account list and Administrators/sudo group membership
- Every running service and enabled scheduled task/timer/cron job
- Listening ports and SMB shares
- SUID/SGID inventory and world-writable files under key paths
- Files matching common prohibited extensions (`.mp3`, `.mp4`, `.torrent`, etc.) — **listed, never deleted**
- SSH config (Linux) — inspected and syntax-checked, never edited, since disabling or restricting SSH incorrectly can lock you out
- BitLocker, HVCI, Windows 11 VBS/Smart App Control status — reported; not force-enabled, since these can break driver-dependent images

## Configuration knobs (Windows scripts, top of file)

```powershell
$DisableRdp = $true
$DisableRemoteRegistry = $true
$DisableTelnet = $true
$DisableWinRM = $false       # leave enabled if the image needs remote management
$DisableLlmnr = $true
$DisableNetbios = $false     # network-dependent; review before enabling
$EnableBitLocker = $false    # not applied even if true — status is just reported
$EnableHvci = $false         # not applied even if true — status is just reported
$MinPasswordLength = 10
$MaxPasswordAge = 90
$MinPasswordAge = 1
$LockoutThreshold = 5
$LockoutDuration = 30
$LockoutWindow = 30
```
Edit these to match your scoring packet's exact values *before* running the script.

## Reverting a change

Every script writes its pre-change state to the backup folder before editing anything, so you can manually restore from there if a change turns out to be wrong for your image (e.g. re-import the `.reg` file, restore `sshd_config`, copy back a `.prechange` file). None of the scripts include an automatic rollback/undo command — treat the backup folder as your safety net, not a one-click undo.

## Review notes / safe-use changes

- Linux firewall hardening is opt-in (`APPLY_UFW_HARDENING=1`) because automatically enabling UFW with a deny-inbound policy can lock out remote access or break required services.
- Linux password-aging defaults are inserted if their `login.defs` keys are absent, rather than silently doing nothing.
- Windows backup creation happens only after the administrator check, and timestamp names include milliseconds to reduce collisions.
- These are still generic practice-image scripts, not a substitute for the image's scoring packet. Test in a snapshot and verify each setting after running.


## Operator notes

- **Read-only is intentional in several sections.** Account membership, services, listeners, shares, startup items, SUID/SGID files, world-writable files, and suspicious file extensions are shown for a human to review. A finding is not automatically a vulnerability.
- **Treat backups as sensitive.** They can include password hashes, registry exports, firewall configuration, and security policy. Do not commit backup folders or logs to a public repository.
- **Run elevated, locally, and from a VM snapshot.** Linux scripts require root; Windows scripts require an elevated PowerShell session. Prefer the VM console over a remote session when testing firewall or remote-access settings.
- **A successful script run is not a score guarantee.** Some operations can be unsupported, overridden by policy, or inappropriate for the target image. Read each `[REVIEW]` message and verify the resulting state.
- **Re-run carefully.** The scripts are designed to be mostly repeatable, but every run creates another backup and may re-apply policy. Keep the backup associated with each run.
- **Restore manually and selectively.** There is no one-click rollback. Restore only the setting/file you intend to revert, and validate configuration syntax before restarting the related service.

## Code layout

Each script is organized in this order: privilege check, private backup/log setup, shared status helpers, competition-specific configuration, then named audit/hardening sections and a final verification pass. `# NOTE:` comments above major sections describe the purpose and call out common risks. Keep Windows 10/11 and Debian/Mint counterparts aligned when making shared changes, but test each platform independently.
