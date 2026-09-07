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

Each `[CHECKPOINT]` in the output pauses for Enter; `Ctrl+C` stops the script at that point without doing anything further.

## What gets backed up, and where

- **Windows:** `%SystemDrive%\CyberPatriot-Backup-<timestamp>\` — full `HKLM` registry export, exported security policy (`secpol-before.inf`), exported firewall config (`firewall-before.wfw`), and a CSV snapshot of every service's prior state/start type.
- **Linux:** `/root/cyberpatriot-backup-<timestamp>/` — `passwd`/`shadow`/`group`/`gshadow`, `login.defs`, `/etc/ssh`, `sudoers` + `sudoers.d`, a snapshot of enabled services and listening sockets, and (if present) `nftables.conf` and `/etc/ufw`. Anything the script edits later (`login.defs`, `pwquality.conf`, audit rules, sysctl file) is also copied to this folder with a `.prechange` suffix immediately before it's touched.

A full transcript of the run is also saved: `hardening.log` in the same backup folder (Linux) / console output you should redirect yourself (Windows — pipe to `Tee-Object` if you want a saved log there too).

## What's applied automatically vs. only reported

**Applied automatically** (safe on the large majority of images):
- Firewall enabled, default-deny inbound (Windows Firewall / `ufw`)
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
