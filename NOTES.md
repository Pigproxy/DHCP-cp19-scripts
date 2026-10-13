# Maintainer and operator notes

These scripts are a starting point for CyberPatriot practice images, not a universal baseline. Always prioritize the official scoring packet, image README, and forensics requirements.

## Safe workflow

1. Take a VM snapshot and complete forensic questions before running any hardening actions.
2. Read the configuration variables at the top of the Windows scripts and review Linux firewall opt-in behavior.
3. Run from an elevated local console where possible. Firewall and remote-access changes can interrupt remote sessions.
4. Read the entire console/log output. `[OK]` means a command returned successfully; it does not prove that the desired effective policy is in force.
5. Verify settings with native tools and compare them with the scoring report.
6. Keep backups private. Linux backups contain account database files and Windows backups may contain registry and policy exports.

## How to read the scripts

- `Step` / `step`: marks a major section.
- `Ok` / `ok`: a command completed successfully.
- `Warn` / `warn`: review the result; the command may have failed or the finding needs a human decision.
- `Pause-Step` / `pause_step`: intentional checkpoint for reviewing the scoring packet or findings.
- Windows `Try-Do`: catches command errors and reports them without stopping the entire audit.
- Linux `try`: runs one command and reports success/failure without terminating the whole script.
- `# NOTE:` comments explain the purpose and risk of each major section.

## Important limitations

- No automatic rollback is provided; use the saved backup to restore selected settings manually.
- Audit policy, password policy, service availability, and security features vary by OS version, installed packages, and local/domain policy.
- The Linux scripts intentionally leave UFW enforcement off unless `APPLY_UFW_HARDENING=1` is set.
- Linux password-aging defaults preserve already stricter `login.defs` values. The interactive-account loop skips accounts whose shell is `nologin` or `false`.
- Linux password-quality settings preserve already stronger numeric values rather than replacing them with weaker template defaults.
- Windows scripts locate the built-in Guest account by its well-known SID suffix rather than assuming the account is named `Guest`.
- Suspicious/prohibited files and many configuration findings are reported, not deleted or automatically corrected, to preserve evidence and avoid breaking required functionality.
- Static checks such as `bash -n` do not replace running tests in disposable Debian/Mint/Windows VMs.
