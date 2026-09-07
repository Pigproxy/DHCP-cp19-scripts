#!/bin/bash
# Run: sudo bash mint-hardening-max.sh
set -u

BACKUP="/root/cyberpatriot-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
exec > >(tee -a "$BACKUP/hardening.log") 2>&1

step(){ echo -e "\n\033[1;36m=== $1 ===\033[0m"; }
warn(){ echo -e "\033[1;33m[REVIEW] $1\033[0m"; }
ok(){ echo -e "\033[1;32m[OK] $1\033[0m"; }
pause_step(){ echo -e "\n\033[1;33m[CHECKPOINT]\033[0m $1"; read -rp "Press Enter to continue, or Ctrl+C to stop... "; }
try(){ local d="$1"; shift; if "$@"; then ok "$d"; else warn "$d failed"; fi; }

if [ "$EUID" -ne 0 ]; then echo "Run as root: sudo bash mint-hardening-max.sh"; exit 1; fi

step "FORENSICS CHECKPOINT"
warn "Preserve evidence before changing/deleting anything."
pause_step "Confirm the scoring packet and forensics questions have been reviewed."

step "BACKUP"
cp -a /etc/passwd /etc/shadow /etc/group /etc/gshadow "$BACKUP/" 2>/dev/null || true
cp -a /etc/login.defs "$BACKUP/" 2>/dev/null || true
cp -a /etc/ssh "$BACKUP/ssh" 2>/dev/null || true
cp -a /etc/sudoers "$BACKUP/" 2>/dev/null || true
cp -a /etc/sudoers.d "$BACKUP/sudoers.d" 2>/dev/null || true
systemctl list-unit-files --type=service > "$BACKUP/services.txt" 2>/dev/null || true
ss -lntup > "$BACKUP/listeners.txt" 2>/dev/null || true
cp -a /etc/nftables.conf "$BACKUP/" 2>/dev/null || true
cp -a /etc/ufw "$BACKUP/ufw" 2>/dev/null || true

step "ACCOUNT AUDIT"
awk -F: '($3>=1000)||($3==0){print $1, $3, $6, $7}' /etc/passwd
echo "--- UID 0 accounts ---"; awk -F: '($3==0){print $1}' /etc/passwd
echo "--- sudo group ---"; getent group sudo 2>/dev/null || true
echo "--- wheel group ---"; getent group wheel 2>/dev/null || true
echo "--- empty-password accounts ---"; awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null
pause_step "Review accounts against the scoring packet before removing or changing any user."

# Built-in guest-style accounts: lock only if present; do not remove.
# (nobody is intentionally left alone -- it has no valid login shell/password
# by default and locking it is not a meaningful hardening action.)
if id guest >/dev/null 2>&1; then
    try "Locking guest account" passwd -l guest
fi

step "PASSWORD AGING"
cp -a /etc/login.defs "$BACKUP/login.defs.prechange"
sed -i -E 's/^[[:space:]]*PASS_MAX_DAYS[[:space:]].*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i -E 's/^[[:space:]]*PASS_MIN_DAYS[[:space:]].*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i -E 's/^[[:space:]]*PASS_WARN_AGE[[:space:]].*/PASS_WARN_AGE   7/' /etc/login.defs
grep -E '^[[:space:]]*PASS_(MAX|MIN|WARN)_DAYS' /etc/login.defs

# login.defs only affects accounts created AFTER this change -- it does NOT
# retroactively update existing users. Apply the same aging values directly
# to existing real (UID >= 1000) accounts with chage.
warn "Applying password aging to existing accounts (login.defs only affects new accounts)."
while IFS=: read -r uname _ uid _; do
    if [ "$uid" -ge 1000 ] 2>/dev/null; then
        try "Setting password aging for $uname" chage --maxdays 90 --mindays 1 --warndays 7 "$uname"
    fi
done < /etc/passwd

step "PAM / PASSWORD COMPLEXITY"
if command -v pam-auth-update >/dev/null; then pam-auth-update --package >/dev/null 2>&1 || true; fi
if dpkg-query -W -f='${Status}\n' libpam-pwquality 2>/dev/null | grep -q "install ok installed"; then
    ok "libpam-pwquality is installed"
    # Detecting the package is not the same as enforcing anything -- without
    # this, nothing actually requires a minimum length or complexity. Back up
    # pwquality.conf, then set a baseline minlen/complexity if one isn't
    # already configured more strictly.
    if [ -f /etc/security/pwquality.conf ]; then
        cp -a /etc/security/pwquality.conf "$BACKUP/pwquality.conf.prechange"
        if ! grep -qE '^[[:space:]]*minlen[[:space:]]*=' /etc/security/pwquality.conf; then
            echo "minlen = 10" >> /etc/security/pwquality.conf
        fi
        for opt in dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1; do
            key="${opt%%=*}"
            if ! grep -qE "^[[:space:]]*${key}[[:space:]]*=" /etc/security/pwquality.conf; then
                echo "$opt" >> /etc/security/pwquality.conf
            fi
        done
        ok "Baseline pwquality settings ensured in /etc/security/pwquality.conf"
        warn "Adjust minlen/credit values to match the exact scoring requirement if different."
    else
        warn "/etc/security/pwquality.conf not found; complexity not enforced."
    fi
else
    warn "libpam-pwquality not installed; install only if allowed by the image/rules."
fi
warn "Do not overwrite PAM files blindly; exact distro/version/scoring requirements vary."

step "FIREWALL"
if command -v ufw >/dev/null; then
    ufw default deny incoming
    ufw default allow outgoing
    ufw logging on
    ufw --force enable
    ufw status verbose
elif command -v nft >/dev/null; then
    nft list ruleset
    warn "nftables exists. Do not replace an existing ruleset blindly; preserve required scoring/network services."
elif command -v iptables >/dev/null; then
    iptables -L -n -v
    warn "iptables exists but no UFW/nftables wrapper was selected."
else
    warn "No recognized firewall command found."
fi

step "SSH"
if [ -f /etc/ssh/sshd_config ]; then
    cp -a /etc/ssh/sshd_config "$BACKUP/sshd_config"
    grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|X11Forwarding|MaxAuthTries|AllowUsers|AllowGroups)' /etc/ssh/sshd_config || true
    warn "SSH is image-specific. If required, harden according to the scoring packet; if not required, disable the service after confirming."
    if command -v sshd >/dev/null; then sshd -t && ok "sshd configuration syntax is valid" || warn "sshd config syntax check failed"; fi
fi

step "REMOTE / INSECURE SERVICES"
for svc in telnet.socket telnet rsh.socket rlogin.socket rexec.socket vsftpd; do
    if systemctl list-unit-files "$svc" >/dev/null 2>&1; then
        warn "Found service: $svc — verify whether required before disabling."
    fi
done
if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
    echo "SSH service detected."
fi

step "SERVICE REVIEW"
systemctl list-unit-files --type=service --state=enabled 2>/dev/null
systemctl --type=service --state=running 2>/dev/null
pause_step "Disable only services confirmed unnecessary by the scoring packet."

step "NETWORK REVIEW"
ss -lntup 2>/dev/null || true
ip addr 2>/dev/null || true
ip route 2>/dev/null || true

step "AUDITING"
if command -v auditctl >/dev/null; then
    auditctl -s || true
    systemctl enable --now auditd 2>/dev/null || warn "Could not start/enable auditd."
    auditctl -w /etc/passwd -p wa -k identity 2>/dev/null || true
    auditctl -w /etc/shadow -p wa -k identity 2>/dev/null || true
    auditctl -w /etc/group -p wa -k identity 2>/dev/null || true
    auditctl -w /etc/sudoers -p wa -k scope 2>/dev/null || true
    # auditctl -w only sets RUNTIME rules -- they are lost on reboot unless
    # also written to a persistent rules file that auditd loads at startup.
    if [ -d /etc/audit/rules.d ]; then
        RULES_FILE=/etc/audit/rules.d/cyberpatriot-hardening.rules
        [ -f "$RULES_FILE" ] && cp -a "$RULES_FILE" "$BACKUP/$(basename "$RULES_FILE").prechange"
        cat > "$RULES_FILE" <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k scope
EOF
        try "Persisting audit rules across reboot" augenrules --load
    else
        warn "/etc/audit/rules.d not found; audit watches will not survive a reboot."
    fi
else
    warn "auditd/auditctl not installed. Check scoring requirements before installing packages."
fi

step "SUDOERS"
visudo -c 2>/dev/null && ok "sudoers syntax valid" || warn "sudoers syntax could not be validated"
find /etc/sudoers.d -maxdepth 1 -type f -print -exec sed -n '1,160p' {} \; 2>/dev/null || true

step "CRON / STARTUP"
crontab -l -u root 2>/dev/null || echo "(root crontab empty/unavailable)"
find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f -print 2>/dev/null
systemctl list-timers --all 2>/dev/null

step "SENSITIVE PERMISSIONS"
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers 2>/dev/null
warn "Compare permissions to distro defaults before changing them."

step "SUID / SGID INVENTORY"
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf '%m %u:%g %p\n' 2>/dev/null | sort

step "WORLD-WRITABLE REVIEW"
find /etc /usr/local /opt /var/www -xdev -type f -perm -0002 -printf '%m %u:%g %p\n' 2>/dev/null | head -200

step "PROHIBITED-FILE REVIEW"
find /home /root -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' -o -iname '*.torrent' \) -print 2>/dev/null
warn "LIST ONLY: verify against scoring/forensics before deletion."

step "KERNEL / SECURITY SETTINGS"
echo "--- current values ---"
sysctl -a 2>/dev/null | grep -E '^(net\.ipv4\.ip_forward|net\.ipv4\.conf\..*\.accept_redirects|net\.ipv4\.conf\..*\.send_redirects|net\.ipv4\.conf\..*\.rp_filter|net\.ipv4\.icmp_echo_ignore_broadcasts)' | head -100
warn "ip_forward is left untouched -- routing requirements are genuinely image-specific."

# The following are safe on the large majority of CyberPatriot images (they
# don't route traffic for other hosts) and are commonly scored. Written to a
# dedicated file (backed up if it already exists) rather than editing
# sysctl.conf directly, so it's easy to identify/revert.
SYSCTL_FILE=/etc/sysctl.d/60-cyberpatriot-hardening.conf
[ -f "$SYSCTL_FILE" ] && cp -a "$SYSCTL_FILE" "$BACKUP/$(basename "$SYSCTL_FILE").prechange"
cat > "$SYSCTL_FILE" <<'EOF'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOF
try "Applying network hardening sysctls" sysctl --system

step "UPDATES"
if command -v apt-get >/dev/null; then
    apt-get update 2>&1 | tail -20 || warn "apt update failed (offline images commonly fail here)."
fi

step "FINAL CHECK"
echo "Backup: $BACKUP"
echo "--- firewall ---"
if command -v ufw >/dev/null; then ufw status verbose; elif command -v nft >/dev/null; then nft list ruleset; fi
echo "--- listeners ---"; ss -lntup 2>/dev/null || true
echo "--- enabled services ---"; systemctl list-unit-files --type=service --state=enabled 2>/dev/null
echo -e "\n\033[1;36m=== PASS COMPLETE ===\033[0m"
warn "Re-check every change against the CyberPatriot score report and image-specific README."
