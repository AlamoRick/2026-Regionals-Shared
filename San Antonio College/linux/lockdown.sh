#!/bin/bash
# =============================================================================
# lockdown.sh — Linux Hardening Script
# San Antonio College — SWCCDC 2026
# Based on patterns from University of Tulsa's lockdown.sh
#
# Works on: Debian, RHEL, Alpine, FreeBSD
# Each section asks before running. Nothing assumed about the environment.
#
# Usage:
#   sudo ./lockdown.sh -c     # CCDC mode (recommended)
#   sudo ./lockdown.sh -p     # Password changes only
#   sudo ./lockdown.sh -h     # Help
# =============================================================================

set -uo pipefail

# Colors
G='\033[1;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[1;36m'; P='\033[1;35m'; B='\033[1m'; N='\033[0m'
ok()      { echo -e "${G}[+]${N} $1"; }
fail()    { echo -e "${R}[-]${N} $1"; }
warn()    { echo -e "${Y}[!]${N} $1"; }
info()    { echo -e "${C}[*]${N} $1"; }
section() { echo -e "\n${B}$1${N}"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo ./lockdown.sh -c"
    exit 1
fi

# Detect distro
if command -v apt-get >/dev/null 2>&1; then
    DISTRO="debian"
elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
    DISTRO="redhat"
elif command -v apk >/dev/null 2>&1; then
    DISTRO="alpine"
elif command -v pkg >/dev/null 2>&1; then
    DISTRO="freebsd"
else
    DISTRO="unknown"
fi

echo -e "${P}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo -e "${P}  Linux Lockdown — San Antonio College${N}"
echo -e "${P}  OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')${N}"
echo -e "${P}  Distro family: $DISTRO${N}"
echo -e "${P}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"

# =========================================================================
# SECTION: Backup critical files (always runs first)
# =========================================================================
backup_files() {
    section "Backing up critical files..."
    BACKUP="/root/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP"
    for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config \
             /etc/crontab /etc/hosts /etc/resolv.conf; do
        [ -f "$f" ] && cp -a "$f" "$BACKUP/" 2>/dev/null
    done
    cp -a /etc/cron.d "$BACKUP/" 2>/dev/null
    cp -a /var/spool/cron "$BACKUP/" 2>/dev/null
    ok "Backed up to $BACKUP"
}

# =========================================================================
# SECTION: Change passwords
# =========================================================================
change_passwords() {
    section "Password Changes"
    echo -e "  Options:"
    echo -e "    1) Set ALL user passwords to a single new password"
    echo -e "    2) Change passwords one by one"
    echo -e "    3) Skip"
    echo -n "  Choice [1/2/3]: "
    read -r choice

    case "$choice" in
        1)
            echo -n "  Enter new password for all users: "
            read -r newpass
            PASSFILE="/root/passwords_$(hostname).txt"
            : > "$PASSFILE"
            chmod 600 "$PASSFILE"

            # Change root
            echo "root:$newpass" | chpasswd && ok "root" || fail "root"
            echo "root:$newpass" >> "$PASSFILE"

            # Change all human users
            while IFS=: read -r user _ uid _ _ _ shell; do
                if [ "$uid" -ge 1000 ] 2>/dev/null && \
                   [ "$shell" != "/usr/sbin/nologin" ] && \
                   [ "$shell" != "/bin/false" ] && \
                   [ "$shell" != "/sbin/nologin" ]; then
                    echo "$user:$newpass" | chpasswd && ok "$user" || fail "$user"
                    echo "$user:$newpass" >> "$PASSFILE"
                fi
            done < /etc/passwd
            warn "Passwords saved to $PASSFILE — DELETE after updating the scoring portal"
            ;;
        2)
            while IFS=: read -r user _ uid _ _ _ shell; do
                if [ "$uid" -ge 1000 ] 2>/dev/null && \
                   [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
                    echo -n "  Change password for $user? [y/N] "
                    read -r yn
                    [ "$yn" = "y" ] || [ "$yn" = "Y" ] && passwd "$user"
                fi
            done < /etc/passwd
            warn "Don't forget to change root: passwd root"
            ;;
        *) info "Skipped" ;;
    esac
}

# =========================================================================
# SECTION: Kill SSH keys and backdoor services
# =========================================================================
kill_persistence() {
    section "Remove SSH Keys & Backdoor Services"
    read -p "[?] Disable authorized_keys and kill known backdoors? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then

        # Disable authorized_keys
        for d in /root /home/*; do
            if [ -f "$d/.ssh/authorized_keys" ]; then
                mv "$d/.ssh/authorized_keys" "$BACKUP/authorized_keys_$(basename "$d")" 2>/dev/null
                ok "Disabled authorized_keys for $(basename "$d")"
            fi
            # Remove SSH private keys
            for key in "$d/.ssh/id_rsa" "$d/.ssh/id_ed25519" "$d/.ssh/id_ecdsa"; do
                [ -f "$key" ] && rm -f "$key" && warn "Removed private key: $key"
            done
        done

        # Kill known Red Team services
        for svc in tailscaled startup_check startup_check-installer reverse-shell \
                   beacon chisel ngrok rathole frpc socat; do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                systemctl disable --now "$svc" 2>/dev/null
                warn "KILLED service: $svc"
            fi
        done

        # Kill suspicious processes
        for pattern in "nc -l" "ncat -l" "socat" "chisel" "ngrok" "rathole" "/tmp/"; do
            pids=$(pgrep -f "$pattern" 2>/dev/null || true)
            [ -n "$pids" ] && kill -9 $pids 2>/dev/null && warn "Killed processes matching: $pattern"
        done

        ok "Persistence cleanup done"
    fi
}

# =========================================================================
# SECTION: Harden SSH
# =========================================================================
harden_ssh() {
    section "SSH Hardening"
    if ! pgrep -x sshd >/dev/null 2>&1; then
        info "SSH not running — skipping"
        return
    fi

    read -p "[?] Harden SSH config? (skip if SSH is a scored service you're unsure about) [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null
        sshd="/etc/ssh/sshd_config"

        # Apply settings — sed replaces existing or appends
        apply() {
            if grep -qE "^#?$1" "$sshd" 2>/dev/null; then
                sed -i "s|^#*$1.*|$1 $2|" "$sshd"
            else
                echo "$1 $2" >> "$sshd"
            fi
        }

        apply "PermitRootLogin" "no"
        apply "MaxAuthTries" "3"
        apply "PermitEmptyPasswords" "no"
        apply "PasswordAuthentication" "yes"
        apply "X11Forwarding" "no"
        apply "AllowAgentForwarding" "no"
        apply "AllowTcpForwarding" "no"
        apply "MaxSessions" "3"

        # Restart SSH
        systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || service sshd restart 2>/dev/null
        ok "SSH hardened and restarted"
    fi
}

# =========================================================================
# SECTION: Kernel hardening (sysctl)
# =========================================================================
harden_kernel() {
    section "Kernel Hardening (sysctl)"
    [ "$DISTRO" = "freebsd" ] && { info "FreeBSD — skipping sysctl"; return; }

    read -p "[?] Apply kernel hardening? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp -n /etc/sysctl.conf /etc/sysctl.conf.bak 2>/dev/null

        # Check if this box routes traffic (don't break it)
        ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)

        cat >> /etc/sysctl.conf << 'EOF'

# San Antonio College — CCDC hardening
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
fs.suid_dumpable = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
        # Preserve ip_forward if it was on
        if [ "$ip_fwd" = "1" ]; then
            echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
            warn "ip_forward was ON — preserved (this box routes traffic)"
        else
            echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
        fi

        sysctl -p 2>/dev/null | tail -3
        ok "Kernel hardened"
    fi
}

# =========================================================================
# SECTION: Firewall — auto-detects listening ports
# =========================================================================
setup_firewall() {
    section "Firewall Setup"
    echo "  This will:"
    echo "    - Detect all currently listening ports"
    echo "    - Allow those ports inbound (so scored services keep working)"
    echo "    - Allow SSH (so you don't lock yourself out)"
    echo "    - Drop everything else"
    echo ""

    read -p "[?] Set up firewall? [y/N] " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && return

    # Discover listening ports
    TCP_PORTS=$(ss -Htlnp 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un)
    UDP_PORTS=$(ss -Hulnp 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un)

    # Always include SSH
    echo "$TCP_PORTS" | grep -q "^22$" || TCP_PORTS="22
$TCP_PORTS"

    info "Detected TCP ports: $(echo $TCP_PORTS | tr '\n' ' ')"
    info "Detected UDP ports: $(echo $UDP_PORTS | tr '\n' ' ')"

    if command -v iptables >/dev/null 2>&1; then
        info "Using iptables"

        # Save current rules for rollback
        iptables-save > /root/iptables_before_lockdown.rules 2>/dev/null

        iptables -F
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT

        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p icmp -j ACCEPT

        for port in $TCP_PORTS; do
            [ -n "$port" ] && iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        done
        for port in $UDP_PORTS; do
            [ -n "$port" ] && iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        done

        iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "[iptables-drop] "

        # Save persistently
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
        [ -d /etc/sysconfig ] && iptables-save > /etc/sysconfig/iptables

        ok "iptables rules applied"
        warn "Rollback: iptables-restore < /root/iptables_before_lockdown.rules"

    elif command -v nft >/dev/null 2>&1; then
        info "Using nftables"
        nft list ruleset > /root/nft_before_lockdown.rules 2>/dev/null
        nft flush ruleset

        nft add table inet filter
        nft add chain inet filter input '{ type filter hook input priority 0; }'
        nft add chain inet filter output '{ type filter hook output priority 0; }'

        nft add rule inet filter input iif lo accept
        nft add rule inet filter input ct state established,related accept
        nft add rule inet filter input ip protocol icmp accept
        nft add rule inet filter output accept

        for port in $TCP_PORTS; do
            [ -n "$port" ] && nft add rule inet filter input tcp dport "$port" accept
        done
        for port in $UDP_PORTS; do
            [ -n "$port" ] && nft add rule inet filter input udp dport "$port" accept
        done

        nft add chain inet filter input '{ policy drop; }'
        nft list ruleset > /etc/nftables.conf 2>/dev/null
        ok "nftables rules applied"

    elif command -v ufw >/dev/null 2>&1; then
        info "Using UFW"
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        for port in $TCP_PORTS; do
            [ -n "$port" ] && ufw allow "$port/tcp"
        done
        for port in $UDP_PORTS; do
            [ -n "$port" ] && ufw allow "$port/udp"
        done
        ufw --force enable
        ok "UFW rules applied"
    else
        fail "No firewall tool found — install iptables"
    fi

    echo ""
    warn "VERIFY scored services still work before moving on!"
}

# =========================================================================
# SECTION: User lockdown
# =========================================================================
user_lockdown() {
    section "User Lockdown"
    read -p "[?] Create a backup admin account? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -n "  Username for backup admin: "
        read -r newadmin
        if [ "$DISTRO" = "alpine" ]; then
            adduser "$newadmin" && adduser "$newadmin" wheel
        elif [ "$DISTRO" = "freebsd" ]; then
            pw user add "$newadmin" && pw usermod "$newadmin" -G wheel && passwd "$newadmin"
        else
            useradd -m -s /bin/bash "$newadmin" 2>/dev/null
            usermod -aG sudo "$newadmin" 2>/dev/null
            usermod -aG wheel "$newadmin" 2>/dev/null
            passwd "$newadmin"
        fi
        ok "Created admin user: $newadmin"
    fi

    read -p "[?] Review sudoers file? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        warn "Remove 'ALL ALL=(ALL) NOPASSWD: ALL' lines"
        warn "Keep 'root ALL=(ALL) ALL'"
        warn "Make sure sudo/wheel groups don't have NOPASSWD"
        read -p "  Press Enter to open sudoers..." _
        visudo
    fi
}

# =========================================================================
# SECTION: Cron audit
# =========================================================================
audit_cron() {
    section "Cron Job Audit"
    read -p "[?] Review and clean cron jobs? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "  System crontab:"
        grep -vE '^#|^$|PATH|SHELL|MAILTO' /etc/crontab 2>/dev/null | awk '{print "    " $0}'

        for f in /etc/cron.d/*; do
            [ -f "$f" ] && echo "  $f:" && grep -vE '^#|^$' "$f" 2>/dev/null | awk '{print "    " $0}'
        done

        for uc in /var/spool/cron/crontabs/* /var/spool/cron/*; do
            [ -f "$uc" ] && echo "  User: $(basename "$uc"):" && cat "$uc" 2>/dev/null | awk '{print "    " $0}'
        done

        echo ""
        warn "Edit any suspicious cron with: crontab -e -u <username>"
        warn "Or delete: rm /etc/cron.d/<suspicious_file>"
    fi
}

# =========================================================================
# SECTION: Enable audit logging
# =========================================================================
setup_logging() {
    section "Audit Logging"
    read -p "[?] Install and configure auditd? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        case "$DISTRO" in
            debian)  apt-get install -y auditd 2>/dev/null ;;
            redhat)  yum install -y audit 2>/dev/null || dnf install -y audit 2>/dev/null ;;
        esac

        if command -v auditctl >/dev/null 2>&1; then
            auditctl -w /etc/passwd -p wa -k identity
            auditctl -w /etc/shadow -p wa -k identity
            auditctl -w /etc/group -p wa -k identity
            auditctl -w /etc/sudoers -p wa -k sudoers
            auditctl -w /etc/ssh/sshd_config -p wa -k sshd
            auditctl -w /etc/crontab -p wa -k cron
            auditctl -w /var/spool/cron/ -p wa -k cron
            systemctl enable auditd 2>/dev/null
            systemctl restart auditd 2>/dev/null
            ok "Audit logging enabled"
        else
            fail "auditd not available"
        fi
    fi
}

# =========================================================================
# SECTION: File Integrity Monitoring
# =========================================================================
setup_fim() {
    section "File Integrity Monitoring"
    read -p "[?] Create FIM baseline and cron monitor? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        FIM_DIR="/var/lib/fim"
        FIM_DB="$FIM_DIR/baseline.db"
        mkdir -p "$FIM_DIR"

        : > "$FIM_DB"
        for target in /etc/passwd /etc/shadow /etc/group /etc/sudoers \
                      /etc/ssh/sshd_config /etc/crontab /etc/hosts /usr/bin /usr/sbin; do
            if [ -d "$target" ]; then
                find "$target" -type f -exec sha256sum {} \; >> "$FIM_DB" 2>/dev/null
            elif [ -f "$target" ]; then
                sha256sum "$target" >> "$FIM_DB" 2>/dev/null
            fi
        done
        chmod 600 "$FIM_DB"
        ok "Baseline: $(wc -l < "$FIM_DB") files"

        # Create monitor script
        cat > "$FIM_DIR/check.sh" << 'FIMEOF'
#!/bin/bash
DB="/var/lib/fim/baseline.db"
[ ! -f "$DB" ] && exit 1
TMP="/tmp/fim_$$"
for t in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/crontab /etc/hosts /usr/bin /usr/sbin; do
    [ -d "$t" ] && find "$t" -type f -exec sha256sum {} \; >> "$TMP" 2>/dev/null
    [ -f "$t" ] && sha256sum "$t" >> "$TMP" 2>/dev/null
done
while read -r hash path; do
    cur=$(grep -F "$path" "$TMP" 2>/dev/null)
    [ -z "$cur" ] && logger -t FIM "DELETED: $path" && continue
    echo "$cur" | grep -qF "$hash" || logger -t FIM "MODIFIED: $path"
done < "$DB"
while read -r hash path; do
    grep -qF "$path" "$DB" || logger -t FIM "NEW: $path"
done < "$TMP"
rm -f "$TMP"
FIMEOF
        chmod +x "$FIM_DIR/check.sh"

        # Add cron
        CRON="*/5 * * * * /var/lib/fim/check.sh"
        (crontab -l 2>/dev/null | grep -v "fim/check"; echo "$CRON") | crontab -
        ok "FIM monitoring every 5 min (check: journalctl -t FIM)"
    fi
}

# =========================================================================
# MODES
# =========================================================================
mode_ccdc() {
    ok "MODE: CCDC Competition"
    backup_files
    change_passwords
    kill_persistence
    harden_ssh
    harden_kernel
    setup_firewall
    user_lockdown
    audit_cron
    setup_logging
    setup_fim

    echo ""
    echo -e "${P}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo -e "${P}  Lockdown Complete!${N}"
    echo -e "${P}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo ""
    warn "Things to still do manually:"
    warn "  - Verify ALL scored services are still running"
    warn "  - Check for web apps in /var/www or /srv"
    warn "  - Look at service-specific configs (Apache, Postfix, etc)"
}

mode_passwords() {
    ok "MODE: Password Changes Only"
    backup_files
    change_passwords
}

usage() {
    echo "Usage: sudo $0 [option]"
    echo "  -c    CCDC competition mode (full lockdown)"
    echo "  -p    Password changes only"
    echo "  -h    This help"
    exit 0
}

case "${1:-}" in
    -c) mode_ccdc ;;
    -p) mode_passwords ;;
    -h) usage ;;
    *)  usage ;;
esac
