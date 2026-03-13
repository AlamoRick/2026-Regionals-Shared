#!/bin/bash
# =============================================================================
# inventory.sh — Discover everything about this machine
# San Antonio College — SWCCDC 2026
#
# This is your FIRST MOVE on every Linux box. It discovers:
#   - What OS, what distro, what kernel
#   - What IP addresses and network config
#   - What ports are listening (these are your scored services)
#   - What users exist and who has sudo
#   - What services are running
#   - What cron jobs exist
#   - SSH config, firewall state, suspicious files
#
# Run this, save the output, paste it into AI if needed.
#
# Usage: sudo ./inventory.sh [-o filename]
# =============================================================================

set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo ./inventory.sh"
    exit 1
fi

# Colors
G='\033[1;32m'  # green
C='\033[1;36m'  # cyan
Y='\033[1;33m'  # yellow
R='\033[1;31m'  # red
B='\033[1m'     # bold
N='\033[0m'     # reset

header()    { echo -e "\n${G}══════════════════════════════════════${N}"; echo -e "${G}  $1${N}"; echo -e "${G}══════════════════════════════════════${N}"; }
subheader() { echo -e "${C}  ▶ $1${N}"; }
info()      { echo -e "    ${B}$1:${N} $2"; }
warn()      { echo -e "    ${Y}⚠ $1${N}"; }
bad()       { echo -e "    ${R}✖ $1${N}"; }
ok()        { echo -e "    ${G}✔ $1${N}"; }

# Handle -o flag for saving to file
OUTPUT_FILE=""
while getopts "o:" opt; do
    case $opt in
        o) OUTPUT_FILE="$OPTARG" ;;
    esac
done

if [ -n "$OUTPUT_FILE" ]; then
    exec > >(tee "$OUTPUT_FILE") 2>&1
    echo "Saving output to: $OUTPUT_FILE"
fi

echo -e "${G}╔══════════════════════════════════════╗${N}"
echo -e "${G}║   Linux Asset Inventory              ║${N}"
echo -e "${G}║   San Antonio College — SWCCDC 2026  ║${N}"
echo -e "${G}╚══════════════════════════════════════╝${N}"

# =========================================================================
# 1. SYSTEM OVERVIEW
# =========================================================================
header "System Overview"

info "Hostname" "$(hostname 2>/dev/null || echo Unknown)"

if [ -f /etc/os-release ]; then
    info "OS" "$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
fi

info "Kernel" "$(uname -r)"
info "Architecture" "$(uname -m)"
info "Uptime" "$(uptime -p 2>/dev/null || uptime)"
info "Time" "$(date '+%Y-%m-%d %H:%M:%S %Z')"

# =========================================================================
# 2. NETWORK — This tells you what services to protect
# =========================================================================
header "Network Configuration"

subheader "IP Addresses"
if command -v ip >/dev/null 2>&1; then
    ip -4 addr show | grep inet | awk '{print "    " $2, $NF}'
else
    ifconfig 2>/dev/null | grep "inet " | awk '{print "    " $2}'
fi

subheader "Default Gateway"
if command -v ip >/dev/null 2>&1; then
    gw=$(ip route | awk '/default/ {print $3; exit}')
    echo "    ${gw:-Not set}"
else
    route -n 2>/dev/null | awk '/^0.0.0.0/ {print "    " $2}'
fi

subheader "DNS Servers"
if [ -f /etc/resolv.conf ]; then
    grep "^nameserver" /etc/resolv.conf | awk '{print "    " $2}'
else
    warn "/etc/resolv.conf not found"
fi

subheader "Listening Ports — THESE ARE YOUR SCORED SERVICES"
echo ""
echo "    Proto  Local Address          Process"
echo "    ─────  ─────────────────────  ───────────────────"
if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>/dev/null | awk 'NR>1 {printf "    %-6s %-22s %s\n", $1, $5, $7}'
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulnp 2>/dev/null | awk '/LISTEN|udp/ {printf "    %-6s %-22s %s\n", $1, $4, $7}'
fi

subheader "Firewall Status"
if command -v ufw >/dev/null 2>&1; then
    info "UFW" "$(ufw status 2>/dev/null | head -1)"
fi
if command -v firewall-cmd >/dev/null 2>&1; then
    info "firewalld" "$(firewall-cmd --state 2>/dev/null || echo not running)"
fi
if command -v iptables >/dev/null 2>&1; then
    rules=$(iptables -L 2>/dev/null | grep -cE "^(ACCEPT|DROP|REJECT)" || true)
    info "iptables" "${rules:-0} active rules"
fi
if command -v nft >/dev/null 2>&1; then
    info "nftables" "$(nft list tables 2>/dev/null | wc -l) tables"
fi

# =========================================================================
# 3. USERS — Who can log in, who has sudo
# =========================================================================
header "Users & Access"

subheader "Users with login shells"
while IFS=: read -r user _ uid _ _ home shell; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
        echo "    $user  (UID:$uid)  Home:$home  Shell:$shell"
    fi
done < /etc/passwd

subheader "Root and system accounts with shells"
while IFS=: read -r user _ uid _ _ _ shell; do
    if [ "$uid" -lt 1000 ] 2>/dev/null && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ] && [ "$shell" != "/sbin/nologin" ]; then
        echo "    $user  (UID:$uid)  Shell:$shell"
    fi
done < /etc/passwd

subheader "Sudo / Wheel / Admin group members"
for g in sudo wheel admin docker; do
    entry=$(getent group "$g" 2>/dev/null)
    [ -n "$entry" ] && echo "    $entry"
done

subheader "Sudoers file (non-comment lines)"
grep -vE '^#|^$|^Defaults' /etc/sudoers 2>/dev/null | awk '{print "    " $0}'
for f in /etc/sudoers.d/*; do
    [ -f "$f" ] && echo "    [$f]:" && grep -vE '^#|^$' "$f" 2>/dev/null | awk '{print "      " $0}'
done

subheader "Currently logged in"
w 2>/dev/null || who 2>/dev/null

subheader "Recent logins (last 10)"
last -10 2>/dev/null | head -12

subheader "Failed login attempts"
if command -v lastb >/dev/null 2>&1; then
    count=$(lastb 2>/dev/null | grep -vc "^$\|begins" || echo 0)
    info "Total failed attempts" "$count"
    lastb 2>/dev/null | head -5
fi

# =========================================================================
# 4. SERVICES — What's running
# =========================================================================
header "Running Services"

subheader "Service detection"
check_proc() { pgrep -f "$1" >/dev/null 2>&1 && echo -e "    ${G}✔${N}  $2"; }

check_proc "sshd"         "SSH: OpenSSH"
check_proc "apache2\|httpd" "Web: Apache"
check_proc "nginx"        "Web: Nginx"
check_proc "named"        "DNS: BIND"
check_proc "dnsmasq"      "DNS: dnsmasq"
check_proc "postfix"      "Mail: Postfix"
check_proc "dovecot"      "Mail: Dovecot (IMAP/POP3)"
check_proc "sendmail"     "Mail: Sendmail"
check_proc "exim"         "Mail: Exim"
check_proc "mysqld\|mariadbd" "Database: MySQL/MariaDB"
check_proc "postgres"     "Database: PostgreSQL"
check_proc "mongod"       "Database: MongoDB"
check_proc "vsftpd"       "FTP: vsftpd"
check_proc "proftpd"      "FTP: ProFTPD"
check_proc "slapd"        "LDAP: OpenLDAP"
check_proc "smbd"         "SMB: Samba"
check_proc "dockerd"      "Container: Docker"
check_proc "splunkd"      "SIEM: Splunk"
check_proc "gitlab"       "CI/CD: GitLab"
check_proc "jenkins"      "CI/CD: Jenkins"
check_proc "minecraft"    "Game: Minecraft Server"

if command -v systemctl >/dev/null 2>&1; then
    subheader "All running systemd services"
    systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep ".service" | awk '{print "    " $0}' | head -30

    subheader "Failed services"
    failed=$(systemctl list-units --type=service --state=failed --no-pager 2>/dev/null | grep ".service" || true)
    if [ -n "$failed" ]; then
        echo -e "${R}$failed${N}" | awk '{print "    " $0}'
    else
        ok "No failed services"
    fi
fi

# =========================================================================
# 5. SECURITY SNAPSHOT
# =========================================================================
header "Security Snapshot"

subheader "SSH config"
sshd="/etc/ssh/sshd_config"
if [ -f "$sshd" ]; then
    for key in PermitRootLogin PasswordAuthentication PermitEmptyPasswords X11Forwarding MaxAuthTries; do
        val=$(grep -i "^$key" "$sshd" 2>/dev/null | awk '{print $2}' || echo "not set (using default)")
        info "$key" "$val"
    done
fi

subheader "SSH authorized_keys files"
found=0
for d in /root /home/*; do
    if [ -f "$d/.ssh/authorized_keys" ]; then
        found=1
        bad "FOUND: $d/.ssh/authorized_keys ($(wc -l < "$d/.ssh/authorized_keys") keys)"
    fi
done
[ "$found" -eq 0 ] && ok "No authorized_keys files found"

subheader "Cron jobs (non-comment)"
for f in /etc/crontab /etc/cron.d/*; do
    if [ -f "$f" ]; then
        content=$(grep -vE '^#|^$|^PATH|^SHELL|^MAILTO' "$f" 2>/dev/null || true)
        if [ -n "$content" ]; then
            echo "    [$f]"
            echo "$content" | awk '{print "      " $0}'
        fi
    fi
done
for uc in /var/spool/cron/crontabs/* /var/spool/cron/*; do
    if [ -f "$uc" ]; then
        echo "    [User crontab: $(basename "$uc")]"
        grep -vE '^#|^$' "$uc" 2>/dev/null | awk '{print "      " $0}'
    fi
done

subheader "SUID binaries in unusual locations"
suid=$(find /home /tmp /var/tmp /opt /usr/local -maxdepth 5 -perm -4000 -type f 2>/dev/null)
if [ -n "$suid" ]; then
    echo "$suid" | awk '{print "    " $0}'
else
    ok "None found in /home /tmp /opt /usr/local"
fi

subheader "Executable files in /tmp"
tmp_exec=$(find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null)
if [ -n "$tmp_exec" ]; then
    bad "Executable files in temp directories:"
    echo "$tmp_exec" | awk '{print "    " $0}'
else
    ok "No executables in /tmp"
fi

subheader "World-writable files in /etc"
ww=$(find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | head -10)
if [ -n "$ww" ]; then
    bad "World-writable files:"
    echo "$ww" | awk '{print "    " $0}'
else
    ok "None found"
fi

# =========================================================================
# DONE
# =========================================================================
echo ""
echo -e "${G}══════════════════════════════════════${N}"
echo -e "${G}  Inventory Complete${N}"
echo -e "${G}══════════════════════════════════════${N}"
echo ""
echo "TIP: Paste this output into Claude/ChatGPT with the prompt:"
echo '  "I am in a CCDC competition. Here is the inventory of one of'
echo '   my Linux machines. What are the scored services? What should'
echo '   I harden first? What looks suspicious?"'
