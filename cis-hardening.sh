#!/usr/bin/env bash
# CIS Hardening Script for Linux Servers
# Supports: RHEL/CentOS/Rocky/Alma Linux 8/9, Ubuntu 20.04/22.04+
# Reference: CIS Benchmarks
# WARNING: Test in non-production environment first!

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging
LOGFILE="/var/log/cis_hardening_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

echo -e "${GREEN}===== CIS Linux Hardening Started: $(date) =====${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}This script must be run as root.${NC}"
  exit 1
fi

# Detect OS
if grep -qi 'ubuntu' /etc/os-release; then
  OS_FAMILY="debian"
  OS_NAME="Ubuntu"
elif grep -qi -e 'rhel' -e 'centos' -e 'rocky' -e 'almalinux' /etc/os-release; then
  OS_FAMILY="rhel"
  OS_NAME="RHEL-based"
else
  echo -e "${RED}Unsupported Linux distribution${NC}"
  exit 1
fi

echo -e "${GREEN}[*] Detected: $OS_NAME ($OS_FAMILY)${NC}"

# Function to run tests
log_test() {
  echo -e "${YELLOW}[*] $1${NC}"
}

log_success() {
  echo -e "${GREEN}[✓] $1${NC}"
}

log_fail() {
  echo -e "${RED}[✗] $1${NC}"
}

# ========== 1. SYSTEM UPDATES ==========
log_test "Updating system packages"
if [[ "$OS_FAMILY" == "debian" ]]; then
  apt-get update -y
  apt-get upgrade -y
else
  dnf update -y 2>/dev/null || yum update -y
fi
log_success "System packages updated"

# ========== 2. INSTALL REQUIRED PACKAGES ==========
log_test "Installing security and monitoring packages"
if [[ "$OS_FAMILY" == "debian" ]]; then
  apt-get install -y \
    aid aide-common chrony \
    openssh-server openssh-client \
    fail2ban rsyslog \
    net-tools wget curl
else
  dnf install -y aide chrony openssh-server openssh-clients \
    fail2ban rsyslog net-tools wget curl 2>/dev/null || \
  yum install -y aide chrony openssh-server openssh-clients \
    fail2ban rsyslog net-tools wget curl
fi
log_success "Security packages installed"

# ========== 3. TIME SYNCHRONIZATION ==========
log_test "Configuring NTP/Chrony"
if [[ "$OS_FAMILY" == "debian" ]]; then
  systemctl enable --now chrony
else
  systemctl enable --now chronyd
fi
log_success "Time synchronization configured"

# ========== 4. FILESYSTEM HARDENING ==========
log_test "Hardening filesystem mounts"

# Check and add mount options to /etc/fstab
if ! grep -q '/tmp.*noexec' /etc/fstab; then
  echo 'tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime' >> /etc/fstab
  mount -o remount,noexec /tmp
fi

if ! grep -q '/var/tmp.*noexec' /etc/fstab; then
  echo 'tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime' >> /etc/fstab
  mount -o remount,noexec /var/tmp
fi

log_success "Filesystem mounts hardened"

# ========== 5. DISABLE UNCOMMON FILESYSTEMS ==========
log_test "Disabling uncommon filesystems"
for fs in cramfs freevxfs jffs2 hfs hfsplus udf vfat; do
  echo "install $fs /bin/true" >> /etc/modprobe.d/uncommon-fs.conf
done
log_success "Uncommon filesystems disabled"

# ========== 6. KERNEL PARAMETERS (SYSCTL) ==========
log_test "Applying kernel security parameters"
cat > /etc/sysctl.d/99-cis-hardening.conf << 'EOF'
# IP forwarding (disable unless needed)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Accept redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ICMP settings
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# TCP hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

# Randomize memory addresses
kernel.randomize_va_space = 2

# Core dumps
kernel.core_uses_pid = 1
fs.suid_dumpable = 0

# Process accounting
kernel.sysrq = 0
EOF

sysctl -p /etc/sysctl.d/99-cis-hardening.conf > /dev/null
log_success "Kernel parameters applied"

# ========== 7. SUDO CONFIGURATION ==========
log_test "Configuring sudo with secure defaults"
mkdir -p /etc/sudoers.d
cat > /etc/sudoers.d/cis-hardening << 'EOF'
Defaults use_pty
Defaults log_input, log_output
Defaults requiretty
EOF
chmod 440 /etc/sudoers.d/cis-hardening
log_success "Sudo hardened"

# ========== 8. SSH HARDENING ==========
log_test "Hardening SSH configuration"
cat >> /etc/ssh/sshd_config << 'EOF'
# CIS Hardening
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
PermitUserEnvironment no
Compression delayed
UsePAM yes
EOF

systemctl restart sshd
log_success "SSH hardened"

# ========== 9. FILE INTEGRITY MONITORING (AIDE) ==========
log_test "Initializing AIDE database (this may take a while)..."
if command -v aide &> /dev/null; then
  aideinit 2>/dev/null || true
  log_success "AIDE initialized"
else
  log_fail "AIDE not available"
fi

# ========== 10. FIREWALL CONFIGURATION ==========
log_test "Configuring firewall"
if [[ "$OS_FAMILY" == "debian" ]]; then
  apt-get install -y ufw
  ufw --force enable
  ufw default deny incoming
  ufw default allow outgoing
  log_success "UFW firewall enabled"
else
  systemctl enable firewalld
  systemctl start firewalld
  log_success "Firewalld firewall enabled"
fi

# ========== 11. DISABLE UNNECESSARY SERVICES ==========
log_test "Disabling unnecessary services"
for service in avahi cups bluetooth; do
  systemctl disable "$service" 2>/dev/null || true
  systemctl stop "$service" 2>/dev/null || true
done
log_success "Unnecessary services disabled"

# ========== 12. AUDITD/LOGGING CONFIGURATION ==========
log_test "Configuring audit daemon"
if [[ "$OS_FAMILY" == "debian" ]]; then
  apt-get install -y auditd audispd-plugins
else
  dnf install -y audit 2>/dev/null || yum install -y audit
fi

cat >> /etc/audit/rules.d/cis.rules << 'EOF'
# CIS Audit Rules
-w /sbin/insmod -p x
-w /sbin/rmmod -p x
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-w /var/log/faillog -p wa
-w /var/log/lastlog -p wa
-w /var/log/tallylog -p wa
-w /var/run/utmp -p wa
-w /var/log/wtmp -p wa
-w /var/log/btmp -p wa
EOF

systemctl enable auditd
systemctl restart auditd
log_success "Audit daemon configured"

# ========== 13. RSYSLOG CONFIGURATION ==========
log_test "Securing rsyslog configuration"
chmod 640 /etc/rsyslog.conf
systemctl restart rsyslog
log_success "Rsyslog secured"

# ========== 14. PERMISSION HARDENING ==========
log_test "Hardening file permissions"
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
log_success "File permissions hardened"

# ========== 15. AIDE DATABASE VALIDATION ==========
log_test "Creating AIDE cron job for regular integrity checks"
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --config=/etc/aide/aide.conf.d/aide.conf --check >> /var/log/aide-check.log 2>&1
EOF
chmod 755 /etc/cron.daily/aide-check
log_success "AIDE cron job created"

# ========== 16. PAM CONFIGURATION ==========
log_test "Hardening PAM configuration"
if [[ "$OS_FAMILY" == "debian" ]]; then
  apt-get install -y libpam-pwquality
else
  dnf install -y libpwquality 2>/dev/null || yum install -y libpwquality
fi

cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
EOF

log_success "PAM hardened"

# ========== 17. UMASK SETTINGS ==========
log_test "Setting secure umask"
echo 'umask 0027' >> /etc/profile
echo 'umask 0027' >> /etc/bashrc
log_success "Umask hardened"

# ========== 18. GENERATE SUMMARY ==========
echo ""
echo -e "${GREEN}===== CIS Hardening Completed =====${NC}"
echo -e "${GREEN}Log file: $LOGFILE${NC}"
echo ""
echo -e "${YELLOW}Post-hardening recommendations:${NC}"
echo "1. Review and test SSH key-based authentication"
echo "2. Verify firewall rules don't block required services"
echo "3. Check AIDE and audit log output regularly"
echo "4. Schedule regular updates and security patches"
echo "5. Review this script and customize for your environment"
echo ""
log_success "Hardening script execution completed successfully!"
