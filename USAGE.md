# CIS Hardening Script - Usage Guide

## Quick Start

### Prerequisites
- Root access required
- Supported Systems:
  - Red Hat Enterprise Linux (RHEL) 8/9
  - CentOS 8/9
  - Rocky Linux 8/9
  - AlmaLinux 8/9
  - Ubuntu 20.04 LTS / 22.04 LTS

### Installation

```bash
# Clone the repository
git clone https://github.com/Manjunathsmurthy/linux-cis-hardening.git
cd linux-cis-hardening

# Make the script executable
chmod +x cis-hardening.sh
```

### Running the Script

```bash
# Run as root (recommended in test environment first)
sudo ./cis-hardening.sh

# Or with explicit root
su -c './cis-hardening.sh'
```

## What This Script Does

The script implements CIS Benchmark hardening controls including:

### 1. System Updates
- Updates all system packages to latest security patches
- Ensures kernel is current

### 2. Security Packages
- Installs AIDE (file integrity monitoring)
- Installs Chrony/NTP (time synchronization)
- Installs auditd (audit daemon)
- Installs fail2ban (intrusion prevention)
- Installs firewall (UFW for Debian, firewalld for RHEL)

### 3. Kernel Hardening
- Disables IP forwarding
- Disables ICMP redirects
- Enables TCP SYN cookies
- Enables ASLR (Address Space Layout Randomization)
- Disables core dumps with SUID

### 4. Filesystem Hardening
- Makes /tmp noexec, nosuid, nodev
- Makes /var/tmp noexec, nosuid, nodev
- Disables uncommon filesystems (cramfs, freevxfs, etc.)

### 5. SSH Hardening
- Disables root login
- Enables public key authentication only
- Disables password authentication
- Disables X11 forwarding
- Sets connection limits
- Enables client keep-alive

### 6. File Integrity Monitoring (AIDE)
- Initializes AIDE database
- Creates daily cron job for integrity checks
- Logs to /var/log/aide-check.log

### 7. Audit Configuration
- Enables auditd service
- Adds rules for system call monitoring
- Monitors file access and modifications

### 8. Access Control
- Hardens sudo configuration
- Restricts sudo session behavior
- Enables session logging

### 9. Authentication Hardening
- Sets password quality requirements:
  - Minimum 14 characters
  - Must include uppercase letters
  - Must include lowercase letters
  - Must include numbers
  - Must include special characters
  - Maximum 3 repeated characters

## Important Notes

### Before Running

1. **TEST IN NON-PRODUCTION FIRST**
   - Test on a development/lab system first
   - Verify all services work after hardening
   - Document any service issues

2. **SSH Configuration**
   - Ensure you have SSH public key authentication working
   - Do NOT disable password auth until key-based auth is verified
   - Risk of lockout if not properly configured

3. **Firewall Rules**
   - Review firewall configuration after script
   - Add exceptions for required services
   - Document all firewall rules changes

4. **Password Policies**
   - Change your password to meet new requirements
   - Ensure users understand new password policy
   - Plan for password reset in production

### Post-Installation Checklist

- [ ] Review SSH keys are working
- [ ] Verify firewall allows required ports
- [ ] Check AIDE log: `tail -f /var/log/aide-check.log`
- [ ] Review audit logs: `ausearch -ts today`
- [ ] Test sudo access
- [ ] Verify time synchronization: `timedatectl`
- [ ] Check system updates available: `apt list --upgradable` or `dnf list upgrades`
- [ ] Review kernel parameters: `sysctl -a | grep -E "net\.ipv4|kernel\.randomize"`

## Logs and Monitoring

### Main Log File
```bash
ls -lt /var/log/cis_hardening_*.log
tail -f /var/log/cis_hardening_*.log
```

### File Integrity
```bash
tail -f /var/log/aide-check.log
```

### Audit Logs
```bash
ausearch -ts today
auditctl -l  # List current rules
```

### Firewall Status

For Ubuntu/Debian (UFW):
```bash
ufw status
ufw status verbose
```

For RHEL/CentOS (firewalld):
```bash
firewall-cmd --list-all
firewall-cmd --list-all --permanent
```

## Customization

### Modifying SSH Settings
Edit the SSH section in the script to:
- Enable password auth if needed
- Add additional options
- Customize port (non-standard)

### Adjusting Firewall Rules
After running the script:

UFW (Ubuntu):
```bash
ufw allow 22/tcp  # SSH
ufw allow 80/tcp  # HTTP
ufw allow 443/tcp # HTTPS
```

Firewalld (RHEL):
```bash
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

### Disabling Features
Comment out sections in the script if you need to:
- Skip SSH hardening (comment section 8)
- Skip firewall setup (comment section 10)
- Skip AIDE (comment section 9)

## Troubleshooting

### Service Issues After Running

**SSH locked out:**
- Boot into recovery mode
- Mount filesystem read-write
- Edit /etc/ssh/sshd_config
- Restart SSH: `systemctl restart sshd`

**Firewall blocking traffic:**
```bash
# UFW
ufw allow FROM_IP_HERE to any port SERVICE_PORT

# Firewalld
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="FROM_IP_HERE" port protocol="tcp" port="SERVICE_PORT" accept'
```

**AIDE database too large:**
Reconfigure AIDE to exclude directories:
```bash
edit /etc/aide/aide.conf
aideinit
```

## Support and References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Ubuntu Security Documentation](https://wiki.ubuntu.com/SecurityTeam)
- [RHEL Security Guide](https://access.redhat.com/documentation/)
- [Linux Hardening Best Practices](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)

## License

MIT License - See LICENSE file

## Disclaimer

This script provides security hardening recommendations based on CIS Benchmarks. Always test thoroughly in your environment before production deployment. The author assumes no liability for any issues resulting from the use of this script.
