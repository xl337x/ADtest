# Active Directory Enumeration Toolkit

A comprehensive two-phase Active Directory enumeration toolkit for penetration testing and security assessments.

## Overview

This toolkit consists of two main scripts:
1. **Phase 1**: Discovery - Automatically detects Domain Controllers and gathers basic information
2. **Phase 2**: Enumeration - Performs comprehensive AD enumeration with detailed logging
also the ADPentestV2.html html file enable you to generate massive AD commands that you maybe need it,give it a look🤠
<img width="1876" height="904" alt="image" src="https://github.com/user-attachments/assets/7021266a-d258-4828-b028-1f1e740b224a" />

## Features

### Phase 1: Discovery (`ad_discovery_phase1.sh`)
- Auto-detects network interfaces
- Scans for Domain Controllers (Kerberos, LDAP, SMB)
- Gathers DC hostname, IP, and domain information
- Saves configuration for Phase 2

### Phase 2: Enumeration (`ad_enum_phase2.sh`)
- **Unauthenticated Enumeration**:
  - RPC null session enumeration
  - LDAP anonymous bind checks
  - DNS zone transfers
  - SMB null session shares
  - ASREPRoast attack (unauthenticated)

- **Authenticated Enumeration**:
  - Complete user/group/computer enumeration
  - Password policy extraction
  - Privileged group membership
  - Kerberoasting (SPN extraction)
  - Share enumeration + SYSVOL spider
  - Domain trust enumeration
  - GPO enumeration
  - BloodHound data collection
  - Vulnerability checks (EternalBlue, ZeroLogon, PetitPotam, noPac)

### Output Features
- Organized directory structure
- **ENUMERATION_REPORT.txt** - Summary with critical findings highlighted
- **COMMANDS_EXECUTED.txt** - Complete log of all commands run
- Individual category folders (users, groups, computers, shares, etc.)
- BloodHound-ready data collection

## Installation

### Required Tools
```bash
# Core tools
sudo apt install -y nmap ldap-utils smbclient rpcclient enum4linux-ng crackmapexec

# Python tools
sudo apt install -y python3-pip
pip3 install bloodhound impacket

# Optional but recommended
sudo apt install -y tree
```

### Download Scripts
```bash
chmod +x ad_discovery_phase1.sh ad_enum_phase2.sh
```

## Usage

### Phase 1: Discovery
```bash
sudo ./ad_discovery_phase1.sh
```

**Interactive prompts:**
1. Select network interface(s) or automatic scan
2. Script auto-detects DCs and saves to `ad_target.conf`

### Phase 2: Enumeration
```bash
sudo ./ad_enum_phase2.sh
```

**Interactive prompts:**
1. Reads `ad_target.conf` from Phase 1
2. Choose authentication method:
   - Unauthenticated (null session)
   - Username + Password
   - Username + NTLM Hash

### Example Workflow
```bash
# Step 1: Discovery
sudo ./ad_discovery_phase1.sh
# Select interface 2 (172.16.5.225/23)
# Discovers: DC=172.16.5.5, Domain=INLANEFREIGHT.LOCAL

# Step 2: Enumeration (unauthenticated first)
sudo ./ad_enum_phase2.sh
# Choice: [1] Unauthenticated

# Step 3: Re-run with credentials if obtained
sudo ./ad_enum_phase2.sh
# Choice: [2] Username + Password
# Username: INLANEFREIGHT\user
# Password: ********
```

## Output Structure

```
ad_enum_YYYYMMDD_HHMMSS/
├── ENUMERATION_REPORT.txt      # Summary report with findings
├── COMMANDS_EXECUTED.txt        # All commands that were run
├── users/                       # User enumeration results
│   ├── userlist.txt
│   ├── users_password_desc.txt  # Users with passwords in description
│   └── ...
├── groups/                      # Group enumeration
│   ├── privileged_groups.txt
│   └── ...
├── computers/                   # Computer enumeration
├── kerberos/                    # Attack hashes
│   ├── asreproast.txt          # AS-REP hashes for cracking
│   └── kerberoast_hashes.txt   # TGS hashes for cracking
├── shares/                      # SMB shares and files
│   └── sysvol_spider.txt
├── bloodhound/                  # BloodHound JSON/ZIP files
├── vulnerabilities/             # CVE check results
└── misc/                        # Domain info, trusts, GPOs, DNS

```

## Key Features Explained

### Command Logging
Every command executed is logged to `COMMANDS_EXECUTED.txt` with:
- Description of what the command does
- Full command syntax
- Timestamp

### Critical Findings Detection
The report automatically highlights:
- **CRITICAL**: Passwords in user descriptions
- **CRITICAL**: Privileged accounts that are Kerberoastable
- **HIGH**: ASREPRoastable accounts
- **HIGH**: Kerberoastable accounts (SPNs)
- **MEDIUM**: LDAP anonymous bind allowed
- **MEDIUM**: DNS zone transfers allowed

### Kerberos Attacks
- **ASREPRoasting**: Finds accounts without Kerberos pre-authentication
- **Kerberoasting**: Extracts TGS tickets for offline cracking
- Output ready for hashcat/john

### BloodHound Integration
Automatically collects:
- Users, Groups, Computers
- Group memberships
- ACLs and permissions
- Trust relationships
- Session information

## Post-Enumeration

### Crack Kerberos Hashes
```bash
# ASREPRoast
hashcat -m 18200 kerberos/asreproast.txt wordlist.txt

# Kerberoast
hashcat -m 13100 kerberos/kerberoast_hashes.txt wordlist.txt
```

### Import to BloodHound
```bash
# Start Neo4j
sudo neo4j start

# Import data
bloodhound

# Upload the .zip files from bloodhound/ folder
```

### Analyze Shares
```bash
# Review interesting files found
cat shares/sysvol_spider.txt

# Access readable shares
smbclient //DC-IP/ShareName -U DOMAIN\\username
```

## Troubleshooting

### CrackMapExec Modules Fail to Load

**Error:** `Failed loading module: No module named 'pylnk3'`

**Solution:**
```bash
# Install the missing dependency
pip3 install pylnk3 --break-system-packages

# Verify it works
crackmapexec smb <target> -u user -p pass -M ms17-010
```

**Note:** The script will automatically fall back to Nmap vulnerability scans if CME modules fail.

### BloodHound Collection Fails
```bash
# Check the log
cat ad_enum_*/bloodhound/collection.log

# Common issue: DNS resolution
# Fix: Add DC to /etc/hosts
echo "172.16.5.5 DC01.domain.local" | sudo tee -a /etc/hosts
```

### Missing Modules (crackmapexec)
```bash
# Check what modules are available
crackmapexec smb -L

# Install missing dependencies
pip3 install pylnk3 --break-system-packages

# Or use alternative vulnerability scanners (already included)
# The script automatically uses Nmap as fallback
```

### Permission Denied
Always run with `sudo` for:
- Network scanning (nmap)
- Low-level network operations
- BloodHound collection

### No Domain Controllers Found

**Check network connectivity:**
```bash
# Ping the network
ping 172.16.5.5

# Check if ports are open
nmap -p 88,389,445 172.16.5.5

# Verify you're on the correct network
ip a
```

### LDAP/RPC Queries Fail

**Possible causes:**
- Firewall blocking
- Network segmentation
- Credentials invalid
- Anonymous access disabled (expected on hardened environments)

**Solution:** Try with valid credentials in Phase 2

## Security & Ethics

⚠️ **WARNING**: This toolkit is for authorized security assessments only.

- Only use on systems you have explicit permission to test
- Obtain written authorization before any penetration test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## Credits

Built using industry-standard tools:
- Impacket (SecureAuth)
- CrackMapExec
- BloodHound (SpecterOps)
- enum4linux-ng
- Standard Linux utilities (nmap, ldapsearch, rpcclient)

## License

For educational and authorized security testing purposes only.

## Support

For issues or improvements:
1. Check the `ENUMERATION_REPORT.txt` for errors
2. Review `COMMANDS_EXECUTED.txt` to see what ran
3. Check individual output files for tool-specific errors

## Version History

- v1.0 - Initial two-phase enumeration toolkit
  - Discovery phase with auto-detection
  - Comprehensive enumeration phase
  - Command logging and critical findings detection
 
for the ADPentestV2.html
