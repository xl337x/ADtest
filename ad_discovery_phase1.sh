#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
    ____  __                       ___          ____  _                                 
   / __ \/ /_  ____ _________     <  /         / __ \(_)_____________ _   _____  _______  __
  / /_/ / __ \/ __ `/ ___/ _ \    / /         / / / / / ___/ ___/ __ \ | / / _ \/ ___/ / / /
 / ____/ / / / /_/ (__  )  __/   / /         / /_/ / (__  ) /__/ /_/ / |/ /  __/ /  / /_/ / 
/_/   /_/ /_/\__,_/____/\___/   /_/ ________/_____/_/____/\___/\____/|___/\___/_/   \__, /  
                                    /_____/                                         /____/   
EOF
echo -e "${NC}"
echo -e "${CYAN}Active Directory Discovery & Information Gathering${NC}\n"

# Function to get all active network interfaces with IPs (excluding loopback and docker)
get_interfaces() {
    ip -4 addr show | grep -E "^[0-9]+:" | grep -v "lo:" | grep -v "docker" | while read line; do
        iface=$(echo "$line" | awk '{print $2}' | tr -d ':')
        ip_info=$(ip -4 addr show "$iface" | grep "inet " | awk '{print $2}')
        if [ ! -z "$ip_info" ]; then
            echo "$iface|$ip_info"
        fi
    done
}

# Get interfaces
interfaces=($(get_interfaces))

if [ ${#interfaces[@]} -eq 0 ]; then
    echo -e "${RED}[!] No active network interfaces found${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Available Network Interfaces:${NC}"
for i in "${!interfaces[@]}"; do
    IFS='|' read -r iface ip <<< "${interfaces[$i]}"
    echo -e "  ${YELLOW}[$((i+1))]${NC} $iface - $ip"
done

echo ""
echo -e "${YELLOW}[?] Select mode:${NC}"
echo "  [1] Manual selection"
echo "  [2] Automatic (scan all interfaces)"
read -p "Choice [1/2]: " mode_choice

selected_interfaces=()

if [ "$mode_choice" == "1" ]; then
    read -p "Enter interface number(s) separated by space (e.g., 1 2): " choices
    for choice in $choices; do
        idx=$((choice-1))
        if [ $idx -ge 0 ] && [ $idx -lt ${#interfaces[@]} ]; then
            selected_interfaces+=("${interfaces[$idx]}")
        fi
    done
elif [ "$mode_choice" == "2" ]; then
    selected_interfaces=("${interfaces[@]}")
else
    echo -e "${RED}[!] Invalid choice${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}=== Starting AD Discovery ===${NC}\n"

# Function to calculate network from CIDR
get_network() {
    local cidr=$1
    local ip=$(echo $cidr | cut -d'/' -f1)
    local prefix=$(echo $cidr | cut -d'/' -f2)
    
    # Convert to /24 or /23 for scanning
    local base=$(echo $ip | cut -d'.' -f1-3)
    
    if [ $prefix -ge 24 ]; then
        echo "${base}.0/24"
    else
        # For /23 or smaller, adjust accordingly
        local third_octet=$(echo $ip | cut -d'.' -f3)
        local network_third=$((third_octet & 254))
        echo "$(echo $ip | cut -d'.' -f1-2).${network_third}.0/23"
    fi
}

# Store all discovered DCs
declare -A all_dcs

# Scan each selected interface
for iface_info in "${selected_interfaces[@]}"; do
    IFS='|' read -r iface ip_cidr <<< "$iface_info"
    network=$(get_network "$ip_cidr")
    
    echo -e "${GREEN}[+] Scanning interface: ${YELLOW}$iface${NC} (Network: ${YELLOW}$network${NC})"
    
    # Quick port scan for DC services
    echo -e "${BLUE}[*] Discovering Domain Controllers...${NC}"
    echo -e "${CYAN}    CMD: ${NC}nmap -p 88,389,445 --open $network --min-rate 1000"
    echo -e "${CYAN}    DESC:${NC} Scanning for Kerberos(88), LDAP(389), SMB(445) to find Domain Controllers"
    echo ""
    
    # Use nmap to find DCs (ports 88=Kerberos, 389=LDAP, 445=SMB)
    dc_ips=$(sudo nmap -p 88,389,445 --open "$network" --min-rate 1000 -oG - 2>/dev/null | \
             awk '/88\/open.*389\/open.*445\/open/{print $2}')
    
    if [ -z "$dc_ips" ]; then
        echo -e "${RED}[!] No Domain Controllers found on $network${NC}\n"
        continue
    fi
    
    echo -e "${GREEN}[+] Found potential DCs: ${YELLOW}$dc_ips${NC}\n"
    
    # Enumerate each DC
    for dc_ip in $dc_ips; do
        if [ ! -z "${all_dcs[$dc_ip]}" ]; then
            continue  # Skip if already enumerated
        fi
        
        echo -e "${BLUE}[*] Enumerating DC: ${YELLOW}$dc_ip${NC}"
        
        # Get LDAP root DSE information
        echo -e "${CYAN}    CMD: ${NC}ldapsearch -x -H ldap://$dc_ip -b \"\" -s base"
        echo -e "${CYAN}    DESC:${NC} Querying LDAP root DSE for domain information (anonymous bind)"
        echo ""
        
        ldap_info=$(ldapsearch -x -H ldap://$dc_ip -b "" -s base \
                    defaultNamingContext dnsHostName configurationNamingContext \
                    2>/dev/null | grep -E "dnsHostName|defaultNamingContext|configurationNamingContext")
        
        if [ ! -z "$ldap_info" ]; then
            dns_hostname=$(echo "$ldap_info" | grep "dnsHostName:" | awk '{print $2}')
            domain=$(echo "$ldap_info" | grep "defaultNamingContext:" | head -1 | sed 's/defaultNamingContext: //' | sed 's/DC=//g' | sed 's/,/./g')
            
            all_dcs[$dc_ip]="$dns_hostname|$domain"
            
            echo -e "${GREEN}  [✓] DC Name: ${YELLOW}$dns_hostname${NC}"
            echo -e "${GREEN}  [✓] Domain: ${YELLOW}$domain${NC}"
            echo -e "${GREEN}  [✓] IP Address: ${YELLOW}$dc_ip${NC}"
        fi
        
        # Get additional SMB info using crackmapexec if available
        if command -v crackmapexec &> /dev/null; then
            echo -e "${CYAN}    CMD: ${NC}crackmapexec smb $dc_ip"
            echo -e "${CYAN}    DESC:${NC} Getting SMB information (OS version, signing status, SMBv1)"
            echo ""
            
            smb_info=$(crackmapexec smb $dc_ip 2>/dev/null | grep -E "name:|domain:|signing:")
            if [ ! -z "$smb_info" ]; then
                echo -e "${GREEN}  [✓] SMB Info:${NC}"
                echo "$smb_info" | sed 's/^/      /'
            fi
        fi
        
        echo ""
    done
done

# Save results to file
CONFIG_FILE="ad_target.conf"

echo -e "${BLUE}=== Saving Configuration ===${NC}\n"

if [ ${#all_dcs[@]} -eq 0 ]; then
    echo -e "${RED}[!] No Domain Controllers discovered${NC}"
    exit 1
fi

# Take the first DC found
for dc_ip in "${!all_dcs[@]}"; do
    IFS='|' read -r hostname domain <<< "${all_dcs[$dc_ip]}"
    
    cat > "$CONFIG_FILE" << EOF
# Active Directory Target Configuration
# Generated: $(date)
DC_IP="$dc_ip"
DC_NAME="$hostname"
DOMAIN="$domain"
DOMAIN_SHORT="$(echo $domain | cut -d'.' -f1)"
BASE_DN="$(echo $domain | sed 's/\./,DC=/g' | sed 's/^/DC=/')"
EOF
    
    echo -e "${GREEN}[+] Configuration saved to: ${YELLOW}$CONFIG_FILE${NC}"
    break  # Use first DC found
done

# Summary
echo ""
echo -e "${BLUE}=== Discovery Summary ===${NC}\n"

echo -e "${GREEN}[+] Total Domain Controllers Found: ${YELLOW}${#all_dcs[@]}${NC}\n"

for dc_ip in "${!all_dcs[@]}"; do
    IFS='|' read -r hostname domain <<< "${all_dcs[$dc_ip]}"
    echo -e "${YELLOW}DC:${NC} $hostname"
    echo -e "${YELLOW}IP:${NC} $dc_ip"
    echo -e "${YELLOW}Domain:${NC} $domain"
    echo ""
done

echo -e "${GREEN}[+] Phase 1 Complete!${NC}"
echo -e "${CYAN}[→] Run Phase 2 enumeration script with: ${YELLOW}./ad_enum_phase2.sh${NC}\n"
