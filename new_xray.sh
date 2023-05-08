#!/usr/bin/env bash


# Colors
Color_Off='\033[0m'
Black='\033[0;30m'
Red='\033[0;31m'
Green='\033[0;32m'
Yellow='\033[0;33m'
Blue='\033[0;34m'
Purple='\033[0;35m'
Cyan='\033[0;36m'
White='\033[0;37m'

# Constants
XRAY_CONFIG_DIRECTORY="/usr/local/etc/xray"
XRAY_CONFIG_FILE="$XRAY_CONFIG_DIRECTORY/config.json"
XRAY_BACKUP_CONFIG_FILE="$XRAY_CONFIG_DIRECTORY/config.json.bak"
XRAY_TEMP_CONFIG_FILE="$XRAY_CONFIG_DIRECTORY/config_tmp.json"
XRAY_BACKUP_DIRECTORY="/root/xray_backup"
XRAY_SSL_CERTIFICATE_OWNERSHIP_GROUP="nobody"
XRAY_DOMAIN_NAME_FILE="$XRAY_CONFIG_DIRECTORY/domain.txt"

NGINX_CONFIG_FILE_PATH="/etc/nginx/sites-available/default"
FAKE_WEBSITE_DIRECTORY="/var/www/html" 

SLEEP="sleep 0.2"

OK="${Green}[OK]"
ERROR="${Red}[ERROR]"
INFO="${Yellow}[INFO]"


#print OK
function print_ok() {
    echo -e "${OK} $1 ${Color_Off}"
}


#print ERROR
function print_error() {
    echo -e "${ERROR} $1 ${Color_Off}"
}


#print INFO
function print_info() {
    echo -e "${INFO} $1 ${Color_Off}"
}


# Check the shell
function check_bash() {
    is_BASH=$(readlink /proc/$$/exe | grep -q "bash")
    if [[ $is_BASH -ne "bash" ]]; then
        print_error "This installer needs to be run with bash, not sh."
        exit 1
    fi
}


# Check root
function check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "This installer needs to be run with superuser privileges. Login as root user and run the script again!"
        exit 1
    else 
        print_ok "Root user checked!" && $SLEEP
    fi
}


# Check OS
function check_os() {
    # check the OS
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
        print_ok "Ubuntu detected!"

    elif path_exist "/etc/debian_version"; then
        os="debian"
        os_version=$(cat /etc/debian_version | cut -d '.' -f 1)
        print_ok "Debian detected!"

    else
        print_error "This installer seems to be running on an unsupported distribution.
        Supported distros are ${Yellow}Debian${Color_Off} and ${Yellow}Ubuntu${Color_Off}."
        exit 1
    fi

    # after that check the version of the OS
    if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
        print_error "${Yellow}Ubuntu 20.04${Color_Off} or higher is required to use this installer.
        This version of Ubuntu is too old and unsupported."
        exit 1
    elif [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
        print_error "${Yellow}Debian 11${Color_Off} or higher is required to use this installer.
        This version of fedora is too old and unsupported."
        exit 1
    fi
}


# check last command/function status code
function check_status() {
    if [[ $? == 0 ]]; then
        print_ok "$1 Finished"
        ${SLEEP}
    else
        print_error "$1 Failed" && exit 1
    fi
}


# check if a path already exists
function path_exist() {
    if [[ -e "$1" ]]; then
        return 0
    fi

    return 1
}


# install packages
function install_pkgs() {
    apt install -y $*
    check_status "Install $*"
}


# disable a systemd service
function disable_service() {
    systemctl stop $1
    systemctl disable $1
}


# disable system firewalls
function disable_firewalls() {
    firewalls=(firewalld nftables ufw)

    for firewall in "${firewalls[@]}"; do
        status=$(systemctl is-actice --quiet ${firewall})
        if [[ ${status} == 0 ]]; then
            disable_service ${firewall}
        fi
    done
}


function install_deps() {
    install_pkgs lsof tar cron htop

    touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
    systemctl start cron && systemctl enable cron
    check_status "cron autostart"

    install_pkgs unzip curl

    install_pkgs libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev

    install_pkgs qrencode jq

    if [[ $(path_exist "/usr/local/bin") == 1 ]]; then
        mkdir /usr/local/bin >/dev/null 2>&1
    fi
}


function basic_optimization() {
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf
}


function check_ip() {
    ipv4=$(curl -s4m8 https://icanhazip.com)
    ipv6=$(curl -s6m8 https://icanhazip.com)

    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
        print_ok "Pure IPv6 server"
        PURE_IPV6=0
        IP=${ipv6}
    else
        print_ok "Server has IPv4"
        IP=${ipv4}
    fi
}


function cloudflare_dns() {
    local RESOLV_CONF_FILE="/etc/resolv.conf"

    if ${PURE_IPV6}; then
        tee ${RESOLV_CONF_FILE} <<EOF
nameserver 2606:4700:4700::1111
nameserver 2606:4700:4700::1001
EOF
    else
        tee ${RESOLV_CONF_FILE} <<EOF
nameserver 1.1.1.1
nameserver 1.0.0.1
EOF
    fi

    check_status "Change DNS to Cloudflare"
}


function install_xray_core() {
    print_info "Installing Xray-Core Pre-release version"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta
    check_status "Install Xray-Core"

    groupadd nobody
    gpasswd -a nobody nobody
}


function xray_tmp_config_file_check_and_use() {
    cp -f ${XRAY_CONFIG_FILE} ${XRAY_BACKUP_CONFIG_FILE}

    if [[ -s ${XRAY_TEMP_CONFIG_FILE} ]]; then
        mv -f ${XRAY_TEMP_CONFIG_FILE} ${XRAY_CONFIG_FILE}
        check_status "Use new config.json"
    else
        print_error "Cannot modify xray config file" && exit 1
    fi

    touch ${XRAY_TEMP_CONFIG_FILE}
    check_status "Make new ${XRAY_TEMP_CONFIG_FILE}"
    # restart_service xray
}


function make_inbound_summery_menu() {
    echo "  protocol  |  network  | security  | port"
    echo "==========================================="
    for ((i = 0; i < $1; i++)); do
        xray_config_content=$(cat ${XRAY_CONFIG_FILE})
        local protocol=$(jq ".inbounds[${i}].protocol" <<< ${xray_config_content})
        local security=$(jq ".inbounds[${i}].streamSettings.security" <<< ${xray_config_content})
        local network=$(jq ".inbounds[${i}].streamSettings.network" <<< ${xray_config_content})
        local port=$(jq ".inbounds[${i}].port" <<< ${xray_config_content})

        echo "${i}) ${protocol} ${network} ${security} ${port}"
    done
}


function choose_inbound() {
    inbounds_count=$(jq '.inbounds | length' ${XRAY_CONFIG_FILE})
    if [[ $((inbounds_count)) != 0 ]]; then
        make_inbound_summery_menu $((inbounds_count))

        read -rp "Choose Inbound: " inb_idx
        if [[ $((inb_idx)) > $((inbounds_count)) ]]; then
            print_error "Invalid inbound index" && exit 1
        fi
        INBOUND_INDEX=$(($inb_idx))

    else
        INBOUND_INDEX=0
    fi

    WORKING_INBOUND=$(jq .inbounds[$INBOUND_INDEX] ${XRAY_CONFIG_FILE})
    jq .inbounds[$INBOUND_INDEX] ${XRAY_CONFIG_FILE}
}


function save_inbound_changes() {
    jq '.inbounds['$INBOUND_INDEX'] = '"$1"'' ${XRAY_CONFIG_FILE} > ${XRAY_TEMP_CONFIG_FILE}
    xray_tmp_config_file_check_and_use
}


function add_new_inbound() {
    jq '.inbounds += '"[$1]"'' ${XRAY_CONFIG_FILE} > ${XRAY_TEMP_CONFIG_FILE}
    xray_tmp_config_file_check_and_use
}


function restart_service() {
    systemctl restart $1
}


function port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        return
    else
        local PROCCESS_NAME=$(lsof -i:"$1" | awk '{print $1}' | grep -v "COMMAND" | uniq)
        local PROCCESS_ID=$(lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | uniq)
        print_error "Port $1 is in use by $PROCCESS_NAME (PID: $PROCCESS_ID)" && exit 1
    fi
}


function make_users_menu() {
    local users_count=$(jq ".settings.clients | length" $1)

    echo -e "Users:"
    for ((i = 0; i < $((users_count)); i++)); do
        local name=$(jq .settings.clients[${i}].email $1 | tr -d '"')
        echo -e "  ${i}) ${name}"
    done

    echo ""

    read -rp "Choose User: " user_index
    if [[ $((user_index)) > $((users_count)) ]]; then
        print_error "Invalid user index"
        exit 1
    fi

    CLIENT_INDEX=$(($user_index))
}


function domain_check() {
    check_ip
    cloudflare_dns

    if [[ -z $1 ]]; then
        read -rp "Please enter your domain name (example: www.google.com):" domain
        DOMAIN_NAME=$domain
        echo -e "${DOMAIN_NAME}" > ${XRAY_DOMAIN_NAME_FILE}
    else
        DOMAIN_NAME=$1
    fi

    #domain_ip=$(ping -c 1 ${domain} | grep -m 1 -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    local domain_ip=$(dig +short $DOMAIN_NAME)
    print_ok "Getting domain IP address information, please be wait..."

    #wgcfv4_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    #wgcfv6_status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    #if [[ ${wgcfv4_status} =~ "on|plus" ]] || [[ ${wgcfv6_status} =~ "on|plus" ]]; then
    #  # Turn off wgcf-warp to prevent misjudgment of VPS IP situation
    #  wg-quick down wgcf >/dev/null 2>&1
    #  print_ok "wgcf-warp closed"
    #fi

    echo -e "DNS-resolved IP address of the domain name: ${domain_ip}"
    echo -e "Local public network IPv4 address ${ipv4}"

    if [[ -n $ipv6 ]]; then
        echo -e "Local public network IPv6 address ${ipv6}"
    fi

    sleep 2

    if [[ ${domain_ip} == ${ipv4} ]]; then
        print_ok "The DNS-resolved IP address of the domain name matches the native IPv4 address"
        sleep 1
    elif [[ ${domain_ip} == ${ipv6} ]]; then
        print_ok "The DNS-resolved IP address of the domain name matches the native IPv6 address"
        sleep 1
    else
        print_error "Please make sure that the correct A/AAAA records are added to the domain name, otherwise xray will not work properly"
        print_error "The IP address of the domain name resolved through DNS does not match the native IPv4/IPv6 address, 
        do you want to continue the installation? (y/n)" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
          print_ok "Continue Installation"
          sleep 1
          ;;
        *)
          print_error "Installation terminated"
          exit 1
          ;;
        esac
    fi
}


function configure_certbot() {
    # pass domain name as first argument
    install_pkgs certbot python3-certbot

    certbot certonly --standalone --preferred-challenges http \
        --register-unsafely-without-email -d $1
    check_status "Get SSL Certificate with Certbot"

    mkdir /ssl >/dev/null 2>&1

    cp -L -f /etc/letsencrypt/live/$1/fullchain.pem /ssl/xray.crt
    check_status "Copy fullchain.pem file"

    cp -L -f /etc/letsencrypt/live/$1/privkey.pem /ssl/xray.key
    check_status "Copy privkey.pem file"

    chown nobody:nobody /ssl/xray.*
}


function bbr_boost() {
    bash -c "$(curl -L https://github.com/teddysun/across/raw/master/bbr.sh)"
}


function download_dat_files() {
    # Block ir and iranian domains and ips.
    if ! command -v wget >/dev/null; then
        install_pkgs wget
    fi

    local iran_dat_file="/usr/local/share/xray/iran.dat"
    local dlc_dat_file="/usr/local/share/xray/dlc.dat"

    wget -O ${iran_dat_file} https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/iran.dat
    wget -O ${dlc_dat_file} https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
}


function modify_port() {
    read -rp "Please enter the port number (default 443): " PORT
    [ -z "$PORT" ] && PORT="443"
    if [[ $PORT -le 0 ]] || [[ $PORT -gt 65535 ]]; then
        print_error "Port must be in range of 0-65535"
        exit 1
    fi
    port_exist_check $PORT

    jq 'setpath(["port"];'${PORT}')' <<< $1
}


function modify_network() {
    # $1 -> inbound
    # $2 -> network (tcp - grpc - ws)
    jq 'setpath(["streamSettings","network"];"'$2'")' <<< $1
}


function modify_ws_path() {
    local random_num=$((RANDOM % 12 + 4))
    local NEW_WS_PATH="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"

    current_network=$(jq .streamSettings.network <<< $1)
    if [[ ${current_network} != "ws" ]]; then
        print_error "This inbound does not support websocket" && exit 1
    fi

    jq 'setpath(["streamSettings","wsSettings","path"];"'${NEW_WS_PATH}'")' <<< $1
}


function modify_tls() {
    local certFile="/ssl/xray.crt"
    local keyFile="/ssl/xray.key"

    if path_exist ${certFile} && path_exist ${keyFile}; then
        jq 'setpath(["streamSettings","tlsSettings","certificates",0,"certificateFile"];"'${certFile}'")' <<< $1
        jq 'setpath(["streamSettings","tlsSettings","certificates",0,"keyFile"];"'${keyFile}'")' <<< $1
    else
        print_error "Cannot find certificate files" && exit 1
    fi
}


function modify_protocol() {
    # $1 -> inbound
    # $2 -> protocol

    jq 'setpath(["protocol"];"'$2'")' <<< $1
}


function base_inbound() {
    local SETTINGS=$(jq -n \
        --argjson clients '[]' \
        '$ARGS.named'
    )

    local STREAM_SETTINGS=$(jq -n \
        --arg network "" \
        '$ARGS.named'
    )

    local SNIFFING=$(jq -n \
        --argjson enabled 'true' \
        --argjson destOverride '[ "http", "tls" ]' \
        '$ARGS.named'
    )

    jq -n \
        --arg listen '0.0.0.0' \
        --arg protocol '' \
        --argjson settings "$SETTINGS" \
        --argjson streamSettings "$STREAM_SETTINGS" \
        --argjson sniffing "$SNIFFING" \
        '$ARGS.named'
}


function add_tcp_header() {
    HEADERS=$(jq -n \
        --argjson Content-Type '[ "application/octet-stream", "application/x-msdownload", "text/html", "application/x-shockwave-flash" ]' \
        --argjson Transfer-Encoding '[ "chunked" ]' \
        --argjson Connection '[ "keep-alive" ]' \
        --arg Pragma 'no-cache' \
        '$ARGS.named'
    )

    RESPONSE=$(jq -n \
        --arg version "1.1" \
        --arg status "200" \
        --arg reason "OK" \
        --argjson headers "$HEADERS" \
        '$ARGS.named'
    )
    
    HEADER=$(jq -n \
        --arg type "http" \
        --argjson response "$RESPONSE" \
        '$ARGS.named'
    )

    TCP_SETTINGS=$(jq -n \
        --argjson header "$HEADER" \
        '$ARGS.named'
    )

    jq --argjson tcpSettings "$TCP_SETTINGS" \
        '.streamSettings = .streamSettings + $ARGS.named' <<< $1
}


function add_new_client() {
    # $1 -> Inbound
    # $2 -> username
    inbound_protocol=$(jq .protocol $1 | tr -d '"')

    if [[ $inbound_protocol == "vless" ]] || [[ $inbound_protocol == "vmess" ]]; then
        local NEW_UUID=$(cat /proc/sys/kernel/random/uuid)

        CLIENT_INFO=$(jq -n \
            --arg id "${NEW_UUID}" \
            --arg email "$2" \
            '$ARGS.named'
        )
    elif [[ $inbound_protocol == "trojan" ]]; then
        local NEW_PASSWORD="$(head -n 10 /dev/urandom | md5sum | head -c 18)"

        CLIENT_INFO=$(jq -n \
            --arg password "${NEW_PASSWORD}" \
            --arg email "$2" \
            '$ARGS.named'
        )
    fi

    #jq '.inbounds['"$INBOUND_INDEX"'].settings.clients += '"[$CLIENT_INFO]"'' \
    #    ${XRAY_CONFIG_FILE} > ${XRAY_TEMP_CONFIG_FILE}

    jq '.settings.clients += '"[$CLIENT_INFO]"'' <<< $1
}


function remove_client() {
    make_users_menu
    jq 'del(.settings.clients['$CLIENT_INDEX'])' <<< $1
}


function init_xray() {
    install_xray_core
    download_dat_files
    wget -O ${XRAY_CONFIG_FILE} https://raw.githubusercontent.com/thehxdev/xray-examples/main/Base-Config/server.json
}


function vless_ws_tls {
    local INB=$(base_inbound)
    local INB=$(modify_port "$INB")
    local INB=$(modify_protocol "$INB" 'vless')
    local INB=$(modify_network "$INB" 'ws')
    local INB=$(modify_ws_path "$INB")

    echo $INB | jq .
}

#check_root
#check_os

vless_ws_tls

