#!/usr/bin/env bash

# Colors
Color_Off='\033[0m'       # Text Reset
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White Variables

# Variables
github_branch="main"
xray_conf_dir="/usr/local/etc/xray"
website_dir="/var/www/html"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
cert_dir="/root/.ssl/"
domain_tmp_dir="/usr/local/etc/xray"
cert_group="nobody"
random_num=$((RANDOM % 12 + 4))

WS_PATH="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"

OK="[${Green}OK${Color_Off}]"
ERROR="[${Red}ERROR${Color_Off}]"

SLEEP="sleep 0.5"

#print OK
function print_ok() {
  echo -e "${OK} $1"
}

#print ERROR
function print_error() {
  echo -e "${ERROR} $1"
}

function installit() {
    apt install -y $*
}

function judge() {
    if [[ 0 -eq $? ]]; then
        print_ok "$1 Finished"
        $SLEEP
    else
        print_error "$1 Failde"
        exit 1
    fi
}

# Check the shell
function check_bash() {
    is_BASH=$(readlink /proc/$$/exe | grep -q "bash")
    if [[ $is_BASH -ne "bash" ]]; then
        print_error "This installer needs to be run with bash, not sh."
        exit
    fi
}

# Check root
function check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "This installer needs to be run with superuser privileges. Login as root user and run the script again!\n"
        exit
    else 
        print_ok "Root user checked!" ; $SLEEP
    fi
}

# Check OS
function check_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
        print_ok "Ubuntu detected!"
    elif [[ -e /etc/debian_version ]]; then
        os="debian"
        os_version=$(cat /etc/debian_version | cut -d '.' -f 1)
        print_ok "Debian detected!"
    else
        print_error "This installer seems to be running on an unsupported distribution.
        Supported distros are ${Yellow}Debian${Color_Off} and ${Yellow}Ubuntu${Color_Off}."
        exit
    fi
	if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
        print_error "${Yellow}Ubuntu 20.04${Color_Off} or higher is required to use this installer.
        This version of Ubuntu is too old and unsupported."
        exit
    elif [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then
        print_error "${Yellow}Debian 11${Color_Off} or higher is required to use this installer.
        This version of fedora is too old and unsupported."
        exit
    fi
}

function disable_firewalls() {
    is_firewalld=$(systemctl list-units --type=service --state=active | grep firewalld | wc -l)
    is_nftables=$(systemctl list-units --type=service --state=active | grep nftables | wc -l)
    is_ufw=$(systemctl list-units --type=service --state=active | grep ufw | wc -l)

    if [[ is_nftables -gt 0 ]]; then
        systemctl stop nftables
        systemctl disable nftables
    fi 

    if [[ is_ufw -gt 0 ]]; then
        systemctl stop ufw
        systemctl disable ufw
    fi

    if [[ is_firewalld -gt 0 ]]; then
        systemctl stop firewalld
        systemctl disable firewalld
    fi
}

function install_nginx() {
    if ! command -v nginx >/dev/null 2>&1; then
        installit nginx
        judge "install Nginx"
    else
        print_ok "Nginx Already Installed!"
    fi
}

function install_deps() {
    installit lsof tar
    judge "Install lsof tar"

    installit cron
    judge "install crontab"

    touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
    systemctl start cron && systemctl enable cron
    judge "crontab autostart"

    installit unzip
    judge "install unzip"

    installit curl
    judge "install curl"

    installit libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev
    judge "install libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev"

    installit qrencode
    judge "install qrencode"

    installit jq
    if ! command -v jq >/dev/null 2>&1; then
    wget -P /usr/bin https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/binary/jq && chmod +x /usr/bin/jq
    judge "install jq"
    fi

    mkdir /usr/local/bin >/dev/null 2>&1
}

function basic_optimization() {
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf
}

function ip_check() {
    local_ipv4=$(curl -s4m8 https://ip.gs)
    local_ipv6=$(curl -s6m8 https://ip.gs)
    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
		print_ok "Pure IPv6 server"
		SERVER_IP=$(curl -s6m8 https://ip.gs)
	else
		print_ok "Server hase IPv4"
		SERVER_IP=$(curl -s4m8 https://ip.gs)
    fi
}

function cloudflare_dns() {
    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
		echo "nameserver 2606:4700:4700::1111" > /etc/resolv.conf
		echo "nameserver 2606:4700:4700::1001" >> /etc/resolv.conf
		print_ok "server dns changed to cloudflare"
	else
		echo "nameserver 1.1.1.1" > /etc/resolv.conf
		echo "nameserver 1.0.0.1" >> /etc/resolv.conf
		print_ok "server dns changed to cloudflare"
	fi
}

function domain_check() {
    read -rp "Please enter your domain name information (example: www.google.com):" domain
    domain_ip=$(curl -sm8 ipget.net/?ip="${domain}")
    print_ok "Getting domain IP address information, please be wait..."
    #wgcfv4_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    #wgcfv6_status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    #if [[ ${wgcfv4_status} =~ "on"|"plus" ]] || [[ ${wgcfv6_status} =~ "on"|"plus" ]]; then
    #  # Turn off wgcf-warp to prevent misjudgment of VPS IP situation
    #  wg-quick down wgcf >/dev/null 2>&1
    #  print_ok "wgcf-warp closed"
    #fi
    local_ipv4=$(curl -s4m8 https://ip.gs)
    local_ipv6=$(curl -s6m8 https://ip.gs)
    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
        # Pure IPv6 VPS, automatically add DNS64 server for acme.sh to apply for certificate
        echo -e nameserver 2606:4700:4700::1111 > /etc/resolv.conf
        print_ok "Recognized VPS as IPv6 Only, automatically add DNS64 server"
    fi
    echo -e "DNS-resolved IP address of the domain name: ${domain_ip}"
    echo -e "Local public network IPv4 address ${local_ipv4}"
    echo -e "Local public network IPv6 address ${local_ipv6}"
    sleep 2
    if [[ ${domain_ip} == "${local_ipv4}" ]]; then
        print_ok "The DNS-resolved IP address of the domain name matches the native IPv4 address"
        sleep 2
    elif [[ ${domain_ip} == "${local_ipv6}" ]]; then
        print_ok "The DNS-resolved IP address of the domain name matches the native IPv6 address"
        sleep 2
    else
        print_error "Please make sure that the correct A/AAAA records are added to the domain name, otherwise xray will not work properly"
        print_error "The IP address of the domain name resolved through DNS does not match the native IPv4/IPv6 address, 
        do you want to continue the installation? (y/n)" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
          print_ok "Continue Installation"
          sleep 2
          ;;
        *)
          print_error "Installation terminated"
          exit 2
          ;;
        esac
    fi
}

function port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        print_ok "$1 Port is not in use"
        sleep 1
    else
        print_error "It is detected that port $1 is occupied, the following is the occupancy information of port $1"
        lsof -i:"$1"
        print_error "After 5s, it will try to kill the occupied process automatically"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        print_ok "Kill Finished"
        sleep 1
    fi
}

function modify_port() {
    read -rp "Please enter the port number (default: 8080): " PORT
    [ -z "$PORT" ] && PORT="8080"
    if [[ $PORT -le 0 ]] || [[ $PORT -gt 65535 ]]; then
        print_error "Port must be in range of 0-65535"
        exit 1
    fi
    port_exist_check $PORT
    cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"port"];'${PORT}')' >${xray_conf_dir}/config_tmp.json
    xray_tmp_config_file_check_and_use
    judge "Xray port modification"
}

function xray_tmp_config_file_check_and_use() {
    if [[ -s ${xray_conf_dir}/config_tmp.json ]]; then
        mv -f ${xray_conf_dir}/config_tmp.json ${xray_conf_dir}/config.json
    else
        print_error "can't modify xray config file!"
    fi
    touch ${xray_conf_dir}/config_tmp.json
}

function conf_nginx_notls() {
    nginx_conf="/etc/nginx/sites-available/default"
    rm -rf /etc/nginx/sites-available/default && wget -O /etc/nginx/sites-available/default https://raw.githubusercontent.com/thehxdev/xray-examples/${github_branch}/nginx/nginx_default_sample.conf
	judge "nginx config download"

	sed -i "s/YOUR_DOMAIN/${domain}/g" ${nginx_conf}
	judge "Nginx config modification"

    systemctl enable nginx
    systemctl restart nginx
}

function conf_nginx_tls() {
	nginx_conf="/etc/nginx/sites-available/default"
	rm -rf /etc/nginx/sites-available/default && wget -O /etc/nginx/sites-available/default https://raw.githubusercontent.com/thehxdev/xray-examples/${github_branch}/nginx/nginx_default_sample_tls.conf
	judge "nginx config download"

	sed -i "s/YOUR_DOMAIN/${domain}/g" ${nginx_conf}
	judge "Nginx config modification"

	systemctl enable nginx
	systemctl restart nginx
}

function configure_nginx_reverse_proxy() {
	nginx_conf="/etc/nginx/sites-available/default"
	rm -rf /etc/nginx/sites-available/default && wget -O /etc/nginx/sites-available/default https://raw.githubusercontent.com/thehxdev/xray-examples/${github_branch}/nginx/nginx_reverse_proxy.conf

	sed -i "s/YOUR_DOMAIN/${domain}/g" ${nginx_conf}
	judge "Nginx config modification"

	systemctl enable nginx
	systemctl restart nginx
}

function nginx_ssl_configuraion() {
	sed -i "s|CERT_PATH|/ssl/xray.crt|g" ${nginx_conf}
	sed -i "s|KEY_PATH|/ssl/xray.key|g" ${nginx_conf}
}

function configure_certbot() {
	mkdir /ssl >/dev/null 2>&1
	installit certbot python3-certbot
	judge "certbot python3-certbot Installation"
	sudo certbot certonly --standalone --preferred-challenges https -d $domain
	judge "certbot ssl certification"

	if [[ -f /etc/letsencrypt/live/$domain ]]; then
		cp -a /etc/letsencrypt/live/$domain/fullchain.pem /ssl/xray.crt
		judge "cert file copy"
		cp -a /etc/letsencrypt/live/$domain/privkey.pem /ssl/xray.key
		judge "key file copy"
	fi
}

function renew_certbot() {
	certbot renew --dry-run
	judge "SSL renew"
}

function add_wsPath_to_nginx() {
	sed -i "s/wsPATH/${WS_PATH}/g" ${nginx_conf}
}

function xray_install() {
    print_ok "Installing Xray"
    curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
    judge "Xray Installation"

    # Import link for Xray generation
    echo $domain >$domain_tmp_dir/domain
    judge "Domain name record"
}

function modify_UUID() {
    [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
    cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
    judge "modify Xray TCP UUID"
    xray_tmp_config_file_check_and_use
    judge "change tmp file to main file"
}

function modify_UUID_ws() {
    cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
    judge "modify Xray ws UUID"
    xray_tmp_config_file_check_and_use
    judge "change tmp file to main file"
}

function modify_fallback_ws() {
	cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","fallbacks",2,"path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
    judge "modify Xray fallback_ws"
    xray_tmp_config_file_check_and_use
    judge "change tmp file to main file"
}

function modify_ws() {
	cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"streamSettings","wsSettings","path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
	judge "modify Xray ws"
	xray_tmp_config_file_check_and_use
	judge "change tmp file to main file"
}

function modify_tls() {
	cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"streamSettings","tlsSettings","certificates","certificateFile"];"'${certFile}'")' >${xray_conf_dir}/config_tmp.json
	judge "modify Xray TLS Cert File"
	xray_tmp_config_file_check_and_use
	judge "change tmp file to main file"
	cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"streamSettings","tlsSettings","certificates","keyFile"];"'${keyFile}'")' >${xray_conf_dir}/config_tmp.json
	judge "modify Xray TLS Key File"
	xray_tmp_config_file_check_and_use
	judge "change tmp file to main file"
}

function configure_xray() {
	rm -f ${xray_conf_dir}/config.json && wget -O ${xray_conf_dir}/config.json https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/config/xray_xtls-rprx-direct.json
	modify_UUID
	modify_port
}

function ssl_install() {
	curl -L https://get.acme.sh | bash
	judge "Install the SSL certificate generation script"
}

function acme() {
	"$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    sed -i "6s/^/#/" "$nginx_conf"
    sed -i "6a\\\troot $website_dir;" "$nginx_conf"
    systemctl restart nginx

    if "$HOME"/.acme.sh/acme.sh --issue --insecure -d "${domain}" --webroot "$website_dir" -k ec-256 --force; then
		print_ok "SSL certificate generated successfully"
		sleep 2
		if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --reloadcmd "systemctl restart xray" --ecc --force; then
			print_ok "SSL certificate configured successfully"
			sleep 2
			if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
				wg-quick up wgcf >/dev/null 2>&1
				print_ok "wgcf-warp started"
			fi
        fi
    elif "$HOME"/.acme.sh/acme.sh --issue --insecure -d "${domain}" --webroot "$website_dir" -k ec-256 --force --listen-v6; then
        print_ok "SSL certificate generated successfully"
        sleep 2
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --reloadcmd "systemctl restart xray" --ecc --force; then
			print_ok "SSL certificate configured successfully"
			sleep 2
			if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
				wg-quick up wgcf >/dev/null 2>&1
				print_ok "wgcf-warp started"
			fi
        fi
    else
        print_error "SSL certificate generation failed"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
			wg-quick up wgcf >/dev/null 2>&1
			print_ok "wgcf-warp started"
        fi
        exit 1
    fi

    sed -i "7d" "$nginx_conf"
    sed -i "6s/#//" "$nginx_conf"
}

function ssl_judge_and_install() {
    mkdir -p /ssl >/dev/null 2>&1
    if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
        print_ok "The certificate file in the /ssl directory already exists"
    fi

    if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
        echo "Certificate file already exists"
    elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
        echo "Certificate file already exists"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --ecc
        judge "Certificate enabled"
    else
        mkdir /ssl
        cp -a $cert_dir/self_signed_cert.pem /ssl/xray.crt
        cp -a $cert_dir/self_signed_key.pem /ssl/xray.key
        ssl_install
        acme
    fi

    # Xray runs as nobody user by default, certificate authority adaptation 
    chown -R nobody.$cert_group /ssl/*
}

function generate_certificate() {
    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
        signedcert=$(xray tls cert -domain="$local_ipv6" -name="$local_ipv6" -org="$local_ipv6" -expire=87600h)
    else
        signedcert=$(xray tls cert -domain="$local_ipv4" -name="$local_ipv4" -org="$local_ipv4" -expire=87600h)
    fi
    echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee $cert_dir/self_signed_cert.pem
    echo $signedcert | jq '.key[]' | sed 's/\"//g' >$cert_dir/self_signed_key.pem
    openssl x509 -in $cert_dir/self_signed_cert.pem -noout || (print_error "Failed to generate self-signed certificate" && exit 1)
    print_ok "Self-signed certificate generated successfully"
	chown nobody.$cert_group $cert_dir/self_signed_cert.pem
    chown nobody.$cert_group $cert_dir/self_signed_key.pem
    if [[ ! -f /ssl ]]; then
        mkdir /ssl
        cp $cert_dir/self_signed_cert.pem /ssl/xray.crt
        cp $cert_dir/self_signed_key.pem /ssl/xray.key
    else 
        cp $cert_dir/self_signed_cert.pem /ssl/xray.crt
        cp $cert_dir/self_signed_key.pem /ssl/xray.key
    fi
	certFile="/ssl/xray.crt"
	keyFile="/ssl/xray.key"
}

function configure_web() {
    rm -rf /www/xray_web
    mkdir -p /www/xray_web
    print_ok "Do you configure fake web pages? [Y/N]"
    read -r webpage
    case $webpage in
    [yY][eE][sS] | [yY])
        wget -O web.tar.gz https://raw.githubusercontent.com/wulabing/Xray_onekey/main/basic/web.tar.gz
        tar xzf web.tar.gz -C /var/www/html/
        judge "site masquerading"
        rm -f web.tar.gz
        ;;
    *) ;;
    esac
}

function xray_uninstall() {
    curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- remove --purge
    rm -rf $website_dir/*
    print_ok "Do you want to uninstall Nginx [y/n]?"
    read -r uninstall_nginx
    case $uninstall_nginx in
    [yY][eE][sS] | [yY])
        apt purge nginx -y
        ;;
    *) ;;
    esac
    print_ok "Uninstall acme.sh [y/n]?"
    read -r uninstall_acme
    case $uninstall_acme in
    [yY][eE][sS] | [yY])
        "$HOME"/.acme.sh/acme.sh --uninstall
        rm -rf /root/.acme.sh
        rm -rf /ssl/
        ;;
    *) ;;
    esac
    print_ok "Uninstall complete"
    exit 0
}

function restart_all() {
	systemctl restart nginx
	judge "Nginx start"
	systemctl restart xray
	judge "Xray start"
}

function restart_xray() {
	systemctl restart xray
	judge "Xray start"
}

function bbr_boost() {
	wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}

# ==== VMESS + WS ====

function vmess_ws_link_gen() {
	read -rp "Choose config name: " config_name
	UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
	PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
	server_link=$(echo -neE "{\"add\": \"$SERVER_IP\",\"aid\": \"0\",\"host\": \"\",\"id\": \"$UUID\",\"net\": \"ws\",\"path\": \"$WS_PATH\",\"port\": \"$PORT\",\"ps\": \"$config_name\",\"scy\": \"chacha20-poly1305\",\"sni\": \"\",\"tls\": \"\",\"type\": \"\",\"v\": \"2\"}" | base64 | tr -d '\n')

	qrencode -t ansiutf8 -l L vmess://${server_link}
	echo -e "${Green}VMESS Link: ${Yellow}vmess://$server_link${Color_Off}"
}

function vmess_ws() {
    check_bash
    check_root
    check_os
    disable_firewalls
    install_deps
    basic_optimization
	ip_check
	domain_check
    xray_install
	wget -O ${xray_conf_dir}/config.json https://raw.githubusercontent.com/thehxdev/xray-examples/main/VMess-Websocket-s/config_server.json
    modify_port
    modify_UUID
    modify_ws
    restart_xray
    vmess_ws_link_gen
}

# ==== VMESS + WS + TLS ====

function vmess_ws_link_gen() {
	read -rp "Choose config name: " config_name
	UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
	PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
	server_link=$(echo -neE "{\"add\": \"$SERVER_IP\",\"aid\": \"0\",\"host\": \"\",\"id\": \"$UUID\",\"net\": \"ws\",\"path\": \"$WS_PATH\",\"port\": \"$PORT\",\"ps\": \"$config_name\",\"scy\": \"chacha20-poly1305\",\"sni\": \"$domain\",\"tls\": \"tls\",\"type\": \"\",\"v\": \"2\"}" | base64 | tr -d '\n')

	qrencode -t ansiutf8 -l L vmess://${server_link}
	echo -e "${Green}VMESS Link: ${Yellow}vmess://$server_link${Color_Off}"
}

function vmess_ws_tls() {
    check_bash
    check_root
    check_os
    disable_firewalls
    install_deps
    basic_optimization
	ip_check
    xray_install
	wget -O ${xray_conf_dir}/config.json https://raw.githubusercontent.com/thehxdev/xray-examples/main/VMess-Websocket-TLS-s/config_server.json
	generate_certificate
	ssl_judge_and_install
    modify_port
    modify_UUID
    modify_ws
	modify_tls
    restart_xray
    vmess_ws_tls_link_gen
}

function greetings_screen() {
    clear
    echo -e '

$$\   $$\ $$$$$$$\   $$$$$$\ $$\     $$\       $$\   $$\ $$\   $$\ 
$$ |  $$ |$$ .__$$\ $$  __$$\ $$\   $$  |      $$ |  $$ |$$ |  $$ |
\$$\ $$  |$$ |  $$ |$$ /  $$ |\$$\ $$  /       $$ |  $$ |\$$\ $$  |
 \$$$$  / $$$$$$$  |$$$$$$$$ | \$$$$  /        $$$$$$$$ | \$$$$  / 
 $$  $$<  $$ .__$$< $$ .__$$ |  \$$  /         $$ .__$$ | $$  $$<  
$$  /\$$\ $$ |  $$ |$$ |  $$ |   $$ |          $$ |  $$ |$$  /\$$\ 
$$ /  $$ |$$ |  $$ |$$ |  $$ |   $$ |          $$ |  $$ |$$ /  $$ |
\__|  \__|\__|  \__|\__|  \__|   \__|          \__|  \__|\__|  \__|

=> by thehxdev
=> https://github.com/thehxdev/
'

    if [[ "$os" == "debian" ]]; then
        echo -e "${Color_Off}OS = ${Blue}Debian"
        echo -e "${Color_Off}Version = ${Blue}${os_version}"
    elif [[ "$os" == "ubuntu" ]]; then
        echo -e "${Color_Off}OS = ${Blue}Ubuntu"
        echo -e "${Color_Off}Version = ${Blue}${os_version}\n"
    fi

	echo -e "==========  VMESS  =========="
    echo -e "${Green}1. VMESS + WS${Color_Off}"
	echo -e "========== Settings =========="
	echo -e "${Green}2. Change vps DNS to Cloudflare"
    echo -e "${Red}3. Uninstall Xray${Color_Off}"
    read -rp "Enter an Option: " menu_num
    case $menu_num in
    1)
        vmess_ws
        ;;
	2)
		cloudflare_dns
		;;
    3)
        xray_uninstall
        ;;
    *)
        print_error "Not a valid option"
        ;;
    esac
}

greetings_screen "$@"
