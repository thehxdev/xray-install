#!/usr/bin/env bash

Color_Off='\033[0m'       # Text Reset
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White

github_branch="main"
xray_conf_dir="/usr/local/etc/xray"
website_dir="/var/www/html/"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
cert_dir="/root/.ssl/"
domain_tmp_dir="/usr/local/etc/xray"
cert_group="nobody"
random_num=$((RANDOM % 12 + 4))

WS_PATH="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

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
		print_error "This installer needs to be run with superuser privileges.
		Login as root user and run the script again!\n"
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
		$INS="apt install -y"
		print_ok "Ubuntu detected!"
	elif [[ -e /etc/debian_version ]]; then
		os="debian"
		os_version=$(cat /etc/debian_version | cut -d '.' -f 1)
		$INS="apt install -y"
		print_ok "Debian detected!"
	else
		print_error "This installer seems to be running on an unsupported distribution.
		Supported distros are Debian and Ubuntu."
		exit
	fi

	if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
		print_error "Ubuntu 20.04 or higher is required to use this installer.
		This version of Ubuntu is too old and unsupported."
		exit
	elif [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then
		print_error "Debian 11 or higher is required to use this installer.
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
		print_ok "Recognize VPS as IPv6 Only, automatically add DNS64 server"
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

function xray_tmp_config_file_check_and_use() {
	if [[ -s ${xray_conf_dir}/config_tmp.json ]]; then
		mv -f ${xray_conf_dir}/config_tmp.json ${xray_conf_dir}/config.json
	else
		print_error "can't modify xray config file!"
	fi
}

function modify_UUID() {
	[ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
	cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
	xray_tmp_config_file_check_and_use
	judge "modify Xray TCP UUID"
}

function modify_UUID_ws() {
	cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
	xray_tmp_config_file_check_and_use
	judge "modify Xray ws UUID"
}

function modify_fallback_ws() {
	cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","fallbacks",2,"path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
	xray_tmp_config_file_check_and_use
	judge "modify Xray fallback_ws"
}

function modify_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"streamSettings","wsSettings","path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "modify Xray ws"
}






function greetings_screen() {
	echo -e '=============================================================================

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
		echo -e "${Color_Off}Version = ${Blue}${os_version}"
	fi

	echo -e "\n${Color_Off}============================================================================="
}

check_bash
