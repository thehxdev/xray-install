#!/usr/bin/env bash

# Colors
Color_Off='\033[0m'
#Black='\033[0;30m' 
Red='\033[0;31m'   
Green='\033[0;32m' 
Yellow='\033[0;33m'
Blue='\033[0;34m'  
#Purple='\033[0;35m'
Cyan='\033[0;36m'  
#White='\033[0;37m' 


# Variables
xray_conf_dir="/usr/local/etc/xray"
config_path="/usr/local/etc/xray/config.json"
users_count_file="/usr/local/etc/xray/users_count.txt"
users_number_in_config_file="/usr/local/etc/xray/users_number_in_config.txt"

OK="${Green}[OK]"
ERROR="${Red}[ERROR]"

SLEEP="sleep 1"

#print OK
function print_ok() {
	echo -e "${OK} $1 ${Color_Off}"
}

#print ERROR
function print_error() {
	echo -e "${ERROR} $1 ${Color_Off}"
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


function user_counter() {
	users_count=$(cat ${users_count_file})

	if [[ -e ${users_number_in_config_file} ]];then
		rm -rf ${users_number_in_config_file}
		judge "remove old user_number file"
		touch ${users_number_in_config_file}
		judge "create new user_number file"
	fi

	echo -e "Current Users Count = ${users_count}"
	echo -e "Old Users:"

	cat ${config_path} | grep "email" | grep -Eo "[1-9]{1,3}" | xargs -I INPUT echo INPUT >> ${users_number_in_config_file}
	judge "write users in users_number file"
	for ((i = 0; i < ${users_count}; i++)); do
		config_i=$(($i + 1))
		current_client=$(sed -n "${config_i}p" ${users_number_in_config_file})
		name=$(cat ${config_path} | jq .inbounds[0].settings.clients[${i}].email | tr -d '"' | grep "@." | tr -d "[1-9]{1,3}@")
		current_user_number=$(cat ${config_path} | jq .inbounds[0].settings.clients[${i}].email | grep -Eo "[1-9]{1,3}")
		echo -e "\t${i}) $name \t(Code: ${current_user_number})"
	done
	echo -e ""
}

function xray_tmp_config_file_check_and_use() {
	if [[ -s ${config_path} ]]; then
		mv -f ${xray_conf_dir}/config_tmp.json ${config_path}
	else
		print_error "can't modify xray config file!"
		exit 1
	fi
	touch ${xray_conf_dir}/config_tmp.json
}

function add_new_user() {
	user_counter
	cp ${config_path} ${xray_conf_dir}/config.json.bak

	[ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
	last_user_num=$(wc -l ${users_number_in_config_file} | grep -Eo "[1-9]{1,3}" | xargs -I INPUT sed -n "INPUTp" ${users_number_in_config_file})
	new_user_num=$(($last_user_num + 1))

	cat ${config_path} | jq 'setpath(["inbounds",0,"settings","clients",'${users_count}',"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
	xray_tmp_config_file_check_and_use

	read -p "Enter new user name: " new_user_name
	cat ${config_path} | jq 'setpath(["inbounds",0,"settings","clients",'${users_count}',"email"];"'${new_user_num}@${new_user_name}'")' >${xray_conf_dir}/config_tmp.json
	xray_tmp_config_file_check_and_use

	new_users_count=$(($users_count + 1))
	echo ${new_users_count} > ${users_count_file}
}

function get_user_info() {
	user_counter
	echo -e ""

	read -rp "Enter user number: " user_number
	case $user_number in 
	$user_number)
		user_port=$(cat ${config_path} | jq .inbounds[0].port)
		user_uuid=$(cat ${config_path} | jq .inbounds[0].settings.clients[$user_number].id | tr -d '"')
		user_ws_path=$(cat ${config_path} | jq .inbounds[0].streamSettings.wsSettings.path | tr -d '"')
		echo -e "\n=============================="
		#echo -e "Port = ${user_port}"
		echo -e "UUID = ${user_uuid}"
		#echo -e "WS Path = ${user_ws_path}"
		echo -e "=============================="
		;;
	*)
		exit 1
		;;
	esac
}

function delete_user() {
	user_counter
	cp ${config_path} ${xray_conf_dir}/config.json.bak
	echo -e ""

	read -rp "Enter user number: " user_number

	removed_user_number=$(cat ${config_path} | jq .inbounds[0].settings.clients[${user_number}].email | grep -Eo "[1-9]{1,3}")
	echo "removed user code: ${removed_user_number}"
	sed -i "s/${removed_user_number}//g" ${users_number_in_config_file}

	cat ${config_path} | jq 'del(.inbounds[0].settings.clients['${user_number}'])'>${xray_conf_dir}/config_tmp.json
	xray_tmp_config_file_check_and_use

	new_users_count=$(($users_count - 1))
	echo ${new_users_count} > ${users_count_file}

}

function first_run() {
	if [[ ! -e "${config_path}" ]]; then
		print_error "can't find xray config. Seems like you don't installed xray"
		exit 1
	fi

	if [[ -e "${config_path}" ]]; then
		if ! grep -q "email" ${config_path} && ! grep -q -E "[1-9]{1,3}@."; then
			cp ${config_path} ${xray_conf_dir}/config.json.bak1
			judge "make backup file from config.json"
			cat ${config_path} | jq 'setpath(["inbounds",0,"settings","clients",0,"email"];"1@admin")' >${xray_conf_dir}/config_tmp.json
			judge "initialize first user"
			xray_tmp_config_file_check_and_use
		fi
	fi

	if [[ ! -e "${users_count_file}" && ! -e "${users_number_in_config_file}" ]]; then
		print_error "users_count.txt not found!"
		touch ${users_count_file}
		judge "create user count file"
		echo -e "1" > ${users_count_file}
		touch ${users_number_in_config_file}
		judge "create user number file"
		echo -e "1" > ${users_number_in_config_file}
	fi
}

clear

first_run

echo -e "${Green}1) get users info${Color_Off}"
echo -e "${Green}2) add new user${Color_Off}"
echo -e "${Red}3) delete user${Color_Off}"
echo -e "${Cyan}exit\n${Color_Off}"

read -rp "Enter menu Number: " menu_number

case $menu_number in
1)
	echo -e ""
	get_user_info
	systemctl restart xray
	;;
2)
	echo -e ""
	add_new_user
	systemctl restart xray
	;;
3)
	echo -e ""
	delete_user
	systemctl restart xray
	;;
4)
	exit 0
	;;
*)
	print_error "Invalid Option"
	exit 1
	;;
esac
