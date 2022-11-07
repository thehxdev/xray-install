#!/usr/bin/env bash

#config_path="/usr/local/etc/xray/config.json"
config_path="./config_server.json"
users_count_file="./users_count.txt"

function user_counter() {
	users_count=$(cat ./users_count.txt)

	echo -e "Current Users Count = ${users_count}"

	echo -e "Old Users:"

	rm -rf ./users_number_in_config.txt
	touch ./users_number_in_config.txt
	cat ${config_path} | grep "email" | grep -Eo "[1-9]{1,3}" | xargs -I INPUT echo INPUT >> ./users_number_in_config.txt
	for ((i = 0; i < ${users_count}; i++)); do
		config_i=$(($i + 1))
		current_client=$(sed -n "${config_i}p" ./users_number_in_config.txt)
		name=$(cat ${config_path} | jq .inbounds[0].settings.clients[${i}].email | tr -d '"' | grep "@." | tr -d "[1-9]{1,3}@")
		current_user_number=$(cat ${config_path} | jq .inbounds[0].settings.clients[${i}].email | grep -Eo "[1-9]{1,3}")
		echo -e "\t${i}) $name \t(user number: ${current_user_number})"
	done
	echo -e ""
}

function xray_tmp_config_file_check_and_use() {
	if [[ -s ${config_path} ]]; then
		mv -f ./config_server_tmp.json ${config_path}
	else
		print_error "can't modify xray config file!"
		exit 1
	fi
	touch ./config_server_tmp.json
}

function add_new_user() {
	user_counter
	cp ${config_path} ./config_server.json.bak1

	[ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
	last_user_num=$(wc -l ./users_number_in_config.txt | grep -Eo "[1-9]{1,3}" | xargs -I INPUT sed -n "INPUTp" ./users_number_in_config.txt)
	new_user_num=$(($last_user_num + 1))

	cat ${config_path} | jq 'setpath(["inbounds",0,"settings","clients",'${users_count}',"id"];"'${UUID}'")' >./config_server_tmp.json
	xray_tmp_config_file_check_and_use

	read -p "Enter new user name: " new_user_name
	cat ${config_path} | jq 'setpath(["inbounds",0,"settings","clients",'${users_count}',"email"];"'${new_user_num}@${new_user_name}'")' >./config_server_tmp.json
	xray_tmp_config_file_check_and_use

	new_users_count=$(($users_count + 1))
	echo ${new_users_count} > ./users_count.txt
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
		echo -e "Port = ${user_port}"
		echo -e "UUID = ${user_uuid}"
		echo -e "WS Path = ${user_ws_path}"
		echo -e "=============================="
		;;
	*)
		exit 1
		;;
	esac
}

function delete_user() {
	user_counter
	cp ${config_path} ./config_server.json.bak1
	echo -e ""

	read -rp "Enter user number: " user_number
	cat ${config_path} | jq 'del(.inbounds[0].settings.clients['${user_number}'])'>./config_server_tmp.json
	xray_tmp_config_file_check_and_use

	removed_user_number=$(cat ${config_path} | jq .inbounds[0].settings.clients[${user_number}].email | grep -Eo "[1-9]{1,3}")
	sed -i "s/${removed_user_number}//g" ./users_number_in_config.txt
	new_users_count=$(($users_count - 1))
	echo ${new_users_count} > ./users_count.txt

}

echo -e "1) get users info"
echo -e "2) add new user"
echo -e "3) delete user\n"

read -rp "Enter menu Number: " menu_number

case $menu_number in
1)
	echo -e ""
	get_user_info
	;;
2)
	echo -e ""
	add_new_user
	;;
3)
	echo -e ""
	delete_user
	;;
*)
	exit 1
	;;
esac
