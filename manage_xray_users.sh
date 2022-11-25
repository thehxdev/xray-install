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
access_log_path="/var/log/xray/access.log"
users_expiry_date_file="/usr/local/etc/xray/users_expiry_date.txt"

OK="${Green}[OK]"
ERROR="${Red}[ERROR]"
INFO="${Yellow}[INFO]"

SLEEP="sleep 0.2"

#print OK
function print_ok() {
    echo -e "${OK} $1 ${Color_Off}"
}

#print ERROR
function print_error() {
    echo -e "${ERROR} $1 ${Color_Off}"
}

function print_info() {
    echo -e "${INFO} $1 ${Color_Off}"
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

    cat ${config_path} | grep "email" | grep -Eo "[1-9]{1,3}" | xargs -I INPUT echo INPUT >> ${users_number_in_config_file}
    judge "write users in users_number file"
    echo -e "\nCurrent Users Count = ${users_count}"
    echo -e "Old Users:"
    for ((i = 0; i < ${users_count}; i++)); do
        config_i=$(($i + 1))
        current_client=$(sed -n "${config_i}p" ${users_number_in_config_file})
        name=$(cat ${config_path} | jq .inbounds[0].settings.clients[${i}].email | tr -d '"' | grep "@." | tr -d "[1-9]{1,3}@")
        current_user_number=$(cat ${config_path} | jq .inbounds[0].settings.clients[${i}].email | grep -Eo "[1-9]{1,3}")
        echo -e "  ${i}) $name \t(email-num: ${current_user_number})"
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

    last_user_num=$(wc -l ${users_number_in_config_file} | grep -Eo "[1-9]{1,3}" | xargs -I INPUT sed -n "INPUTp" ${users_number_in_config_file})
    last_user_num_inNum=$((last_user_num))
    new_user_num=$((${last_user_num_inNum} + 1))

    if grep -q "vmess" ${config_path} || grep -q "vless" ${config_path}; then
        [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
        cat ${config_path} | jq 'setpath(["inbounds",0,"settings","clients",'${users_count}',"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
        xray_tmp_config_file_check_and_use
    elif grep -q "trojan" ${config_path}; then
        [ -z "$PASSWORD" ] && PASSWORD=$(head -n 10 /dev/urandom | md5sum | head -c 18)
        cat ${config_path} | jq 'setpath(["inbounds",0,"settings","clients",'${users_count}',"password"];"'${PASSWORD}'")' >${xray_conf_dir}/config_tmp.json
        xray_tmp_config_file_check_and_use
        if grep -q "xtls" ${config_path}; then
            XTLS_FLOW="xtls-rprx-direct"
            cat ${config_path} | jq 'setpath(["inbounds",0,"settings","clients",'${users_count}',"flow"];"'${XTLS_FLOW}'")' >${xray_conf_dir}/config_tmp.json
            xray_tmp_config_file_check_and_use
        fi
    else
        print_error "Your current protocol is not supported"
        exit 1
    fi

    read -p "Enter New Username: " new_user_name
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
        if grep -q "id" ${config_path}; then
            user_uuid=$(cat ${config_path} | jq .inbounds[0].settings.clients[$user_number].id | tr -d '"')
        elif grep -q "password" ${config_path}; then
            user_password=$(cat ${config_path} | jq .inbounds[0].settings.clients[$user_number].password | tr -d '"')
        fi
        user_ws_path=$(cat ${config_path} | jq .inbounds[0].streamSettings.wsSettings.path | tr -d '"')
        echo -e "\n=============================="
        #echo -e "Port = ${user_port}"
        if [ -n "$user_uuid" ]; then
            echo -e "UUID = ${user_uuid}"
        elif [ -n "$user_password" ]; then
            echo -e "Password = ${user_password}"
        fi
        if [ -n "${user_ws_path}" ]; then
            echo -e "WS Path = ${user_ws_path}"
        fi
        echo -e "=============================="
        ;;
    *)
        exit 1
        ;;
    esac
}

function delete_user() {
    current_users_count=$(cat ${users_count_file})
    if [[ ${current_users_count} == "1" ]]; then
        print_error "You can't delete the last user. Xray Must have at least ONE user."
        print_info "Please create second user then try again."
        exit 1
    fi
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
    #echo -e "checking..."
    if [[ ! -e "${config_path}" ]]; then
        print_error "can't find xray config. Seems like you don't installed xray"
        exit 1
    else
        print_ok "xray is installed"
    fi

    if grep -q -E -o "[1-9]{1,3}@" ${config_path} ; then
        print_ok "admin user found"
    else
        cp ${config_path} ${xray_conf_dir}/config.json.bak1
        judge "make backup file from config.json"
        cat ${config_path} | jq 'setpath(["inbounds",0,"settings","clients",0,"email"];"1@admin")' >${xray_conf_dir}/config_tmp.json
        judge "initialize first user"
        xray_tmp_config_file_check_and_use
    fi

    if [[ ! -e "${users_count_file}" && ! -e "${users_number_in_config_file}" ]]; then
        print_error "users_count.txt not found!"
        touch ${users_count_file}
        judge "create user count file"
        echo -e "1" > ${users_count_file}
        touch ${users_number_in_config_file}
        judge "create user number file"
        echo -e "1" > ${users_number_in_config_file}
    else
        print_ok "rquired files exist"
    fi
}

function make_users_expiry_date_file() {
    if [[ ! -e "${users_expiry_date_file}" ]]; then
        touch ${users_expiry_date_file}
        judge "Create users expiry date file"
    else
        print_ok "Users expiry date file exists"
    fi
}

function add_users_to_users_expiry_date_file() {
    make_users_expiry_date_file
    user_counter

    echo -e "${Blue}Add User Expiry Date${Color_Off}\n"

    read -rp "Enter User Number: " user_number
    user_name=$(cat ${config_path} | jq .inbounds[0].settings.clients[${user_number}].email | tr -d '"' | grep "@." | tr -d "[1-9]{1,3}@")

    if grep -q "${user_name}" ${users_expiry_date_file}; then
        print_info "Chosen user Already has an expiry date. Do you want to update user's settings?"
        read -rp "Enter Your Choice [y/n]: " update_user_choice
        case $update_user_choice in
        [yY][eE][sS] | [yY])
            sed -i "/^${user_name}/d" ${users_expiry_date_file}
            judge "Remove existing settings for user ${user_name}"
            ;;
        *)
            print_info "Ok! No changes will take effect!"
            exit 0
            ;;
        esac
    fi

    today_date_formated=$(date +%Y.%m.%d)
    echo -e "Today = ${today_date_formated}\n"
    read -rp "Enter Expiry Date (example: 2023.01.15): " user_expiry_date
    if [[ ! ${user_expiry_date} =~ [0-9]{4}\.[0-9]{2}\.[0-9]{2} ]]; then
       print_error "Unsupported date format." 
       print_info "Opration failed. run script again!"
       print_info "Your Changes not effected"
       exit 1
    fi

    today_date=$(date +%Y%m%d)
    user_enterd_date=$(echo -e "${user_expiry_date}" | tr -d ".")
    if [[ "${user_enterd_date}" -lt "${today_date}" ]]; then
        print_error "You entered a date from the past!"
        print_info "Today: $(date +%Y.%m.%d)"
        exit 1
    fi

    echo -e "${user_name}\t${user_expiry_date}" >> ${users_expiry_date_file}
    judge "Add ${user_name} to users expiry date file"
    print_info "File location ${users_expiry_date_file}"
}

function print_users_expiry_date_file() {
    if [[ ! -e "${users_expiry_date_file}" ]]; then
        print_error "You're not defined users"
        exit 1
    fi

    file_lines_count=$(cat ${users_expiry_date_file} | wc -l)

    for ((i = 0; i < ${file_lines_count}; i++)); do
        current_user=$(sed -n "$((i + 1))p" ${users_expiry_date_file})
        expiry_date=$(echo -e "${current_user}" | grep -Eo "[0-9]{4}\.[0-9]{2}\.[0-9]{2}")
        expiry_date_num=$(echo -e "${current_user}" | grep -Eo "[0-9]{4}\.[0-9]{2}\.[0-9]{2}" | tr -d ".")
        current_date=$(date +%Y%m%d)

        if [[ "${expiry_date_num}" -gt "${current_date}" ]]; then
            echo -e "  ${i}) ${current_user} ${Green}(Not Expired)${Color_Off}"
        else
            echo -e "  ${i}) ${current_user} ${Red}(Expired)${Color_Off}"
        fi
    done
    echo -e ""
}

function delete_user_date() {
    print_users_expiry_date_file

    read -rp "Enter user's number: " user_number
    chosen_user=$(sed -n "$((user_numberp + 1))p" ${users_expiry_date_file})
    sed -ibak "/^${chosen_user}/d" ${users_expiry_date_file}
    judge "Remove user date limitation"
}

function users_exp_menu() {
    clear

    echo -e "================== Date =================="
    echo -e "${Green}1) Add Expiry date for a user ${Color_Off}"
    echo -e "${Green}2) Print Users Info ${Color_Off}"
    echo -e "${Green}3) Delete a user's date limitation ${Color_Off}"
    echo -e "${Yellow}4) Exit${Color_Off}"
    echo -e ""

    read -rp "Enter An Option: " date_menu_number
    case $date_menu_number in
        1)
            add_users_to_users_expiry_date_file
            ;;
        2)
            print_users_expiry_date_file
            ;;
        3)
            delete_user_date
            ;;
        4)
            print_ok "Exit"
            exit 0
            ;;
        *)
            print_error "Invalid Opiton. Run script again!"
            exit 1
            ;;
    esac
}

clear

echo -e "${Green}1) get users info${Color_Off}"
echo -e "${Green}2) add new user${Color_Off}"
echo -e "${Green}3) Add Expiry Date For Each User${Color_Off}"
echo -e "${Red}4) delete user${Color_Off}"
echo -e "${Cyan}5) exit\n${Color_Off}"

read -rp "Enter menu Number: " menu_number

case $menu_number in
1)
    echo -e ""
    first_run
    get_user_info
    systemctl restart xray
    ;;
2)
    echo -e ""
    first_run
    add_new_user
    systemctl restart xray
    ;;
3)
    users_exp_menu
    ;;
4)
    echo -e ""
    first_run
    delete_user
    systemctl restart xray
    ;;
*)
    print_error "Invalid Option"
    exit 1
    ;;
esac

