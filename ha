#!/bin/bash
#KaizenVPN Panel Premium Script

#############################
#############################
# Variables (Can be changed depends on your preferred values)
# Script name
MyScriptName='KaizenVPN-OCS Script'

# My VPS IP
MYIP=$(wget -qO- ipv4.icanhazip.com);



# Server local time
MyVPS_Time='Asia/Kuala_Lumpur'
#############################
#############################


#############################
#############################
## All function used for this script
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 
 # Removing some firewall tools that may affect other services
 apt-get remove --purge ufw firewalld -y
 
 # Installing some important machine essentials
 apt-get install nano git wget curl zip unzip tar gzip p7zip-full bc rc openssl cron build-essential expect net-tools screen bzip2 ccrypt lsof -y
 
 # Installing apt-transport-https and needed files
 apt-get install apt-transport-https lsb-release libdbi-perl libecap3 -y

 # Installing nginx
 apt-get install nginx -y
 
 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y
 
 # Installing sury repo by pulling its repository inside sources.list file 
 apt-get -y install apt-transport-https lsb-release ca-certificates curl
 wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
 sleep 2
 sh -c 'echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list'
 apt-get update
 
 # Installing php 5.6
 apt-get install php5.6 php5.6-fpm php5.6-cli php5.6-mbstring php5.6-mysql php5.6-mcrypt php5.6-xml php5.6-ssh2 -y
}

function InstMysql(){
# Installing mysql server
wget https://dev.mysql.com/get/mysql-apt-config_0.8.13-1_all.deb
sudo dpkg -i mysql-apt-config_0.8.13-1_all.deb
apt-get update -y
apt-get install mysql-server -y

 # Set Database Permissions
 cd
 chown -R mysql:mysql /var/lib/mysql/
 chmod -R 755 /var/lib/mysql/
 
 # mysql_secure_installation
 mysql_secure_installation

mysql -u root -p
mysql -u root -p
}

function InstNginx(){
 #modify nginx configs
 mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup 
 mv /etc/nginx/conf.d/vps.conf /etc/nginx/conf.d/vps.conf.backup 
 wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/Apeachsan91/vps/master/nginx.conf" 
 wget -O /etc/nginx/conf.d/kaizenvpn.conf "https://raw.githubusercontent.com/Apeachsan91/vps/master/vpss.conf" 
 rm /etc/php/5.6/fpm/php.ini
 rm /etc/php/5.6/fpm/pool.d/www.conf
 wget -O /etc/php/5.6/fpm/php.ini "https://raw.githubusercontent.com/Apeachsan91/vps/master/phpp.ini" 
 wget -O /etc/php/5.6/fpm/pool.d/www.conf "https://raw.githubusercontent.com/Apeachsan91/vps/master/wwww.conf" 
 
 # Setup dir and permissions
 useradd -m panel
 mkdir -p /home/panel/html
 echo "<?php phpinfo() ?>" > /home/panel/html/info.php
 chown -R www-data:www-data /home/panel/html
 chmod -R g+rw /home/panel/html
 
 # Then restart to take effect
 service php5.6-fpm restart
 service nginx restart
}

function InstPanel(){
 
 # Pull OCS Source Code
 wget -O /home/panel/html/debianvpn.zip https://github.com/Apeachsan91/vps/raw/master/debianvpn.zip
 sleep 2
 
 # Change dir to Webroot
 cd /home/panel/html
 
 # Deflate panel and set permissions
 unzip debianvpn.zip
 rm -f debianvpn.zip
 
 # Chmod Config
 chmod 777 /home/panel/html/config
 chmod 777 /home/panel/html/config/inc.php
 chmod 777 /home/panel/html/config/route.php
 
 # Install XML Parser Perl
 apt-get install libxml-parser-perl -y -f
}

###function InstImpSql(){
### # Import SQL to Database
###so3=$(expect -c "
###spawn mysql -u root -p $DatabaseName < /home/panel/html/database/sshpanel.sql sleep 3
###expect \"\";  sleep 3; send \"$DatabasePass\r\"
###expect eof; ")
###echo "$so3"
###
### # Change Database Credentials on .env
### sed -i "s|mypassword|$DatabasePass|g" /home/panel/html/system/.env
### sed -i "s|mydatabase|$DatabaseName|g" /home/panel/html/system/.env
###}

function InstHistory(){
 # Clear Machine History
 cd
 rm -f /root/.bash_history && history -c
 echo "unset HISTFILE" >> /etc/profile
}

function ScriptMessage(){
 echo -e " (｡◕‿◕｡) $MyScriptName"
 echo -e ""
 echo -e "Setup by Kaizen"
 echo -e ""
}

function SetBanner(){
 # Install BashRC Banner
 echo "clear"                                                              >> .bashrc
 echo 'echo -e "\e[0m                                                   "' >> .bashrc
 echo 'echo -e "\e[94m    ::::::::::  ::::::::  :::::::::   ::::::::    "' >> .bashrc
 echo 'echo -e "\e[94m    :+:        :+:    :+: :+:    :+:  :+:   :+:   "' >> .bashrc
 echo 'echo -e "\e[94m    +:+        +:+    +:+ +:+    +:+  +:+   +:+   "' >> .bashrc
 echo 'echo -e "\e[94m    +#+#+#+#:  +#+    +#: +#+ #+#++:  +#+   +:+   "' >> .bashrc
 echo 'echo -e "\e[94m    +#+        +#+    +#+ +#+    +#+  +#+   +#+   "' >> .bashrc
 echo 'echo -e "\e[94m    #+#        #+#    #+# #+#    #+#  #+#   #+#   "' >> .bashrc
 echo 'echo -e "\e[94m    ###         ########  ###    ###  ########    "' >> .bashrc
 echo 'echo -e "\e[91m               Script by  JohnFordTV              "' >> .bashrc
 echo 'echo -e "\e[0m"'                                                    >> .bashrc
 echo 'echo -e "\e[92m             [OCSPANEL PREMIUM SCRIPT]            "' >> .bashrc
 echo 'echo -e "\e[0m                  fb.com/johndesu090               "' >> .bashrc
}

#############################
#############################
## Installation Process
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

 # First thing to do is check if this machine is Debian
 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exting..." 
 exit 1
fi

 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 SetBanner
 sleep 2
 InstAsk
 
 # Update and Install Needed Files
 InstUpdates
 echo -e "Updating Server..."
 
 # Configure Mysql
 echo -e "Configuring MySQL..."
 InstMysql
 
 # Configure Nginx
 echo -e "Configuring NginX Webserver..."
 InstNginx
 
 # Configure OCS
 echo -e "Configuring OCS Panel Files..."
 InstPanel
 
### # Configure Database
### echo -e "Configuring Database..."
### InstImpSql
 
 # Clear history
 echo -e "Finalizing Installation..."
 InstHistory
 sleep 5
 
 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime

 # Some assistance and startup scripts
 ScriptMessage
 sleep 3

# info
clear
echo "=======================================================" | tee -a log-install.txt
echo "OCSPanel is installed at http://$MYIP please proceed installation on your Browser" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "OCS Script Installer by JohnFordTV"  | tee -a log-install.txt
echo "        (http://fb.com/johndesu090)         "  | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Run This Command on your VPS Terminal After Finishing Installation " | tee -a log-install.txt
echo "rm -rf /home/panel/html/installation" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "[DONATION] GCash: 09206200840 Paypal: johnford090@gmail.com " | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Installation Log --> /root/log-install.txt" | tee -a log-install.txt
echo "=======================================================" | tee -a log-install.txt
cd ~/

rm DP
