#############################
#############################
# Script name
MyScriptName='KaizenVPN-DEB9&10 Script'

# OpenSSH Ports
SSH_Port1='22'

# Your SSH Banner
SSH_Banner='https://raw.githubusercontent.com/Apeachsan91/vps/master/banner'

# Dropbear Ports
Dropbear_Port1='442'
Dropbear_Port2='445'

# Stunnel Ports
Stunnel_Port1='443' # through Dropbear
Stunnel_Port2='444' # through OpenSSH
Stunnel_Port3='587' # through OpenVPN

# OpenVPN Ports
OpenVPN_TCP_Port='465'
OpenVPN_UDP_Port='25222'

# Privoxy Ports
Privoxy_Port1='8086'

# Squid Ports
Squid_Port1='3128'

# OpenVPN Config Download Port
OvpnDownload_Port='85' # Before changing this value, please read this document. It contains all unsafe ports for Google Chrome Browser, please read from line #23 to line #89: https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/net/base/port_util.cc

# Server local time
MyVPS_Time='Asia/Kuala_Lumpur'
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
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt -y
 
 # Now installing all our wanted services
 apt-get install gnupg tcpdump grepcidr dropbear stunnel4 screen privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid -y

 # Installing all required packages to install Webmin
 apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl -y
 apt-get install shared-mime-info jq fail2ban -y

 
 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y
 
 # Installing OpenVPN by pulling its repository inside sources.list file 
 rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn.list
 wget -qO - http://build.openvpn.net/debian/openvpn/stable/pubkey.gpg|apt-key add -
 apt-get update
 apt-get install openvpn -y
}

function InstWebmin(){
 # Download the webmin .deb package
 # You may change its webmin version depends on the link you've loaded in this variable(.deb file only, do not load .zip or .tar.gz file):
 WebminFile='https://github.com/Apeachsan91/vps/raw/master/webmin_1.920_all.deb'
 wget -qO webmin.deb "$WebminFile"
 
 # Installing .deb package for webmin
 dpkg --install webmin.deb
 
 rm -rf webmin.deb
 
 # Configuring webmin server config to use only http instead of https
 sed -i 's|ssl=1|ssl=0|g' /etc/webmin/miniserv.conf
 
 # Then restart to take effect
 systemctl restart webmin
}

function InstSSH(){
 # Removing some duplicated sshd server configs
 rm -f /etc/ssh/sshd_config*
 
 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT1
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 # Now we'll put our ssh ports inside of sshd_config
 sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config

 # Download our SSH Banner
 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/bin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/bin/nologin' >> /etc/shells
 
 # Restarting openssh service
 systemctl restart ssh
 
 # Removing some duplicate config file
 rm -rf /etc/default/dropbear*
 
 # creating dropbear config using cat eof tricks
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

 # Now changing our desired dropbear ports
 sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
 sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear
 
 # Restarting dropbear service
 systemctl restart dropbear
}

function InsStunnel(){
 StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

 # Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# My Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

 # Removing all stunnel folder contents
 rm -rf /etc/stunnel/*
 
 # Creating stunnel certifcate using openssl
 openssl req -new -x509 -days 9999 -nodes -subj "/C=MY/ST=SBH/L=KotaKinabalu/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null
##  > /dev/null 2>&1

 # Creating stunnel server config
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:dropbear_port_c

[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:openssh_port_c

[openvpn]
accept = Stunnel_Port3
connect = 127.0.0.1:openvpn_port_c
MyStunnelC

# setting stunnel ports
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$Dropbear_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$SSH_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|openvpn_port_c|$OpenVPN_TCP_Port|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port3|$Stunnel_Port3|g" /etc/stunnel/stunnel.conf
 # Restarting stunnel service
 systemctl restart $StunnelDir
}

function InsOpenVPN(){
 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key

 cat <<'myOpenVPNconf' > /etc/openvpn/server_tcp.conf
# OpenVPN TCP
port OVPNTCP
proto tcp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
tls-crypt /etc/openvpn/ta.key
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.200.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log tcp.log
verb 2
ncp-disable
auth SHA512
cipher AES-256-CBC
myOpenVPNconf

cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# OpenVPN UDP
port OVPNUDP
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
tls-crypt /etc/openvpn/ta.key
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.201.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log udp.log
verb 2
ncp-disable
auth SHA512
cipher AES-256-CBC
myOpenVPNconf2

  cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
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
mQXmMKc1Owxb
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=MY, ST=SBH, L=KotaKinabalu, O=KaizenVPN, OU=admin, CN=KaizenVPN_MY/name=KaizenVPN/emailAddress=kaizenvpn@gmail.com
        Validity
            Not Before: May 29 17:09:42 2020 GMT
            Not After : May 27 17:09:42 2030 GMT
        Subject: C=MY, ST=SBH, L=KotaKinabalu, O=KaizenVPN, OU=admin, CN=server/name=KaizenVPN/emailAddress=kaizenvpn@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:ac:a6:e2:ae:46:8f:9d:e6:2b:fb:30:b9:ff:17:
                    6a:5e:25:5f:63:39:24:ea:93:f1:6f:7e:4a:b0:81:
                    c3:e3:e1:0a:0f:cc:83:18:5a:cc:7e:9d:47:53:56:
                    52:84:92:c2:41:57:45:14:43:1a:5b:2f:58:74:81:
                    33:45:04:6e:16:7b:54:12:e8:a5:b8:00:8e:cc:15:
                    c0:1b:bf:6b:66:1f:48:78:91:2f:58:0f:82:42:e6:
                    80:3a:de:c5:77:f5:39:28:84:03:8e:85:8c:55:33:
                    3a:f3:2e:c9:ec:2a:8b:9c:c4:29:55:71:16:d7:77:
                    a0:a3:0a:3c:6e:24:d0:b4:88:d2:3a:5a:81:da:96:
                    b6:c0:c7:d8:85:f5:27:19:33:70:99:a7:eb:13:6b:
                    27:e0:2b:9b:4e:08:a3:29:78:14:3f:9e:f6:b9:a7:
                    1c:c4:d6:bc:a3:fe:a7:98:7d:46:cc:f2:d4:e2:56:
                    41:3f:10:4c:a0:31:63:21:1b:00:a1:e1:38:0e:dd:
                    6b:57:f9:77:66:ba:6e:bb:db:38:26:ff:41:44:72:
                    69:31:97:a0:72:8b:e8:83:90:d1:c6:7f:38:2b:2b:
                    bb:fc:5b:bf:7e:5e:eb:b9:0c:ac:e3:f7:5b:26:91:
                    48:ed:08:5c:16:25:27:22:c6:83:b5:4d:cb:fc:af:
                    7c:9a:6c:b1:5d:ef:9b:37:f3:ba:63:70:05:9c:92:
                    f5:33:b0:fa:ec:2e:fb:10:fe:46:93:02:cb:77:f4:
                    15:e5:1b:52:17:0d:b4:56:2d:9f:16:ac:56:29:ca:
                    49:ed:58:14:a1:d4:d0:ff:83:62:fe:7a:8c:5b:73:
                    1d:93:52:09:9a:e5:09:c8:71:c6:17:56:de:72:86:
                    a3:f3:1a:c8:09:04:8f:11:e6:79:8f:ca:53:e4:82:
                    a1:8a:2d:93:98:79:0d:42:12:ba:61:4f:9f:ce:4e:
                    05:25:d0:de:9f:b9:15:b7:34:a0:d2:4f:e3:99:03:
                    a3:be:38:6c:ae:6d:07:56:e2:a7:62:c6:b9:c8:ff:
                    13:8f:1b:36:61:35:85:61:14:9c:23:23:47:60:1c:
                    62:84:00:16:1a:de:48:06:f3:5d:b9:99:5a:2c:91:
                    e7:0d:9f:12:0e:99:3a:cd:5f:27:b8:8b:10:c7:64:
                    7f:28:d3:a9:44:ae:05:7c:95:35:a4:86:b1:e0:07:
                    db:74:22:50:fb:55:72:3e:45:e3:52:38:6f:1d:c2:
                    80:39:e4:7b:1e:b2:76:86:40:90:66:be:e5:e4:34:
                    d2:9a:52:14:c4:15:32:93:d5:a9:6e:1a:78:03:39:
                    d7:61:61:0e:8a:82:6b:d0:d7:92:88:67:fe:28:92:
                    3f:40:6b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier: 
                35:7F:4E:D6:FE:0F:E8:AB:4D:EE:8D:3B:C3:3B:71:47:56:4C:1F:C1
            X509v3 Authority Key Identifier: 
                keyid:60:05:3E:A5:24:02:9F:89:03:32:0A:17:99:0A:A6:FD:04:1D:87:F0
                DirName:/C=MY/ST=SBH/L=KotaKinabalu/O=KaizenVPN/OU=admin/CN=KaizenVPN_MY/name=KaizenVPN/emailAddress=kaizenvpn@gmail.com
                serial:4E:5D:E5:59:B3:0A:F4:90:3A:EA:EB:38:86:15:A7:A5:20:0C:02:AB

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
    Signature Algorithm: sha256WithRSAEncryption
         56:2d:d8:9a:80:e0:b4:a0:9d:f8:aa:32:5d:ff:f4:23:ee:91:
         1f:1d:32:99:a8:5a:48:5b:bd:5d:7f:6b:d9:97:cb:3b:5d:7c:
         65:6d:01:0c:7c:fc:ff:fb:f7:c2:4c:df:65:6d:87:4f:2a:e4:
         99:b8:1f:04:bd:f3:ec:50:3e:f2:d1:9f:3a:b9:38:8f:fd:ad:
         b0:48:81:29:7b:ce:1d:58:b5:b7:d6:7d:04:ed:47:8d:25:f9:
         c9:27:82:b8:3f:c1:ab:7d:4b:97:94:0c:72:f7:e6:2a:11:00:
         97:9b:10:9d:54:27:e6:b2:2f:9f:6a:d9:f7:82:93:e7:f9:04:
         e4:7a:25:f3:bf:a1:af:03:df:c1:d3:ad:54:78:14:e8:b6:a3:
         71:5d:e2:50:52:72:8c:57:0f:86:52:7e:ed:b6:77:2f:ad:20:
         d9:2b:11:44:0c:19:04:66:93:09:e7:1a:4e:de:50:0a:ae:dd:
         ea:0a:f5:02:f6:0e:d6:05:4e:a2:d0:18:3b:9f:08:e2:28:f4:
         83:68:a2:f6:87:91:12:39:be:02:01:10:91:dd:c5:6c:4f:cd:
         e0:8e:a0:af:7e:a9:e7:2f:c3:a4:8d:ee:19:26:7a:76:9a:e6:
         0c:46:1f:cf:b5:2a:34:eb:04:33:4d:8c:1a:a7:3a:09:82:5d:
         d9:7f:a8:0c:bd:c4:58:25:be:76:77:70:d9:8b:26:2b:98:60:
         4c:e4:bd:c9:68:24:f1:dd:6b:78:e6:63:be:36:40:79:96:ff:
         38:d3:34:0a:ba:c0:63:ec:09:c2:ce:b1:9b:e5:19:ac:51:1b:
         23:c7:02:b4:0c:97:ea:c0:9a:c6:72:7b:cc:35:c9:17:5e:d8:
         0b:5a:0a:75:db:c5:42:55:3f:50:77:8a:3b:e9:31:64:4f:2d:
         34:70:03:c4:c7:37:06:df:99:b9:40:be:8b:ce:b0:72:6d:8e:
         b1:29:07:6c:41:ee:b8:67:59:53:25:5e:61:7a:90:15:e3:8c:
         1a:e3:b3:14:9c:6f:74:e4:9a:50:e1:8c:bb:ce:01:27:0f:f3:
         0d:de:16:c6:f9:7a:73:f3:1f:fb:0f:73:eb:2f:7c:52:a8:e1:
         22:83:61:e3:20:8f:d5:fc:25:bc:f6:1a:73:e6:e9:99:90:89:
         c0:e7:69:ea:0d:be:ba:d1:a4:62:f9:a4:dd:b3:fd:03:2f:36:
         a8:92:ed:27:c0:1a:32:19:c7:83:3d:4a:9c:38:ad:82:bd:29:
         e9:71:c6:fe:0d:b8:29:57:af:2b:19:a2:ef:32:46:c4:f6:08:
         4e:a8:75:90:f3:5d:d2:bb:63:61:b3:e6:e0:c9:8d:8f:81:6f:
         9f:90:47:01:f8:e5:3d:17
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
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
hgiphZwZY1XzAThlsxdBEzK+6kMIjYo=
-----END PRIVATE KEY-----
EOF10
 cat <<'EOF13'> /etc/openvpn/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA8sZPuFbSjnjVIi5Iat2nhEMj9SHZL11plX5jhujN/plKIWljUEzC
xiIzIltWSmpDV4o2HZL8T5RPLLu4Sv0Zidh6C4C+b8KdZdvjQfbvBGqxh2Ia9/d/
HI/Y3oYnatDp6Futb5bm/xbJVNRzwu1ayzr4X9F4VpCCFFK0vnt1VQUORjeif5QI
3XnugwZDihB3j7XEkSI9N05oNx5FsRNEUMhhTpYDaeGggATftZGGDf7KXYg2v4Wb
+Wp3vNZ/8m4l2pK8gaIVVTB7fdY0cG5iNaJ12QFBRJGUD0IVe+Ob7xcoBhZPTXC+
FI2L3z3pdTqq2HEZmuZShPvxiHbE3xn+kwIBAg==
-----END DH PARAMETERS-----
EOF13
 cat <<'EOF19'> /etc/openvpn/ta.key
-----BEGIN OpenVPN Static key V1-----
5a90bdd3b6cc1d9e0924044f6065a662
6d4cc7aeb98d18c5276d746442faa23b
b86c5a2c8b62029517d3ab61e9e84a78
1934c40c4cd31232f834198ae4d0cf1e
8bc857daa689d8d6cb71e4f0e1c23d38
b5f2e33a44604c22f2c9a2a9d51a4481
3240f76885dfadc3f66a3f1f1c04f244
f64f1f51e202cc5de67ab974d58b1857
2accd4848493fd04d052b6ed3fd839e8
3958471ff272975ef2db05275354db67
71dec6f35ffb348beb33fbecec870163
42960aa4382942f6d5b37c3f14a0f7f4
ae1d573da3d92e2baa94c421d0726af5
cc06322c296350a3842b267eadea4811
7712fd7d332f481ac6062dea0135bdc7
e51a070334405aaa543231110e7f5418
-----END OpenVPN Static key V1-----
EOF19
 # Getting all dns inside resolv.conf then use as Default DNS for our openvpn server
 grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_tcp.conf
done

 # Creating a New update message in server.conf
 cat <<'NUovpn' > /etc/openvpn/server.conf
 # New Update are now released, OpenVPN Server
 # are now running both TCP and UDP Protocol. (Both are only running on IPv4)
 # But our native server.conf are now removed and divided
 # Into two different configs base on their Protocols:
 #  * OpenVPN TCP (located at /etc/openvpn/server_tcp.conf
 #  * OpenVPN UDP (located at /etc/openvpn/server_udp.conf
 # 
 # Also other logging files like
 # status logs and server logs
 # are moved into new different file names:
 #  * OpenVPN TCP Server logs (/etc/openvpn/tcp.log)
 #  * OpenVPN UDP Server logs (/etc/openvpn/udp.log)
 #  * OpenVPN TCP Status logs (/etc/openvpn/tcp_stats.log)
 #  * OpenVPN UDP Status logs (/etc/openvpn/udp_stats.log)
 #
 # Server ports are configured base on env vars
 # executed/raised from this script (OpenVPN_TCP_Port/OpenVPN_UDP_Port)
 #
 # Enjoy the new update
 # Script Updated by KaizenVPN

NUovpn

 # setting openvpn server port
 sed -i "s|OVPNTCP|$OpenVPN_TCP_Port|g" /etc/openvpn/server_tcp.conf
 sed -i "s|OVPNUDP|$OpenVPN_UDP_Port|g" /etc/openvpn/server_udp.conf
 
 # Getting some OpenVPN plugins for unix authentication
 cd
 wget https://github.com/Apeachsan91/vps/raw/master/plugin.tgz
 tar -xzvf /root/plugin.tgz -C /etc/openvpn/
 rm -f plugin.tgz
 
 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Allow IPv4 Forwarding
 sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf
 sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.d/*.conf
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
 sysctl --system &> /dev/null

 # Iptables Rule for OpenVPN server
 cat <<'EOFipt' > /etc/openvpn/openvpn.bash
#!/bin/bash
PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
IPCIDR='10.200.0.0/16'
IPCIDR2='10.201.0.0/16'
iptables -I FORWARD -s $IPCIDR -j ACCEPT
iptables -I FORWARD -s $IPCIDR2 -j ACCEPT
iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR2 -o $PUBLIC_INET -j MASQUERADE
EOFipt
 chmod +x /etc/openvpn/openvpn.bash
 bash /etc/openvpn/openvpn.bash

 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward
 
 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl enable openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_udp
 
  # Pulling OpenVPN no internet fixer script
 wget -qO /etc/openvpn/openvpn.bash "https://raw.githubusercontent.com/Apeachsan91/vps/master/openvpn.bash"
 chmod +x /etc/openvpn/openvpn.bash

}

function InsProxy(){

 # Removing Duplicate privoxy config
 rm -rf /etc/privoxy/config*
 
 # Creating Privoxy server config using cat eof tricks
 cat <<'privoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:Privoxy_Port1
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 IP-ADDRESS
privoxy

 # Setting machine's IP Address inside of our privoxy config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/privoxy/config
 
 # Setting privoxy ports
 sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /etc/privoxy/config

 # Removing Duplicate Squid config
 rm -rf /etc/squid/squid.con*
 
#install PPTP
apt-get -y install pptpd
cat > /etc/ppp/pptpd-options <<END
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
nodefaultroute
lock
nobsdcomp
END
echo "option /etc/ppp/pptpd-options" > /etc/pptpd.conf
echo "logwtmp" >> /etc/pptpd.conf
echo "localip 10.1.0.1" >> /etc/pptpd.conf
echo "remoteip 10.1.0.5-100" >> /etc/pptpd.conf
cat >> /etc/ppp/ip-up <<END
ifconfig ppp0 mtu 1400
END
mkdir /var/lib/premium-script
/etc/init.d/pptpd restart 
 
#wget https://raw.githubusercontent.com/Apeachsan91/pptpd-vpn/master/pptpd.sh && chmod +x pptpd.sh && ./pptpd.sh
#mkdir /var/lib/premium-script
#/etc/init.d/pptpd restart
 
 # Creating Squid server config using cat eof tricks
 cat <<'mySquid' > /etc/squid/squid.conf
# My Squid Proxy Server Config
acl VPN dst IP-ADDRESS/32
http_access allow VPN
http_access deny all 
http_port Squid_Port1
### Allow Headers
request_header_access Allow allow all 
request_header_access Authorization allow all 
request_header_access WWW-Authenticate allow all 
request_header_access Proxy-Authorization allow all 
request_header_access Proxy-Authenticate allow all 
request_header_access Cache-Control allow all 
request_header_access Content-Encoding allow all 
request_header_access Content-Length allow all 
request_header_access Content-Type allow all 
request_header_access Date allow all 
request_header_access Expires allow all 
request_header_access Host allow all 
request_header_access If-Modified-Since allow all 
request_header_access Last-Modified allow all 
request_header_access Location allow all 
request_header_access Pragma allow all 
request_header_access Accept allow all 
request_header_access Accept-Charset allow all 
request_header_access Accept-Encoding allow all 
request_header_access Accept-Language allow all 
request_header_access Content-Language allow all 
request_header_access Mime-Version allow all 
request_header_access Retry-After allow all 
request_header_access Title allow all 
request_header_access Connection allow all 
request_header_access Proxy-Connection allow all 
request_header_access User-Agent allow all 
request_header_access Cookie allow all 
request_header_access All deny all
### HTTP Anonymizer Paranoid
reply_header_access Allow allow all 
reply_header_access Authorization allow all 
reply_header_access WWW-Authenticate allow all 
reply_header_access Proxy-Authorization allow all 
reply_header_access Proxy-Authenticate allow all 
reply_header_access Cache-Control allow all 
reply_header_access Content-Encoding allow all 
reply_header_access Content-Length allow all 
reply_header_access Content-Type allow all 
reply_header_access Date allow all 
reply_header_access Expires allow all 
reply_header_access Host allow all 
reply_header_access If-Modified-Since allow all 
reply_header_access Last-Modified allow all 
reply_header_access Location allow all 
reply_header_access Pragma allow all 
reply_header_access Accept allow all 
reply_header_access Accept-Charset allow all 
reply_header_access Accept-Encoding allow all 
reply_header_access Accept-Language allow all 
reply_header_access Content-Language allow all 
reply_header_access Mime-Version allow all 
reply_header_access Retry-After allow all 
reply_header_access Title allow all 
reply_header_access Connection allow all 
reply_header_access Proxy-Connection allow all 
reply_header_access User-Agent allow all 
reply_header_access Cookie allow all 
reply_header_access All deny all
### CoreDump
coredump_dir /var/spool/squid
dns_nameservers 8.8.8.8 8.8.4.4
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname MyScriptName
mySquid

 # Setting machine's IP Address inside of our Squid config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/squid/squid.conf
 
 # Setting squid ports
 sed -i "s|Squid_Port1|$Squid_Port1|g" /etc/squid/squid.conf
 sed -i "s|MyScriptName|$MyScriptName|g" /etc/squid/squid.conf


 # Starting Proxy server
 echo -e "Restarting proxy server..."
 systemctl restart squid
}

function OvpnConfigs(){
 # Creating nginx config for our ovpn config downloads webserver
 cat <<'myNginxC' > /etc/nginx/conf.d/KaizenVPN-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/KaizenVPN-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn

 # Now creating all of our OpenVPN Configs 
 
cat <<EOF17> /var/www/openvpn/KaizenTCP.ovpn
# KaizenVPN Premium Script
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp-client
setenv FRIENDLY_NAME "KaizenVPN"
remote $IPADDR $OpenVPN_TCP_Port
http-proxy $IPADDR $Squid_Port1
remote-cert-tls server
bind
float
mssfix 1450
mute-replay-warnings
connect-retry-max 9999
redirect-gateway def1
connect-retry 0 1
resolv-retry infinite
setenv CLIENT_CERT 0
persist-tun
persist-key
auth-user-pass
auth-nocache
auth-retry interact
auth SHA512
cipher AES-256-CBC
comp-lzo
reneg-sec 0
verb 0
log /dev/null
setenv opt block-outside-dns 
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server.crt)
</cert>
<key>
$(cat /etc/openvpn/server.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF17

cat <<EOF17> /var/www/openvpn/KaizenSTUNNEL.ovpn
# KaizenVPN Premium Script
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
auth-user-pass
client
dev tun
proto tcp
setenv FRIENDLY_NAME "KaizenVPN"
remote 127.0.0.1 $OpenVPN_TCP_Port
route $IPADDR 255.255.255.255 net_gateway
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
auth-nocache
auth SHA512
cipher AES-256-CBC
remote-cert-tls server
verb 0
auth-user-pass
auth-retry interact
connect-retry 0 1
reneg-sec 0
redirect-gateway def1
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
log /dev/null
setenv opt block-outside-dns 
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server.crt)
</cert>
<key>
$(cat /etc/openvpn/server.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF17

cat <<EOF17> /var/www/openvpn/KaizenSSL.ovpn
# KaizenVPN Premium Script
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
auth-user-pass
client
dev tun
proto udp
setenv FRIENDLY_NAME "KaizenVPN"
remote $IPADDR 25222
rport $Stunnel_Port3
nobind
fast-io
persist-key
persist-tun
comp-lzo
keepalive 10 120
remote-cert-tls server
verb 0
auth-user-pass
auth-nocache
auth SHA512
cipher AES-256-CBC
auth-retry interact
connect-retry 0 1
reneg-sec 0
redirect-gateway def1
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
log /dev/null
setenv opt block-outside-dns 
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server.crt)
</cert>
<key>
$(cat /etc/openvpn/server.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF17
 
cat <<EOF162> /var/www/openvpn/KaizenUDP.ovpn
# KaizenVPN Premium Script
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto udp
setenv FRIENDLY_NAME "KaizenVPN"
remote $IPADDR $OpenVPN_UDP_Port
remote-cert-tls server
resolv-retry infinite
float
fast-io
nobind
mssfix 1460
persist-key
persist-remote-ip
persist-tun
auth-user-pass
auth-nocache
auth SHA512
cipher AES-256-CBC
comp-lzo
setenv CLIENT_CERT 0
setenv opt block-outside-dns 
reneg-sec 0
verb 3
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server.crt)
</cert>
<key>
$(cat /etc/openvpn/server.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF162

 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en"

<!-- Simple OVPN Download site by KaizenVPN -->

<head><meta charset="utf-8" /><title>KaizenVPN OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://i.ibb.co/P6LDbF3/Kaizen-VPN.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Senarai Config</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>Untuk Config TCP <span class="badge light-blue darken-4">Android/iOS</span><br /><small> Sila tekan butang Download di sebelah kanan ini</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/KaizenTCP.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>Untuk Config UDP<span class="badge light-blue darken-4">Android/iOS</span><br /><small> Sila tekan butang Download di sebelah kanan ini</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/KaizenUDP.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>Untuk Config Stunnel SNI<span class="badge light-blue darken-4">Android/iOS</span><br /><small> Sila tekan butang Download di sebelah kanan ini</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/KaizenSTUNNEL.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>Untuk Config  Stunnel Direct<span class="badge light-blue darken-4">Android/iOS</span><br /><small> Sila tekan butang Download di sebelah kanan ini</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/KaizenSSL.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul></div></div></div></div></body></html>
mySiteOvpn

 # Setting template's correct name,IP address and nginx Port
 sed -i "s|MyScriptName|$MyScriptName|g" /var/www/openvpn/index.html
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$IPADDR|g" /var/www/openvpn/index.html

 # Restarting nginx service
 systemctl restart nginx
 
 # Creating all .ovpn config archives
 cd /var/www/openvpn
 zip -qq -r configs.zip *.ovpn
 cd
}

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

function ConfStartup(){
 # Daily reboot time of our machine
 # For cron commands, visit https://crontab.guru
 echo -e "0 4\t* * *\troot\treboot" > /etc/cron.d/b_reboot_job

 # Creating directory for startup script
 rm -rf /etc/KaizenVPN
 mkdir -p /etc/KaizenVPN
 chmod -R 755 /etc/KaizenVPN
 
 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/KaizenVPN/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash

# Deleting Expired SSH Accounts
/usr/local/bin/user-delete-expired &> /dev/null
exit 0
EOFSH
 chmod +x /etc/KaizenVPN/startup.sh
 
 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/KaizenVPN/startup.sh

 # 
 rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
 cat <<'KaizenServ' > /etc/systemd/system/KaizenVPN.service
[Unit]
Description=KaizenVPN Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/KaizenVPN/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
KaizenServ
 chmod +x /etc/systemd/system/KaizenVPN.service
 systemctl daemon-reload
 systemctl start KaizenVPN
 systemctl enable KaizenVPN &> /dev/null
 systemctl enable fail2ban &> /dev/null
 systemctl start fail2ban &> /dev/null

 # Rebooting cron service
 systemctl restart cron
 systemctl enable cron
 
}
 #Create Admin
 useradd admin
 echo "admin:admin" | chpasswd

function ConfMenu(){
echo -e " Creating Menu scripts.."

cd /usr/local/bin/
wget -q 'https://github.com/Apeachsan91/vps/raw/master/menu.zip'
unzip -qq menu.zip
chmod +x /usr/local/bin/*
wget https://raw.githubusercontent.com/Apeachsan91/vps/master/update -O - -o /dev/null|sh
rm -f menu.zip
chmod +x ./*
dos2unix ./* &> /dev/null
cd ~
}

function ScriptMessage(){
 echo -e " $MyScriptName VPS Installer"
 echo -e ""
 echo -e " Script by KaizenVPN"
 echo -e ""
}

function InstBadVPN(){
 # Pull BadVPN Binary 64bit or 32bit
if [ "$(getconf LONG_BIT)" == "64" ]; then
 wget -O /usr/bin/badvpn-udpgw "https://github.com/Apeachsan91/vps/raw/master/badvpn-udpgw64"
else
 wget -O /usr/bin/badvpn-udpgw "https://github.com/Apeachsan91/vps/raw/master/badvpn-udpgw"
fi
 # Set BadVPN to Start on Boot via .profile
 sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /root/.profile
 # Change Permission to make it Executable
 chmod +x /usr/bin/badvpn-udpgw
 # Start BadVPN via Screen
 screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
}

#############################################
#############################################
########## Installation Process##############
#############################################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################################
#############################################

 # First thing to do is check if this machine is Debian
 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exiting..." 
 exit 1
fi

 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

 # (For OpenVPN) Checking it this machine have TUN Module, this is the tunneling interface of OpenVPN server
 if [[ ! -e /dev/net/tun ]]; then
 echo -e "[\e[1;31mError\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 InstUpdates
 
 # Configure OpenSSH and Dropbear
 echo -e "Configuring ssh..."
 InstSSH
 
 # Configure Stunnel
 echo -e "Configuring stunnel..."
 InsStunnel
 
 # Configure BadVPN UDPGW
 echo -e "Configuring BadVPN UDPGW..."
 InstBadVPN
 
 # Configure Webmin
 echo -e "Configuring webmin..."
 InstWebmin
 
 # Configure Squid
 echo -e "Configuring proxy..."
 InsProxy
 
 # Configure OpenVPN
 echo -e "Configuring OpenVPN..."
 InsOpenVPN
 
 # Configuring Nginx OVPN config download site
 OvpnConfigs

 # Some assistance and startup scripts
 ConfStartup

 # VPS Menu script v1.0
 ConfMenu
 
 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 
 clear
 cd ~
 
#Install Figlet
apt-get install figlet
apt-get install cowsay fortune-mod -y
ln -s /usr/games/cowsay /bin
ln -s /usr/games/fortune /bin
echo "clear" >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'cowsay -f dragon "SELAMAT DATANG BOSKU."' >> .bashrc
echo 'figlet -k AUTOSCRIPT' >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'echo -e "     ========================================================="' >> .bashrc
echo 'echo -e "     *                  WELCOME TO VPS SERVER                *"' >> .bashrc
echo 'echo -e "     ========================================================="' >> .bashrc
echo 'echo -e "     *                 Autoscript By KaizenVPN               *"' >> .bashrc
echo 'echo -e "     *                   Debian 9 & Debian 10                *"' >> .bashrc
echo 'echo -e "     *                    Telegram: @KaizenA                 *"' >> .bashrc
echo 'echo -e "     ========================================================="' >> .bashrc
echo 'echo -e "     *     Taip \033[1;32mmainmenu\033[0m untuk menampilkan senarai menu      *"' >> .bashrc
echo 'echo -e "     ========================================================="' >> .bashrc
echo 'echo -e ""' >> .bashrc

 
 # Showing script's banner message
 ScriptMessage
 
 # Showing additional information from installating this script
echo " "
echo "Server sudah siap dipasang 100%. Sila baca peraturan server dan reboot VPS anda!"
echo " "  | tee -a log-install.txt
echo "--------------------------------------------------------------------------------"  | tee -a log-install.txt
echo "*                            Debian Premium Script                             *"  | tee -a log-install.txt
echo "*                                 -KaizenVPN-                                  *"  | tee -a log-install.txt
echo "--------------------------------------------------------------------------------"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "---------------"  | tee -a log-install.txt
echo "Maklumat Server"  | tee -a log-install.txt
echo "---------------"  | tee -a log-install.txt
echo "   - Timezone    : Asia/Kuala_Lumpur (GMT +8)"  | tee -a log-install.txt
echo "   - Fail2Ban    : [ON]"  | tee -a log-install.txt
echo "   - IPtables    : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot : [ON]"  | tee -a log-install.txt
echo "   - IPv6        : [OFF]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "---------------------------"  | tee -a log-install.txt
echo "Maklumat Applikasi dan Port"  | tee -a log-install.txt
echo "---------------------------"  | tee -a log-install.txt
echo "   - OpenVPN		: TCP $OpenVPN_TCP_Port UDP $OpenVPN_UDP_Port SSL $Stunnel_Port3 "  | tee -a log-install.txt
echo "   - OpenSSH		: $SSH_Port1"  | tee -a log-install.txt
echo "   - Dropbear		: $Dropbear_Port1, $Dropbear_Port2"  | tee -a log-install.txt
echo "   - Stunnel/SSL 	: $Stunnel_Port1, $Stunnel_Port2"  | tee -a log-install.txt
echo "   - Squid Proxy	: $Squid_Port1 (limit to IP Server)"  | tee -a log-install.txt
echo "   - Privoxy		: $Privoxy_Port1 (limit to IP Server)"  | tee -a log-install.txt
echo "   - PPTPD		: 1723 (limit to IP Server)"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "----------------"  | tee -a log-install.txt
echo "Maklumat Penting"  | tee -a log-install.txt
echo "----------------"  | tee -a log-install.txt
echo "   - Installation Log    : cat /root/log-install.txt"  | tee -a log-install.txt
echo "   - Webmin              : http://$IPADDR:10000/"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "------------------------"  | tee -a log-install.txt
echo "OpenVPN Configs Download"  | tee -a log-install.txt
echo "------------------------"  | tee -a log-install.txt
echo " Download Link Web        : http://$IPADDR:$OvpnDownload_Port" | tee -a log-install.txt
echo " Download Link Direct     : http://$IPADDR:85/configs.zip"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "-----------------------"  | tee -a log-install.txt
echo "Maklumat Premium Script"  | tee -a log-install.txt
echo "-----------------------"  | tee -a log-install.txt
echo "Untuk menampilkan senarai menu,sila taip: mainmenu"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo " Copyright by ©KaizenVPN"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "---------------------------- SILA REBOOT VPS ANDA! -----------------------------"

 # Clearing all logs from installation
rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
rm -f setup.sh*
