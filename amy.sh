#############################
#############################
# Script name
MyScriptName='HelloKittyVPN-DEB9&10 Script'

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
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=MY, ST=MY, L=Malaysia, O=HelloKittyVPN, OU=admin, CN=HelloKittyChannel/name=HelloKittyVPN/emailAddress=hellokitty@gmail.com
        Validity
            Not Before: May 29 20:11:51 2020 GMT
            Not After : May 27 20:11:51 2030 GMT
        Subject: C=MY, ST=MY, L=Malaysia, O=HelloKittyVPN, OU=admin, CN=server/name=HelloKittyVPN/emailAddress=hellokitty@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:ca:ad:4f:19:ab:7e:c1:0f:8e:4e:e6:bd:12:8e:
                    ce:39:38:9f:1d:91:d6:3b:a2:d1:29:59:2d:78:2f:
                    d1:b5:9d:4e:b9:ab:bd:6b:00:01:72:fa:ce:a8:9e:
                    e0:2a:fc:fe:da:e3:a6:6d:eb:b6:c9:08:a8:b6:98:
                    48:6b:56:90:20:9e:f6:a7:5a:a5:52:a1:8b:88:98:
                    6b:9a:ed:1e:44:33:a8:52:f9:e7:25:30:fa:c7:a6:
                    74:6c:f4:01:ff:82:ca:cc:be:79:56:f7:91:2d:46:
                    7e:9e:db:74:c4:1f:ec:28:ef:93:d8:3e:ad:41:32:
                    63:f2:c4:48:c0:83:26:3d:7d:fb:3b:29:d7:08:fe:
                    7e:2d:b8:91:9d:f0:42:87:8c:a0:84:e9:bb:04:76:
                    d3:ba:91:af:6c:bc:56:7e:77:cd:1a:87:64:90:2b:
                    82:cf:b3:40:c8:17:3b:f9:8a:a9:6c:32:a0:51:d2:
                    74:a6:0e:ec:d4:4f:fc:1d:6e:4c:f7:76:09:db:bb:
                    5e:1a:a3:b4:62:99:d7:d0:b8:b8:1c:0b:22:f5:51:
                    94:ef:5c:67:8d:03:74:df:2c:0f:40:c0:51:b9:21:
                    71:12:ab:41:3e:e3:c3:29:65:63:65:9e:0a:39:9e:
                    89:e7:d7:77:df:70:38:b9:85:fc:fb:7e:f3:a7:d8:
                    5d:ab:1b:36:42:d5:ec:fc:8b:3c:75:f1:34:ca:fa:
                    03:67:b4:37:e9:d7:3a:78:fc:79:45:db:97:70:1a:
                    5e:91:86:95:7b:a3:c4:bc:ee:b0:e2:e4:66:6c:17:
                    f1:ed:e9:d2:62:69:2f:05:c0:44:fc:01:f0:e6:47:
                    3b:1d:2e:87:3d:d6:13:de:5b:c3:62:0c:4f:a7:14:
                    a2:eb:0a:3d:41:08:3f:a1:b8:db:2b:6b:fc:a9:ad:
                    3e:80:3a:da:05:40:67:bd:31:91:6c:66:29:7a:e5:
                    8b:95:df:28:3f:a3:9b:de:ca:56:a2:22:6f:6f:f9:
                    51:67:c9:9b:31:70:b3:6b:c1:be:54:b9:a9:95:c9:
                    f7:99:ee:3a:a8:49:af:49:9e:f4:98:fb:f1:3d:4c:
                    54:3b:60:25:46:a1:5c:6d:b7:a1:45:9c:85:8e:f9:
                    d0:0f:37:43:e0:9c:04:27:0e:2f:38:4f:f1:71:1d:
                    ee:55:a0:ec:49:67:b3:e7:58:d1:ff:ba:25:1d:26:
                    6a:18:4a:93:b1:44:0c:f8:1a:db:40:8f:b8:24:9f:
                    f5:cb:c2:13:11:b0:8c:d8:12:68:76:f3:dc:fe:34:
                    be:b4:22:00:50:31:02:2d:65:62:61:9f:cb:ff:f6:
                    c4:35:54:6c:55:4e:85:de:f9:ff:0e:9d:80:30:38:
                    6f:f7:53
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier: 
                68:E8:77:E2:8C:64:EF:E8:DF:AF:30:51:AD:EE:9F:61:BE:83:64:CE
            X509v3 Authority Key Identifier: 
                keyid:B3:FA:0A:7D:22:D6:CB:9E:CC:0A:CF:1A:48:C5:82:19:A7:78:F6:D9
                DirName:/C=MY/ST=MY/L=Malaysia/O=HelloKittyVPN/OU=admin/CN=HelloKittyChannel/name=HelloKittyVPN/emailAddress=hellokitty@gmail.com
                serial:3F:5C:AF:F3:78:1A:A9:F9:E1:6C:7A:2D:EE:CD:22:E8:89:6E:0F:ED

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
    Signature Algorithm: sha256WithRSAEncryption
         81:69:e5:d6:35:6d:9a:80:36:62:7a:88:d6:46:ed:f2:a4:69:
         00:d0:e4:06:a1:e5:bb:c1:76:6a:c5:e7:14:b6:96:65:52:40:
         49:a7:8b:54:a7:9e:64:1b:20:63:17:0c:40:d5:ec:85:d4:9f:
         c2:ab:0d:87:04:ad:4e:50:70:23:29:70:66:6d:4e:9f:d7:27:
         3b:fc:27:e5:5a:ba:b9:3b:94:95:02:cd:9f:8e:94:d0:a8:3f:
         e8:e9:71:49:fa:64:2b:ea:9a:c7:77:95:66:be:cc:e7:7a:90:
         ff:2e:f5:32:31:e6:16:5a:68:3d:2a:88:e2:0d:ea:5a:04:8f:
         da:ea:ba:14:01:e5:08:95:9d:b2:82:cc:48:a0:c4:e8:1e:65:
         17:21:c0:c8:d7:b3:79:df:4d:0b:d7:b6:d3:67:83:5d:f6:90:
         d4:0a:09:bb:b9:7a:83:04:04:a3:e1:f2:ce:80:bd:fe:5d:68:
         50:75:6e:29:25:d4:f2:f6:af:e1:ab:ed:a3:d9:79:63:b0:61:
         d6:b1:bf:09:f2:c4:8e:c3:42:36:8c:7f:4d:28:cc:12:f6:24:
         96:2c:31:97:bf:6c:9b:c2:65:f5:9b:72:bb:51:1f:c7:07:50:
         f0:a8:e0:bf:fa:9e:85:81:fa:61:52:80:20:37:a3:c8:82:c5:
         63:0e:f8:3e:36:38:47:a4:ee:49:77:74:a2:01:04:99:b1:4f:
         1d:9f:64:7b:ae:37:23:6c:9b:6b:62:6d:e4:67:73:e3:99:2f:
         26:c0:2c:58:00:63:9a:8d:f1:62:78:81:13:8c:94:16:1a:06:
         3e:18:35:5a:e2:e6:e8:1a:0f:73:44:aa:91:d5:33:22:86:13:
         86:25:9b:dd:4e:61:58:ab:84:5b:5f:16:c2:f3:61:f9:60:f4:
         73:00:7c:53:48:90:b4:69:be:ee:8b:36:4b:19:b0:e8:25:ea:
         e9:fc:03:1e:f9:4d:02:c7:58:74:f4:96:3a:ac:2a:fa:9a:fe:
         69:4d:e5:60:e1:c2:04:fe:c4:f1:e5:7d:24:e8:ab:65:0c:fd:
         70:83:70:d8:76:18:f0:d1:0e:7e:22:3f:7e:48:91:ba:c9:82:
         dd:63:cd:02:65:f2:a7:84:62:cc:1f:3d:31:5c:a9:38:67:eb:
         b6:12:08:3a:47:62:35:0f:a6:64:aa:d2:63:1d:c7:1e:75:e5:
         c7:db:d7:50:dc:7b:3a:29:15:92:7c:70:49:52:c5:f2:e4:fa:
         95:4c:41:81:62:1a:a3:07:f0:3e:41:a9:b7:56:3d:94:c1:22:
         e9:f1:54:7d:6c:b2:30:c2:5a:5e:af:47:ab:71:97:a1:8f:7f:
         03:d8:9a:3e:ac:ed:ea:f3
-----BEGIN CERTIFICATE-----
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
q3GXoY9/A9iaPqzt6vM=
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQDKrU8Zq37BD45O
5r0Sjs45OJ8dkdY7otEpWS14L9G1nU65q71rAAFy+s6onuAq/P7a46Zt67bJCKi2
mEhrVpAgnvanWqVSoYuImGua7R5EM6hS+eclMPrHpnRs9AH/gsrMvnlW95EtRn6e
23TEH+wo75PYPq1BMmPyxEjAgyY9ffs7KdcI/n4tuJGd8EKHjKCE6bsEdtO6ka9s
vFZ+d80ah2SQK4LPs0DIFzv5iqlsMqBR0nSmDuzUT/wdbkz3dgnbu14ao7RimdfQ
uLgcCyL1UZTvXGeNA3TfLA9AwFG5IXESq0E+48MpZWNlngo5nonn13ffcDi5hfz7
fvOn2F2rGzZC1ez8izx18TTK+gNntDfp1zp4/HlF25dwGl6RhpV7o8S87rDi5GZs
F/Ht6dJiaS8FwET8AfDmRzsdLoc91hPeW8NiDE+nFKLrCj1BCD+huNsra/yprT6A
OtoFQGe9MZFsZil65YuV3yg/o5veylaiIm9v+VFnyZsxcLNrwb5UuamVyfeZ7jqo
Sa9JnvSY+/E9TFQ7YCVGoVxtt6FFnIWO+dAPN0PgnAQnDi84T/FxHe5VoOxJZ7Pn
WNH/uiUdJmoYSpOxRAz4GttAj7gkn/XLwhMRsIzYEmh289z+NL60IgBQMQItZWJh
n8v/9sQ1VGxVToXe+f8OnYAwOG/3UwIDAQABAoICAQCyMKsxw3BepqGURxMGRN2U
u25RXg2/QseoFcp/N3OlvBch8JdJgqjDgTS+VWh7AxHCOpHxZGLA3scOOla5YFK5
C2mJ+40MWBFIV9GLVVvd1Jjx0trg/O4PKA6GWAWFsmVAm1otFt3hs2/RlNpVMEe+
Odx/K6PBhV8QangYIXY2bBO8kW2Ib89ZvULxW/HyILZkBOay5xIBnuJftDpLWGLQ
JydIBaktmMik4qCNJdcM1HnVVjXOZaLcizH6YiZzDqleMZ5rx2/pnJ582Fqt9TCY
BFDwHQrBlL9lEuSaJjvziy5RnpVviGnmdEhuaANPY06Vsf+nR4/ntKCWMKhh8j1u
h/yP0vpZ/vlOrQobkZtNVvDD7rtunTcjG6BY3jX2iUKZZTGBxuxIBduhTlzPOCQE
VpS4/fKRFwm1X7cyW+Gt/7/IvRQpPPiPqyPipC2Xo6z7xEP716V6WbJwS5Y04T87
rCUjmHi48HT/uV1CTKS7AGIc0bAoMlAH2twZjRhWSfABMCCR9Q/hglhmKRfRCTaD
naEcXeYurSUS3z763Vh+qssKQvEBjR0ul9L7qpzizMxcU5F3LV0xJ0VLg0ou+I4d
Fg/ttYiLkLk6DsR8qg6NWMsNj9uKP+I6ERC9UY/UcUc2bQbqGPr+qpllCpWiatC3
4GRpWxDSyjdqaBN2WxHTiQKCAQEA8UsNLxS921OuvHjBA1al4f7RwEqDnaBEBQJZ
ktn1FPJ4tFqrarruf3MjvklGNAx1Ghjx13cnisxgY1XzlDA2VK1B//FvovVDyjKo
vRbAAmCctvZWIzE9yudlBLJt2p5s2lzEP9hGovh43VKqW0U+zB0TChXUT8TT1Om+
64fhbx0ES5XbCC3wRG5j1BMdh3edNBsmaDhZtqqsGywGQv2FjlKGxRarJcTY7zqh
cZjM/7CH19nU3fHxd+Ty5Dy/DSnZGr/6nuoD2v67AFwuTr/fMVqKdoCkcJ3JHpXz
YwClbmJMihm1tB3ja1NWpTgZvwE8n2qGlVsM6QjFt7aPdz0eNwKCAQEA1we4lFkJ
vj/3/ihue5iTzLslJTKbJybPqin06m7MFcA8BiLbQqYR9RGa77TiUU61+lTqrhVI
IZgQtrG3iJOmXL4mDBUYwPy+qpmSHoQPhFedBdchaXinNwP3AW6Z+PbInEOFDmrA
/rwu82PoFRWDwwoW2wzkQ0+MZzu82I5wd8Wqg+btF9cPa3jjYxQXlBEgY97XlBxS
v2o+lrDivOqbVmB4XDLomzdmzbUFE/18Ty16Igj+CoM+ImKi0463Qo3T8+87XYlN
C6AJN+pU76B1WRnFkUlLezExPxm/GtmgrfYukjQQ9dn4MTawblYnu2OBsCQGJbjG
PknVC3StIEKBxQKCAQBXwV7zH40JJn8nZpdz+mBsN/va/n6tpir202r2YLSkwKar
mUo8j+3LhnmabBXPOjSgoC/cmCZWcYwgtJLY80vfMgAN8KYUUzUrZY8+7fY5Jx/3
3tFnDTKXB98SfT48w199bz2kpqjR/qIehEEW3rE/FNfm1BeaR1BvX++iw5F2kswM
HV1CtUpr6OX/rFASA6u11qX6Q3xFVf8wBqvkU0XuhA8lwN/P5a6sGtu6b8MmvvI4
y62CZsrWOvsnjPxC8lRWSToB78QlMn2aXOwukdO/pFk1TgYAOzJ5IDobaJHB+pgx
pbYS4sfiMbYScrvSXsXIiLqXuTyRyDH4Zbn5uM2zAoIBAAe5PUYG1LTCs3OrnBxQ
ZK6r4i+t26jSWg8wpp1tEWOOnhlSUzHXqTl2QmxtwNtOynaNakiKdybNwXvucjsz
onweUFuKvnLgITEbhwYVlEEarIczLP4O2WK+f7bLdDhfFOGYA0V7TCdaNw2C/ykS
tsLgr+V6VxCb4N0sZiIZK60BqphGSSncDa+8jd5XMGmfG9y6el/VjJtXg5wCCoLi
omW93VTidzxsBwNIh0AqkLZ/Wa2zSPyzrh2qEVMsAyUe1wgiBa3caqoKO4qInjhl
ORHUPSZ0zYNFRxGPKTAbtQvKle2mdR1/kMyjvD6aVZ8DefsLsDTWqDhAiqh4rmdE
PEkCggEABZE8ddeRj0hZkYJ0KwKX9ufj5gYCBk+CBwOuB6DHxKG3VVEwGaNaIMxw
sK33sc/wqAWRzIW06UJwljeVxP3EpT0QieT8joKn0FJH9/4j8Ce/AtBEgogzGYFA
NF4lp7F9l58EdmzJQZANp5JiUEnwhYfSxtdzXKebyy2EIbXhxOrcxN4tdE0MydL6
PIsaaQwaJ2p5HTOuz9YgscgvEqbnvTtEY3ar608igwyoCTHdtno39CEeAM7DAeXC
Uss1AcYqwYKJQhm+yVMN3Y5iSJ/YzQfamv6XLdDEmIVpJNm2tBCADKktXiyaNOfG
nju9TTeq/j2DTq/S+7GcQX91jqKWMQ==
-----END PRIVATE KEY-----
EOF10
 cat <<'EOF13'> /etc/openvpn/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA/6dLbxL7t8JlfbcDnzRlKIqyMIRsRUXMNtYELM7Ig5BJVWGrI9hQ
LM06rNNcNWAekJOKZhr6b2MDG2PlJk/+EotpGIcurSXBnoLvn0pnC11HjWiGLscd
5dT50Hfq6TgUTnGQgi/SjtHHYQ/gNm55gNoUatyHWGxyZ/XeFYjbRBd//g4MmCna
KsQ58XBes9kwtF22Kl7cRMnbqcK+TkKwuhJTa8TsAJ8ZM+83+8aqMXHkMUhgg6Id
hbAllTb1moU7Xn8EV+reLEaXKEYE70/JoQU5Kw4p2GoFzHADGatedKzrBaxO76fz
qCLWfb/4GjhvZrWAnzTRXDjOC647+RRjIwIBAg==
-----END DH PARAMETERS-----
EOF13
 cat <<'EOF19'> /etc/openvpn/ta.key
-----BEGIN OpenVPN Static key V1-----
7b11777be700dd432417e8e197c274c1
a69fde670ca796e4581a401b2ddee86c
ea678a7aaacebda04c11a2e3d42ff093
3264d7fd29f50410038518f889a71d85
44364e71d4369631c53208fd584d637e
acfe15f645f0c4fc74681fe2ac250e73
3f54898793bd7150ba28d3c1a0c549c5
a0868a4209205668efb650267047d624
2b7b510ceab7f0cc0657d1b365ddcc8b
20f0e7850fc903958b014a458a6806a5
0ff7be5420037b2fa1c92d80f109d017
154bd188e0e808a50b4a9f1aaeb3bcde
45dbc058f01f9c239dc2880f90364747
ab797acc0600497dd6d9153ed3401f30
b3cf6d03a188aac1fdcda4eef63f86cf
73427ff3c989c60bc57daae81b97cb9c
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
 cat <<'myNginxC' > /etc/nginx/conf.d/HelloKittyVPN-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/HelloKittyVPN-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn

 # Now creating all of our OpenVPN Configs 
 
cat <<EOF17> /var/www/openvpn/HKTCP.ovpn
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp-client
setenv FRIENDLY_NAME "HelloKittyVPN"
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

cat <<EOF17> /var/www/openvpn/HKSTUNNEL.ovpn
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
auth-user-pass
client
dev tun
proto tcp
setenv FRIENDLY_NAME "HelloKittyVPN"
remote 127.0.0.1 $OpenVPN_TCP_Port
route $IPADDR 255.255.255.255 net_gateway
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
auth-nocache
auth none
cipher none
remote-cert-tls server
tls-client
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
EOF17

cat <<EOF17> /var/www/openvpn/HKSSL.ovpn
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
auth-user-pass
client
dev tun
proto udp
setenv FRIENDLY_NAME "HelloKittyVPN"
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
tls-client
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
 
cat <<EOF162> /var/www/openvpn/HKUDP.ovpn
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto udp
setenv FRIENDLY_NAME "HelloKittyVPN"
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

<!-- Simple OVPN Download site by HelloKittyVPN -->

<head><meta charset="utf-8" /><title>HelloKittyVPN OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Senarai Config</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>Untuk Config TCP <span class="badge light-blue darken-4">Android/iOS</span><br /><small> Sila tekan butang Download di sebelah kanan ini</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/HKTCP.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>Untuk Config UDP<span class="badge light-blue darken-4">Android/iOS</span><br /><small> Sila tekan butang Download di sebelah kanan ini</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/HKUDP.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>Untuk Config Stunnel SNI<span class="badge light-blue darken-4">Android/iOS</span><br /><small> Sila tekan butang Download di sebelah kanan ini</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/HKSTUNNEL.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>Untuk Config  Stunnel Direct<span class="badge light-blue darken-4">Android/iOS</span><br /><small> Sila tekan butang Download di sebelah kanan ini</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/HKSSL.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul></div></div></div></div></body></html>
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
 rm -rf /etc/HelloKittyVPN
 mkdir -p /etc/HelloKittyVPN
 chmod -R 755 /etc/HelloKittyVPN
 
 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/HelloKittyVPN/startup.sh
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
 chmod +x /etc/HelloKittyVPN/startup.sh
 
 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/HelloKittyVPN/startup.sh

 # 
 rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
 cat <<'HelloKittyServ' > /etc/systemd/system/HelloKittyVPN.service
[Unit]
Description=HelloKittyVPN Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/HelloKittyVPN/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
HelloKittyServ
 chmod +x /etc/systemd/system/HelloKittyVPN.service
 systemctl daemon-reload
 systemctl start HelloKittyVPN
 systemctl enable HelloKittyVPN &> /dev/null
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
 echo -e " Script by HelloKittyVPN"
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
echo 'cowsay -f dragon "HELLO KITTY CHANNEL."' >> .bashrc
echo 'figlet -k AUTOSCRIPT' >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'echo -e "     ========================================================="' >> .bashrc
echo 'echo -e "     *                  WELCOME TO VPS SERVER                *"' >> .bashrc
echo 'echo -e "     ========================================================="' >> .bashrc
echo 'echo -e "     *                 Autoscript By HelloKittyVPN           *"' >> .bashrc
echo 'echo -e "     *                   Debian 9 & Debian 10                *"' >> .bashrc
echo 'echo -e "     *                   Telegram: @amymariah                *"' >> .bashrc
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
echo "*                               -HelloKittyVPN-                                *"  | tee -a log-install.txt
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
echo " Copyright by ©HelloKittyVPN"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "---------------------------- SILA REBOOT VPS ANDA! -----------------------------"

 # Clearing all logs from installation
rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
rm -f amy.sh*
