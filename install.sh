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

# Stunnel Ports
Stunnel_Port1='443' # through Dropbear
Stunnel_Port2='444' # through OpenSSH

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
 apt-get install gnupg tcpdump grepcidr dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid -y

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
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 
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
MyStunnelC

# setting stunnel ports
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$(netstat -tlnp | grep -i dropbear | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
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
cipher none
auth none
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
cipher none
auth none
myOpenVPNconf2

  cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIHBzCCBO+gAwIBAgIUJWekorsiMtlPx4dLr6yh1teIZogwDQYJKoZIhvcNAQEL
BQAwgasxCzAJBgNVBAYTAk1ZMQ4wDAYDVQQIEwVTYWJhaDEWMBQGA1UEBxMNS290
YSBLaW5hYmFsdTEVMBMGA1UEChMMS2FpemVuVlBOLmNvMRYwFAYDVQQLEw1LYWl6
ZW52cG4ub3JnMRIwEAYDVQQDEwlLYWl6ZW5WUE4xDzANBgNVBCkTBkthaXplbjEg
MB4GCSqGSIb3DQEJARYRaGF6Ym95ekBnbWFpbC5jb20wHhcNMjAwNTAzMTY1OTAz
WhcNMzAwNTAxMTY1OTAzWjCBqzELMAkGA1UEBhMCTVkxDjAMBgNVBAgTBVNhYmFo
MRYwFAYDVQQHEw1Lb3RhIEtpbmFiYWx1MRUwEwYDVQQKEwxLYWl6ZW5WUE4uY28x
FjAUBgNVBAsTDUthaXplbnZwbi5vcmcxEjAQBgNVBAMTCUthaXplblZQTjEPMA0G
A1UEKRMGS2FpemVuMSAwHgYJKoZIhvcNAQkBFhFoYXpib3l6QGdtYWlsLmNvbTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANXy1RODy3bXvms6fWdV3rED
++5qLMpH3zh9xaX8wHAxSlSsDfACFaZNjBX9PcyGqWAErLx2Ev89lCBLDBoWCkPF
rJ6h2HmXku7i2Yc8WPqCaIWyD+VQGkZ4mGeEFeIacllPosRjfO9Fccc1Mmb/lpCw
swb72lKGZFOa0DDZNFm3UMUvug2XUNnqcHim+icWKfyJ5w5zcj2HYcalU64511Zu
sKCA1DZqPgZgIY1R43S9FYCKWCXDbns0o4LrVsVTn4Z56+LFoOZjqUZPkFIZRd3s
tePXqlOiwGHNMyoFBOe6BPg3as9du2ax0aM8cKFn/L96SNiyG7gE6ySciM50ZW7n
klpnvake0nFYLS5sgV04tCrH0JcCMAJ1vvAjZmRZRMTpLMnqRHd9QPS9br0VSFFB
ChIRZ03TKEHcvUJA9L/6PJDiBGAj+SveZMEq+EkeYjZJonlIBYwQ81r0CSMtL4mv
Z3WYjzIscNaWKEqzjEPQWhk5v7d9vmsAFcgEGR9T1qfnLz3sy0O6EH6xL70Yyfxo
Jq+aoB/qg6qF02C7Y1a78CxZhr0RzZwoUijW7H7Ohnu0OIHEKBEi2kHGcRo7F69p
8P4sZmPYXU2/dPdKJKWZ7j9HsETtIzP9Xaqlw+VeeIJOiQgZNzL/sHozwKH8brUv
4Pbua6xntQQiZARsl/vnAgMBAAGjggEfMIIBGzAdBgNVHQ4EFgQUo2shX11pmcpb
Wz6RjSTQHeE1aQ8wgesGA1UdIwSB4zCB4IAUo2shX11pmcpbWz6RjSTQHeE1aQ+h
gbGkga4wgasxCzAJBgNVBAYTAk1ZMQ4wDAYDVQQIEwVTYWJhaDEWMBQGA1UEBxMN
S290YSBLaW5hYmFsdTEVMBMGA1UEChMMS2FpemVuVlBOLmNvMRYwFAYDVQQLEw1L
YWl6ZW52cG4ub3JnMRIwEAYDVQQDEwlLYWl6ZW5WUE4xDzANBgNVBCkTBkthaXpl
bjEgMB4GCSqGSIb3DQEJARYRaGF6Ym95ekBnbWFpbC5jb22CFCVnpKK7IjLZT8eH
S6+sodbXiGaIMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAF01FydA
FpF1UmYPeQ79k0Nq/CVuc5CP5f1HbEHF1CzrriEi63DtJNmEXWrQCvYi33tjDc5y
DDEtV2tD90jiSdeu2uNU31fxd9a3PIHX56PwyyFQWpd7sXcBAZRnbX0kmUWtpVRp
CuTj0xfuHnA63dsM06LOBKYSGf2ysw5sP0jQkSr8TwKvsHW+AOoOoKJ0CqkijGSY
CD469DiNijWN4Eq/A+GQMR9GF9GtQzTjB8n9MEwHnvIVOcfAZdiExhq/thrkGS0N
Wrq0g9XQCYcNgbP52CJc0vlhfqlnEZDh2uzy22iZVVSP3/WLb+9jFfrLhFyL/AKs
oR7pDwdSI9oxztwfRWi4e7qxvRDr4hAGxar7coRYM51WLnggycm5JOw5LYQkYuyg
nBGOW3ZCTxKEn1yQ5U0oprrLKuCDUjMKIZCT1KhwOpv9cKBPQ7JJi6Yobhv0MHlX
zQPi1dQenxxopw+oeeAkN0GiozyuwDFtjFy9WagPWGmTUSb8wJ3JmB22wIAjXKAI
D1CjXERhBKJy02NIZOKX7buVxt+w2dgDdQ6zKOXoOcpHoNzmjEFK+5wRm3VIq62s
PtdpRj/gU26VKou3G/DhGWHkA+CLDNCpLJ9LptNDOgqapO5/OBC1bZg+EkTYVqcg
3rfLwzLervwJ9fqoXliCRFBfqIqBeUjSbA3q
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=MY, ST=Sabah, L=Kota Kinabalu, O=KaizenVPN.co, OU=Kaizenvpn.org, CN=KaizenVPN/name=Kaizen/emailAddress=hazboyz@gmail.com
        Validity
            Not Before: May  3 17:00:21 2020 GMT
            Not After : May  1 17:00:21 2030 GMT
        Subject: C=MY, ST=Sabah, L=Kota Kinabalu, O=KaizenVPN.co, OU=KaizenVPN.org, CN=KaizenVPN/name=Kaizen/emailAddress=hazboyz@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:e9:d0:94:12:e1:1f:7d:98:58:94:6d:86:86:e2:
                    5f:b6:d2:2d:c6:bd:58:c2:b6:fe:ee:11:f5:0b:71:
                    a1:4b:28:1c:03:7d:b5:b9:ee:27:d9:62:ee:cd:81:
                    a3:55:78:b0:ac:61:b1:bc:f0:4b:fb:88:eb:ff:54:
                    0e:c4:ac:c2:5b:a8:28:74:71:89:ac:b9:08:07:b9:
                    99:bf:18:a7:2a:77:ae:88:08:17:77:e7:2b:ab:c4:
                    1b:9a:2a:16:5d:4a:9e:43:95:a8:6e:f4:e6:a9:01:
                    97:d9:b6:26:86:f7:a9:90:4a:93:1c:92:bf:ed:bb:
                    ce:9b:7a:b9:cb:c9:53:b5:68:d9:38:30:4e:58:26:
                    2c:ab:c4:be:ee:0a:15:e4:c5:e4:9f:d4:b0:5e:fc:
                    b1:53:27:5f:ad:20:af:a8:1b:fc:38:d6:a5:e2:e6:
                    3f:e5:d4:bd:6e:4a:c9:c5:83:6b:a3:f7:0f:d5:8e:
                    c1:42:bc:09:c1:dd:e3:97:5a:e0:7c:1f:a0:d4:75:
                    cc:78:f6:3f:4a:5a:c3:e1:7d:72:e0:ea:1d:a1:bb:
                    42:eb:c3:cc:bc:82:5d:89:ce:92:e9:7a:ad:36:67:
                    d0:5c:59:18:e8:88:1b:59:bd:6f:ff:2b:28:98:bb:
                    82:62:c7:8a:ab:d8:8c:5e:e5:7b:47:b6:28:a4:3a:
                    1f:7e:0b:fe:78:be:24:cd:ad:46:f2:31:54:72:a0:
                    ff:40:5b:53:fc:cc:d7:9d:aa:df:05:0b:bf:16:49:
                    74:d4:f8:7a:f1:a4:08:2b:b0:0c:9e:76:b2:f1:ce:
                    0e:3d:6f:c9:7a:ae:e1:e1:9d:56:fe:5e:77:35:34:
                    61:f8:46:d9:23:55:1d:3c:85:fc:1b:bc:b1:32:cb:
                    17:1a:aa:0a:fb:78:3d:0f:24:06:34:dd:14:9e:a5:
                    c7:fb:db:10:72:8d:60:8f:28:e6:29:22:bc:8c:2d:
                    be:96:35:c5:7c:09:bf:5a:f0:27:87:06:77:04:0d:
                    4a:0d:4d:b2:ea:3c:2f:17:b4:5a:f5:ea:31:25:43:
                    59:ed:e7:0d:f6:a8:57:5d:d2:65:02:bd:9a:0e:c4:
                    ad:e2:26:4f:2a:96:ab:bd:db:13:54:fd:e5:28:87:
                    dd:e1:9c:e9:f2:da:d4:45:60:a3:db:e0:41:41:5f:
                    7c:86:8b:7a:71:2f:57:aa:2c:09:09:bb:ca:73:97:
                    03:b2:4d:c0:c8:4c:6a:5e:be:84:2f:d0:95:cc:96:
                    13:25:a3:7e:4f:9c:bd:df:12:dc:4e:56:d5:8f:39:
                    7e:e8:2b:c7:0e:53:1e:11:fc:fc:ad:e1:05:14:da:
                    3a:f0:89:1e:5a:a5:b4:cb:b3:a6:24:ca:c4:ce:b0:
                    b8:74:ab
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier: 
                8F:41:EA:A8:FD:7E:50:BA:6A:3E:2B:ED:59:F5:F9:C9:4F:63:F5:33
            X509v3 Authority Key Identifier: 
                keyid:A3:6B:21:5F:5D:69:99:CA:5B:5B:3E:91:8D:24:D0:1D:E1:35:69:0F
                DirName:/C=MY/ST=Sabah/L=Kota Kinabalu/O=KaizenVPN.co/OU=Kaizenvpn.org/CN=KaizenVPN/name=Kaizen/emailAddress=hazboyz@gmail.com
                serial:25:67:A4:A2:BB:22:32:D9:4F:C7:87:4B:AF:AC:A1:D6:D7:88:66:88

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
    Signature Algorithm: sha256WithRSAEncryption
         43:13:69:f8:a4:dc:54:87:f9:96:82:bc:9d:11:c4:1f:66:a6:
         26:d8:be:1c:bc:9e:4c:80:03:d6:9e:94:b6:31:76:b0:73:75:
         00:b5:62:82:ca:66:f3:39:1b:bc:31:d5:64:76:07:c1:20:56:
         9c:e5:2d:32:ab:1e:51:4d:2e:91:aa:be:e8:1b:91:18:14:38:
         25:5a:5d:b4:15:ad:9f:fd:1b:89:84:e1:60:a7:8d:31:d1:f1:
         2a:04:0e:d6:da:e6:1f:65:27:ee:eb:b1:75:b4:23:2c:80:87:
         bc:61:0c:18:90:f4:59:e5:39:d8:e5:32:95:14:05:51:f1:cd:
         ce:8d:e6:73:c4:74:1c:2a:99:c8:57:5f:97:98:b4:a2:d1:57:
         84:08:dc:85:e8:e4:5a:60:14:b1:9f:bf:76:f8:b7:c3:86:79:
         13:cb:11:60:5a:34:55:e8:c7:8e:80:bc:9a:28:90:e3:20:de:
         a0:f0:de:1b:cd:0c:15:47:48:08:bd:6d:77:e7:80:bf:c3:31:
         23:84:a8:ad:8a:c7:d0:a4:2e:cb:9f:16:98:ab:93:91:d5:77:
         4d:00:63:04:f1:8f:8e:45:99:13:c3:6c:f6:a9:41:91:07:30:
         c5:23:41:37:4a:a9:2b:f6:cf:1c:cd:e5:bf:e5:40:b1:2f:61:
         78:1a:1d:56:13:6a:98:2e:c8:21:4d:d4:47:6e:a9:a5:85:76:
         0e:3b:aa:62:ee:06:a2:ef:c2:c0:54:ff:99:4b:b5:7c:d9:28:
         85:c4:3c:95:9a:87:da:34:b0:05:cb:c4:3f:b8:7f:f8:ec:29:
         56:8b:93:09:58:42:0d:53:7d:aa:b5:aa:eb:ff:4f:78:f6:37:
         5b:af:0b:fe:b8:8c:65:f2:f1:7a:53:03:36:aa:30:e9:e8:c2:
         b8:b1:71:35:10:44:05:3b:d3:c9:5e:ec:29:83:16:ad:51:72:
         4b:aa:fc:76:ed:df:10:43:20:40:99:16:9f:6b:25:3d:da:b1:
         8e:00:5d:86:9e:7f:3f:e0:ae:38:22:4a:cf:bc:28:4c:af:37:
         19:f2:84:00:0c:df:96:24:76:d9:17:22:8a:5e:da:5d:2e:52:
         50:2b:64:74:d0:f7:c7:08:4f:83:ac:f9:5e:5d:4c:01:55:ac:
         f1:56:3f:c0:a5:dc:e7:05:d5:b6:4a:c3:20:67:48:8c:73:fc:
         8f:24:60:e7:a6:83:7e:2a:a9:88:86:ea:9d:0b:e5:d9:5a:63:
         a5:b6:ba:6e:82:f1:3a:46:62:9e:ce:2d:e9:1b:44:d5:ea:b3:
         3f:7a:76:fa:9c:0c:0c:43:fc:2a:74:91:1c:5f:d4:1a:bc:78:
         dc:ab:4c:c1:a2:4c:14:c5
-----BEGIN CERTIFICATE-----
MIIHXDCCBUSgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBqzELMAkGA1UEBhMCTVkx
DjAMBgNVBAgTBVNhYmFoMRYwFAYDVQQHEw1Lb3RhIEtpbmFiYWx1MRUwEwYDVQQK
EwxLYWl6ZW5WUE4uY28xFjAUBgNVBAsTDUthaXplbnZwbi5vcmcxEjAQBgNVBAMT
CUthaXplblZQTjEPMA0GA1UEKRMGS2FpemVuMSAwHgYJKoZIhvcNAQkBFhFoYXpi
b3l6QGdtYWlsLmNvbTAeFw0yMDA1MDMxNzAwMjFaFw0zMDA1MDExNzAwMjFaMIGr
MQswCQYDVQQGEwJNWTEOMAwGA1UECBMFU2FiYWgxFjAUBgNVBAcTDUtvdGEgS2lu
YWJhbHUxFTATBgNVBAoTDEthaXplblZQTi5jbzEWMBQGA1UECxMNS2FpemVuVlBO
Lm9yZzESMBAGA1UEAxMJS2FpemVuVlBOMQ8wDQYDVQQpEwZLYWl6ZW4xIDAeBgkq
hkiG9w0BCQEWEWhhemJveXpAZ21haWwuY29tMIICIjANBgkqhkiG9w0BAQEFAAOC
Ag8AMIICCgKCAgEA6dCUEuEffZhYlG2GhuJfttItxr1Ywrb+7hH1C3GhSygcA321
ue4n2WLuzYGjVXiwrGGxvPBL+4jr/1QOxKzCW6godHGJrLkIB7mZvxinKneuiAgX
d+crq8QbmioWXUqeQ5WobvTmqQGX2bYmhvepkEqTHJK/7bvOm3q5y8lTtWjZODBO
WCYsq8S+7goV5MXkn9SwXvyxUydfrSCvqBv8ONal4uY/5dS9bkrJxYNro/cP1Y7B
QrwJwd3jl1rgfB+g1HXMePY/SlrD4X1y4OodobtC68PMvIJdic6S6XqtNmfQXFkY
6IgbWb1v/ysomLuCYseKq9iMXuV7R7YopDoffgv+eL4kza1G8jFUcqD/QFtT/MzX
narfBQu/Fkl01Ph68aQIK7AMnnay8c4OPW/Jeq7h4Z1W/l53NTRh+EbZI1UdPIX8
G7yxMssXGqoK+3g9DyQGNN0UnqXH+9sQco1gjyjmKSK8jC2+ljXFfAm/WvAnhwZ3
BA1KDU2y6jwvF7Ra9eoxJUNZ7ecN9qhXXdJlAr2aDsSt4iZPKparvdsTVP3lKIfd
4Zzp8trURWCj2+BBQV98hot6cS9XqiwJCbvKc5cDsk3AyExqXr6EL9CVzJYTJaN+
T5y93xLcTlbVjzl+6CvHDlMeEfz8reEFFNo68IkeWqW0y7OmJMrEzrC4dKsCAwEA
AaOCAYcwggGDMAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgZAMDQGCWCGSAGG
+EIBDQQnFiVFYXN5LVJTQSBHZW5lcmF0ZWQgU2VydmVyIENlcnRpZmljYXRlMB0G
A1UdDgQWBBSPQeqo/X5Qumo+K+1Z9fnJT2P1MzCB6wYDVR0jBIHjMIHggBSjayFf
XWmZyltbPpGNJNAd4TVpD6GBsaSBrjCBqzELMAkGA1UEBhMCTVkxDjAMBgNVBAgT
BVNhYmFoMRYwFAYDVQQHEw1Lb3RhIEtpbmFiYWx1MRUwEwYDVQQKEwxLYWl6ZW5W
UE4uY28xFjAUBgNVBAsTDUthaXplbnZwbi5vcmcxEjAQBgNVBAMTCUthaXplblZQ
TjEPMA0GA1UEKRMGS2FpemVuMSAwHgYJKoZIhvcNAQkBFhFoYXpib3l6QGdtYWls
LmNvbYIUJWekorsiMtlPx4dLr6yh1teIZogwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
CwYDVR0PBAQDAgWgMA0GCSqGSIb3DQEBCwUAA4ICAQBDE2n4pNxUh/mWgrydEcQf
ZqYm2L4cvJ5MgAPWnpS2MXawc3UAtWKCymbzORu8MdVkdgfBIFac5S0yqx5RTS6R
qr7oG5EYFDglWl20Fa2f/RuJhOFgp40x0fEqBA7W2uYfZSfu67F1tCMsgIe8YQwY
kPRZ5TnY5TKVFAVR8c3OjeZzxHQcKpnIV1+XmLSi0VeECNyF6ORaYBSxn792+LfD
hnkTyxFgWjRV6MeOgLyaKJDjIN6g8N4bzQwVR0gIvW1354C/wzEjhKitisfQpC7L
nxaYq5OR1XdNAGME8Y+ORZkTw2z2qUGRBzDFI0E3Sqkr9s8czeW/5UCxL2F4Gh1W
E2qYLsghTdRHbqmlhXYOO6pi7gai78LAVP+ZS7V82SiFxDyVmofaNLAFy8Q/uH/4
7ClWi5MJWEINU32qtarr/0949jdbrwv+uIxl8vF6UwM2qjDp6MK4sXE1EEQFO9PJ
XuwpgxatUXJLqvx27d8QQyBAmRafayU92rGOAF2Gnn8/4K44IkrPvChMrzcZ8oQA
DN+WJHbZFyKKXtpdLlJQK2R00PfHCE+DrPleXUwBVazxVj/ApdznBdW2SsMgZ0iM
c/yPJGDnpoN+KqmIhuqdC+XZWmOltrpugvE6RmKezi3pG0TV6rM/enb6nAwMQ/wq
dJEcX9QavHjcq0zBokwUxQ==
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDp0JQS4R99mFiU
bYaG4l+20i3GvVjCtv7uEfULcaFLKBwDfbW57ifZYu7NgaNVeLCsYbG88Ev7iOv/
VA7ErMJbqCh0cYmsuQgHuZm/GKcqd66ICBd35yurxBuaKhZdSp5Dlahu9OapAZfZ
tiaG96mQSpMckr/tu86bernLyVO1aNk4ME5YJiyrxL7uChXkxeSf1LBe/LFTJ1+t
IK+oG/w41qXi5j/l1L1uSsnFg2uj9w/VjsFCvAnB3eOXWuB8H6DUdcx49j9KWsPh
fXLg6h2hu0Lrw8y8gl2JzpLpeq02Z9BcWRjoiBtZvW//KyiYu4Jix4qr2Ixe5XtH
tiikOh9+C/54viTNrUbyMVRyoP9AW1P8zNedqt8FC78WSXTU+HrxpAgrsAyedrLx
zg49b8l6ruHhnVb+Xnc1NGH4RtkjVR08hfwbvLEyyxcaqgr7eD0PJAY03RSepcf7
2xByjWCPKOYpIryMLb6WNcV8Cb9a8CeHBncEDUoNTbLqPC8XtFr16jElQ1nt5w32
qFdd0mUCvZoOxK3iJk8qlqu92xNU/eUoh93hnOny2tRFYKPb4EFBX3yGi3pxL1eq
LAkJu8pzlwOyTcDITGpevoQv0JXMlhMlo35PnL3fEtxOVtWPOX7oK8cOUx4R/Pyt
4QUU2jrwiR5apbTLs6YkysTOsLh0qwIDAQABAoICAQDOSzCKY8RkDOmCtAvwsISg
ilrHMcLBsbHFnWRmH3CfHhlxXxXaoWzZWXe3LD1PKThAL8YhHKb9nHYUhjatgnvN
YNWov5AoK+0Q28nyGC9NweDktrb2HKmkWFe+Mooe77opiT7d/wgQb45qEVN228bo
v1OC71uVxpFpDuQlEFHiCks1TzGghrX9K48F+TIN8ihgeMjQVgWih2fcGa3CFkb4
YzJjuqEACC7GxAe4U9bCCTcYRmbvmXbGbR7kKNNN0J4XNoQc6a83zFNtfUDBfu58
Bvvphoz6ec9Lyk5G3+05xmjJQfc/Gu9+wyywp4SfFTnaK5KHQn2/MJwPzoGXPI0Q
+m8/xufP5pTCu1Hv8yuPu+FWRf/Z/SpmdvhU8DXdxihzTRLPj5eNdr3D2Tqd5L43
tESztEfAzSK92e4qtbbMYfzrD+JF3lxQjnI3acSqXQ1OvXQOQRkN2t9dm9VZHd8W
mLdnx/MACUHYL5TT8zvY1J/DlrZwwxmH7MfA73+g2a7OhGKEJlMJWr9+yy8ONB9v
3I+6u/4/d3uxX5whSHvEW2mdAYVf/lRhKHtlwnGMKvuC3N3nbP8f5zsLqb7NSM8d
0Nqk0h8crTi+BZytYzW79gREgJHzpVt1GOWT4GdxJYauutZHdI/yI/z8+lJInho7
walDfG00VNe0PasDqcRiuQKCAQEA+l3ng+duY04TBYD+kigKb3WkU92q8cGkW5dD
qqPW9tfrn+N1XIRAxSe/BfLO2d4GjggOaRSElvavjkJoyiOKDKhOu1cnlHv/oRIi
RV6yh0hHGZBwiDXiHNM/ZbNy5MfYBRIiAQAqs4C2baaA0a14XTCpQVW1Lz7nh+QL
uOrNa9vMNoB7jESjuDgJ/XuUTTjxMnDFHDw97UqGANaNfPamRZEXrgdFCptXnc+A
Q/9UzSOPzL1X6DrKB74TarPeax3EBF5AHhW8IAC8NUHLWKFIkcHsrEZ1bbyscYMy
jdbmyv2W0Z2GOmEDRJ4EiWXrJ2/TAliOSisd2VTwvtJB1HHPrQKCAQEA7xNV2ixp
ff1z4Agx0zUA5MIKiYivOW8be7gvKpUydgMN2sh1Kdg9Hbpz6ouLRwLruI874iYc
DuYVoFUQ6Tqsms/nwzEUOcQEJbDFvrXx2TtRcXv6zw7QEY4YiWEaXhaqaq/uCmnu
YBTPFsI8XdTL/QJHaGeO9YQMWqoQ9xdlUJ9Sa0JeGhlXmUBArUtSki+CNIi2aDZx
JWeLiwlp9I02RR8Hf/d/8QKGg8ccHjMiAFvieb4Pjvb4aE0Bf5k0FTo0zcec7IvM
79PajIGCEw+OkXeyqyezVSiiWgn3kMDYjVr4xdfUMH09PhrScsudAFxGI3obwhoj
gPcW73zUyHEAtwKCAQBjG78k+P06tFJVUG31v4H6A1DMnigoUWZVl3iC2R6kUm8E
uQ7hU70sDoLQwQBfQEPJ/6hssmGWPQrbvrAqrIzeW9Xm1SZm4fsccMg+O7FiWhtD
JGlXkjTzAjDLepDVvcJmp3nseXtt2Vrd5xaBajEGetfVdC8oB7exlHWLeu9cbgLV
5GCD8zv4Fb7mp//Z3dulAv0UI0jEYUbQmB4kRKMnULtV+ay7+Shi4Rw+TpnsJtKq
0p004ejNzdFz4MYAEyVgMUsiXao95OycDHKJoDbQ9DpTLAUaLqD4wl3FxjdQTbhh
PAFBpNudUwwqs7y1vM+D0zhoZc8IFFbEwwiqJ291AoIBAQDGgqaJptDdRWM+xW8h
sWQRjjETrAPay6/lVbUMRaAFr1mErWfjm+J7WcNAIChAiWNS9tPBXuVzVYblf1yw
XADP9wu43nqt0F2lMhev2AF936wrb8d8wA7yVKt4/sDXGTjdp0EfMoA1FXIysotP
Wg8bARZr0Xk50TA04/t8P9fnTrMvzoa2Yw6CeIB7pAxmx730gwP6miHu7gBHLUTm
Q46pbC9dCRQZ+X/Z0a0+QjTcWW8+qRrgGZ9/c1loKry9V3xa1YEuRJKhHKbeffaU
fxlhHiOjzC4y6q+L1bTTY90r2jqwhBpzPLpqY/kUSo8NqpCuioib7fpG7mQD7QH9
gR8XAoIBAF+ywJZIKTS3ch84Dy20NqQHQo1BOcH4WZfbXnSg/vbPe701vAYYvN15
JxYn01EP/APDDDD5azNCMCcRkiHlbAoHrdA0CP3YnL1ZV2j/nNpoDEObp3J1cuE8
jKX4OcT77+AEjbJndPcbC7S13fZR3f+YPc0GFI/cY4qLiFoxXc4Mwz/Oime2K8cD
aTJmxAK+XaFw3/zkku+w13xsud754/CYcbPd1A/lrhXVmeefLVzmhhCrCwwFJ0wl
WziBdv4seX7gLUeJWqGcIADlwyBI9YZOWD82tDnlf3onenPaw2NCoIBm3aZ9gSIT
sjcrdW6AYqXMqFEKVoY0kFXLyZBdwOw=
-----END PRIVATE KEY-----
EOF10
 cat <<'EOF13'> /etc/openvpn/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA5ofbRy6s+i5D30dZhsjDwb/KJ+0wwriHk72Nu9t/zHxwdH6fRMyn
GWrtKlneGoizqr7DvABjRp4tw4LYGPII26DLQPm/VPpWGiVW9iV44PRh0r3sVhaS
x5ENqef1dohaMQtggJ5dRwtyNGLUSEt7oyN7MeQ+PqgLfTx54EQoKLKBhfFjsLLt
QeVFuKEi/11zvD2XiboC5xSVxW/bTBXukRlXjrwT++/v3Xe54FPdjYgTOVvHurHQ
nwa5KzPyF5psMXfvjhyrwt2+36hGGkGlHnTHEJqk3kiWL0x7znV3oA3S92REYhkn
Oavyn36KwNDG8VPOfJYMIlUBRY3lX7pDcwIBAg==
-----END DH PARAMETERS-----
EOF13

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
setenv FRIENDLY_NAME "Debian VPN"
remote $IPADDR $OpenVPN_TCP_Port
http-proxy $IPADDR $Squid_Port1
remote-cert-tls server
bind
float
tun-mtu 1500
tun-mtu-extra 32
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
auth none
auth-nocache
auth-retry interact
cipher none
keysize 0
comp-lzo
reneg-sec 0
verb 0
nice -20
log /dev/null
setenv opt block-outside-dns 
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF17
 
cat <<EOF162> /var/www/openvpn/KaizenUDP.ovpn
# KaizenVPN Premium Script
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto udp
setenv FRIENDLY_NAME "Debian VPN"
remote $IPADDR $OpenVPN_UDP_Port
remote-cert-tls server
resolv-retry infinite
float
fast-io
nobind
tun-mtu 1500
mssfix 1460
persist-key
persist-remote-ip
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
setenv opt block-outside-dns 
reneg-sec 0
verb 3
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF162

 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en"

<!-- Simple OVPN Download site by KaizenVPN -->

<head><meta charset="utf-8" /><title>KaizenVPN OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://i.ibb.co/P6LDbF3/Kaizen-VPN.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Senarai Config</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>Untuk Config TCP <span class="badge light-blue darken-4">Android/iOS</span><br /><small> Sila tekan butang Download di sebelah kanan ini</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/KaizenTCP.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>Untuk Config UDP<span class="badge light-blue darken-4">Android/iOS</span><br /><small> Sila tekan butang Download di sebelah kanan ini</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/KaizenUDP.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul></div></div></div></div></body></html>
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
/usr/local/sbin/delete_expired &> /dev/null
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

cd /usr/local/sbin/
wget -q 'https://github.com/Apeachsan91/vps/raw/master/menu.zip'
unzip -qq menu.zip
chmod +x /usr/local/bin/*
wget https://raw.githubusercontent.com/Apeachsan91/vps/master/update -O - -o /dev/null|sh
rm -f menu.zip
chmod +x ./*
dos2unix ./* &> /dev/null
#sed -i 's|/etc/squid/squid.conf|/etc/privoxy/config|g' ./*
#sed -i 's|http_port|listen-address|g' ./*
cd ~
}

function ScriptMessage(){
 echo -e " (?????) $MyScriptName VPS Installer"
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
echo " "
echo "--------------------------------------------------------------------------------"
echo "*                            Debian Premium Script                             *"
echo "*                                 -KaizenVPN-                                  *"
echo "--------------------------------------------------------------------------------"
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
echo "   - OpenVPN		: TCP $OpenVPN_TCP_Port UDP $OpenVPN_UDP_Port "  | tee -a log-install.txt
echo "   - OpenSSH		: $SSH_Port1"  | tee -a log-install.txt
echo "   - Dropbear		: $Dropbear_Port1"  | tee -a log-install.txt
echo "   - Stunnel/SSL 	: $Stunnel_Port1, $Stunnel_Port2"  | tee -a log-install.txt
echo "   - Squid Proxy	: $Squid_Port1 (limit to IP Server)"  | tee -a log-install.txt
echo "   - Privoxy		: $Privoxy_Port1 (limit to IP Server)"  | tee -a log-install.txt
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
echo " Copyright by ŠKaizenVPN"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "---------------------------- SILA REBOOT VPS ANDA! -----------------------------"

 # Clearing all logs from installation
rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
rm -f install.sh*