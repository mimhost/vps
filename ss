#!/bin/bash
rm -f /root/opensshport
rm -f /root/dropbearport
rm -f /root/stunnel4port
rm -f /root/openvpnport
rm -f /root/squidport
opensshport="$(netstat -ntlp | grep -i ssh | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
dropbearport="$(netstat -nlpt | grep -i dropbear | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
stunnel4port="$(netstat -nlpt | grep -i stunnel | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
openvpnport="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
squidport="$(cat /etc/squid/squid.conf | grep -i http_port | awk '{print $2}')"
echo $opensshport > /root/opensshport
cat > /root/opensshport <<-END
$opensshport
END
echo $dropbearport > /root/dropbearport
cat > /root/dropbearport <<-END
$dropbearport
END
echo $stunnel4port > /root/stunnel4port
cat > /root/stunnel4port <<-END
$stunnel4port
END
echo $openvpnport > /root/openvpnport
cat > /root/openvpnport <<-END
$openvpnport
END
echo $squidport > /root/squidport
cat > /root/squidport <<-END
$squidport
END

cd
clear
echo -e ""
echo -e " == KaizenVPN == " | lolcat -a
echo -e " Squid Ports: $squidport"
echo -e ""
read -p " Port mana yang ingin ditukar?: " Port
egrep "^$Port" /root/squidport >/dev/null
if [ $? -eq 0 ]; then
	read -p " Dari Port $Port ke Port?: " Port_New
	if grep -Fxq $Port_New /root/opensshport; then
		echo -e ""
		echo -e " Berlanggar dengan Port OpenSSH!"
		echo -e " Port sudah digunakan oleh servis lain!"
		echo -e ""
		exit
	fi
	if grep -Fxq $Port_New /root/dropbearport; then
		echo -e ""
		echo -e " Berlanggar dengan Port Dropbear!"
		echo -e " Port sudah digunakan oleh servis lain!"
		echo -e ""
		exit
	fi
	if grep -Fxq $Port_New /root/stunnel4port; then
		echo -e ""
		echo -e " Berlanggar dengan Port Stunnel4!"
		echo -e " Port sudah digunakan oleh servis lain!"         "
		echo -e ""
		exit
	fi
	if grep -Fxq $Port_New /root/openvpnport; then
		echo -e ""
		echo -e " Berlanggar dengan Port OpenVPN!"
		echo -e " Port sudah digunakan oleh servis lain!"
		echo -e ""
		exit
	fi
	Port_Change="s/$Port/$Port_New/g";
	sed -i $Port_Change /etc/squid/squid.conf
	service squid restart > /dev/null
	rm -f /root/squidport
	squidport="$(cat /etc/squid/squid.conf | grep -i http_port | awk '{print $2}')"
	clear
	echo -e ""
	echo -e "$TITLE"
  echo -e " Port berjaya ditambah"
  echo -e " Port Squid anda sekarang ialah: $squidport"
	echo -e ""
else
	clear
  echo -e ""
  echo -e "$TITLE"
  echo -e " Port tidak terdapat didalam config server Squid, exiting.."
	echo -e ""
fi
