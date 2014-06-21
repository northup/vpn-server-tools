#!/bin/bash
function pause(){  
  read -n 1 -p "$*" INP  
  if [[ $INP != '' ]] ; then  
    echo -ne '\b \n'  
  fi  
} 

if [ $(id -u) != "0" ]; then
  printf "Error: You must be root to run this tool!\n"
  exit 1
fi
clear
printf "
####################################################
#                                                  #
# This is a Shell-Based tool of VPN installation   #
# Version: 0.1.1                                   #
# Author: Northup                                  #
# Website: http://icatvpn.com                      #
#                                                  #
####################################################
This shell script will install:
1. StrongSwan 5.0.4
2. xl2tpd
3. pptpd
on ubuntu 12.04.

Make sure the user path /home/lei exists.
"
server_ip=`curl -s http://ipecho.net/plain`

client_ip_root="10.10"
echo "Please input Client IP range root:"
read -p "(Default: 10.10):" client_ip_root
if [ "$client_ip_root" = "" ]; then
  client_ip_root="10.10"
fi

server_psk="icatvpn7320"
echo "Please input PSK:"
read -p "(Default: icatvpn7320):" server_psk
if [ "$server_psk" = "" ]; then
  server_psk="icatvpn7320"
fi

radius_server="50.116.40.42"
echo "Please input Radius Server:"
read -p "(Default: 50.116.40.42):" radius_server
if [ "$radius_server" = "" ]; then
  radius_server="50.116.40.42"
fi
clear

radius_secret="nassecret001"
echo "Please input Radius Secret:"
read -p "(Default: nassecret001):" radius_secret
if [ "$radius_secret" = "" ]; then
  radius_secret="nassecret001"
fi
clear

echo ""
echo "Server IP: $server_ip"
echo "Radius Server: $radius_server"
echo ""
echo "-- IPSec information -----------------------"
echo "Server Local IP: $client_ip_root.1.1"
echo "Client Remote IP Range: $client_ip_root.1.2 - $client_ip_root.1.254"
echo "PSK: $server_psk"
echo "--------------------------------------------"
echo ""
echo "-- L2TP/IPSec information -----------------------"
echo "Server Local IP: $client_ip_root.2.1"
echo "Client Remote IP Range: $client_ip_root.2.2 - $client_ip_root.2.254"
echo "PSK: $server_psk"
echo "--------------------------------------------"
echo ""
echo "-- PPTP information -----------------------"
echo "Server Local IP: $client_ip_root.3.1"
echo "Client Remote IP Range: $client_ip_root.3.2 - $client_ip_root.3.254"
echo "--------------------------------------------"
echo ""
pause "Press any key to start..."

apt-get update
apt-get upgrade -y

# sysctl.conf
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sysctl -p

# IPSec（StrongSwan）
apt-get install wget -y
apt-get install build-essential libcurl4-openssl-dev libgmp3-dev sqlite3 libsqlite3-dev -y
cd /home/lei/ && mkdir strongswan && cd strongswan
wget http://download.strongswan.org/strongswan-5.0.4.tar.bz2
tar jxvf strongswan-5.0.4.tar.bz2
rm strongswan-5.0.4.tar.bz2
cd strongswan-5.0.4
./configure --prefix=/usr --sysconfdir=/etc --libexecdir=/usr/lib --with-ipsecdir=/usr/lib/strongswan --enable-openssl --enable-curl --enable-attr-sql --enable-sqlite --enable-farp --enable-dhcp --enable-eap-identity --enable-eap-md5 --enable-eap-gtc --enable-eap-aka --enable-eap-aka-3gpp2 --enable-eap-mschapv2 --enable-eap-radius --enable-xauth-eap --enable-shared
make
sudo make install

rm -rf /etc/strongswan.conf
touch /etc/strongswan.conf
cat >>/etc/strongswan.conf<<EOF
# strongswan.conf - strongSwan configuration file

charon {

  # number of worker threads in charon
  threads = 16

  # send strongswan vendor ID?
  # send_vendor_id = yes
  dns1 = 8.8.8.8
  dns2 = 8.8.4.4

  plugins {
    eap-radius {
      accounting = yes
      eap_start = no
      servers {
        primary {
          address = $radius_server
          auth_port = 1812
          acct_port = 1813
          secret = $radius_secret
          nas_identifer = ipsec-gateway
          sockets = 20
        }
      }
    }

    dae {
      listen = 0.0.0.0
      port = 3799
      secret = $radius_secret
    }
  }
  # ...
}

pluto {

}

libstrongswan {

  #  set to no, the DH exponent size is optimized
  #  dh_exponent_ansi_x9_42 = no
}
EOF

rm -rf /etc/ipsec.secrets
touch /etc/ipsec.secrets
cat >>/etc/ipsec.secrets<<EOF
: PSK "$server_psk"
EOF

rm -rf /etc/ipsec.conf
touch /etc/ipsec.conf
cat >>/etc/ipsec.conf<<EOF
# ipsec.conf - strongSwan IPsec configuration file

# basic configuration

config setup
  # strictcrlpolicy=yes
  uniqueids = no

# Add connections here.
conn %default
        dpdaction=clear
        dpddelay=40s
        dpdtimeout=130s

# L2TP
conn L2TP-PSK-NAT
        rightsubnet=vhost:%priv
        also=L2TP-PSK-noNAT

conn L2TP-PSK-noNAT
        keyexchange=ikev1
        authby=secret
        rekey=no
        keyingtries=3
        left=%defaultroute
        leftprotoport=17/1701
        right=%any
        rightprotoport=17/%any
        auto=add

# Cisco IPSec XAuth with PSK
conn cisco_ipsec_psk
        keyexchange=ikev1
        lifetime=24h
        ikelifetime=24h
        left=%defaultroute
        leftsubnet=0.0.0.0/0
        leftfirewall=yes
        leftauth=psk
        right=%any
        rightsubnet=$client_ip_root.1.0/24
        rightsourceip=$client_ip_root.1.0/24
        rightauth=psk
        rightauth2=xauth-eap
        auto=add
EOF

ipsec restart

# radius client
apt-get install radiusclient1 -y

rm -rf /etc/radiusclient/servers
touch /etc/radiusclient/servers
cat >>/etc/radiusclient/servers<<EOF
# Make sure that this file is mode 600 (readable only to owner)!
#
#Server Name or Client/Server pair    Key   
#----------------       ---------------
$radius_server          $radius_secret
EOF

rm -rf /etc/radiusclient/radiusclient.conf
touch /etc/radiusclient/radiusclient.conf
cat >>/etc/radiusclient/radiusclient.conf<<EOF
# General settings

# specify which authentication comes first respectively which
# authentication is used. possible values are: "radius" and "local".
# if you specify "radius,local" then the RADIUS server is asked
# first then the local one. if only one keyword is specified only
# this server is asked.
auth_order  radius,local

# maximum login tries a user has
login_tries 4

# timeout for all login tries
# if this time is exceeded the user is kicked out
login_timeout 60

# name of the nologin file which when it exists disables logins.
# it may be extended by the ttyname which will result in
# a terminal specific lock (e.g. /etc/nologin.ttyS2 will disable
# logins on /dev/ttyS2)
nologin /etc/nologin

# name of the issue file. it's only display when no username is passed
# on the radlogin command line
issue /etc/radiusclient/issue

# RADIUS settings

# RADIUS server to use for authentication requests. this config
# item can appear more then one time. if multiple servers are
# defined they are tried in a round robin fashion if one
# server is not answering.
# optionally you can specify a the port number on which is remote
# RADIUS listens separated by a colon from the hostname. if
# no port is specified /etc/services is consulted of the radius
# service. if this fails also a compiled in default is used.
authserver  $radius_server

# RADIUS server to use for accouting requests. All that I
# said for authserver applies, too. 
#
acctserver  $radius_server

# file holding shared secrets used for the communication
# between the RADIUS client and server
servers   /etc/radiusclient/servers

# dictionary of allowed attributes and values
# just like in the normal RADIUS distributions
dictionary  /etc/radiusclient/dictionary

# program to call for a RADIUS authenticated login
login_radius  /usr/sbin/login.radius

# file which holds sequence number for communication with the
# RADIUS server
seqfile   /var/run/radius.seq

# file which specifies mapping between ttyname and NAS-Port attribute
mapfile   /etc/radiusclient/port-id-map

# default authentication realm to append to all usernames if no
# realm was explicitly specified by the user
# the radiusd directly form Livingston doesnt use any realms, so leave
# it blank then
default_realm

# time to wait for a reply from the RADIUS server
radius_timeout  10

# resend request this many times before trying the next server
radius_retries  3

# LOCAL settings

# program to execute for local login
# it must support the -f flag for preauthenticated login
login_local /bin/login
EOF

cd /home/lei
wget -c http://small-script.googlecode.com/files/dictionary.microsoft
mv dictionary.microsoft /etc/radiusclient/
echo "INCLUDE /etc/radiusclient/dictionary.ascend" >> /etc/radiusclient/dictionary
echo "INCLUDE /etc/radiusclient/dictionary.merit" >> /etc/radiusclient/dictionary
echo "INCLUDE /etc/radiusclient/dictionary.compat" >> /etc/radiusclient/dictionary
echo "INCLUDE /etc/radiusclient/dictionary.microsoft" >> /etc/radiusclient/dictionary

# L2TP (xl2tpd)
apt-get install xl2tpd -y

rm -rf /etc/xl2tpd/xl2tpd.conf
touch /etc/xl2tpd/xl2tpd.conf
cat >>/etc/xl2tpd/xl2tpd.conf<<EOF
[global]                        ; Global parameters:
listen-addr = $server_ip
ipsec saref = no

[lns default]                   ; Our fallthrough LNS definition
name = l2tpd                            ; * Report this as our hostname
ip range = $client_ip_root.2.2-$client_ip_root.2.255        ; * Allocate from this IP range
local ip = $client_ip_root.2.1                    ; * Our local IP to use
length bit = yes                        ; * Use length bit in payload?
refuse pap = yes                        ; * Refuse PAP authentication
refuse chap = yes                       ; * Refuse CHAP authentication
require authentication = yes            ; * Require peer to authenticate
ppp debug = no                          ; * Turn on PPP debugging
pppoptfile = /etc/ppp/options.xl2tpd    ; * ppp options file
EOF

rm -rf /etc/ppp/options.xl2tpd
touch /etc/ppp/options.xl2tpd
cat >>/etc/ppp/options.xl2tpd<<EOF
name l2tpd
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
auth
require-mschap-v2
crtscts
lock
hide-password
modem
debug
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4

logfile /var/log/xl2tpd.log

# for radius
plugin /usr/lib/pppd/2.4.5/radius.so
plugin /usr/lib/pppd/2.4.5/radattr.so
radius-config-file /etc/radiusclient/radiusclient.conf
EOF

service xl2tpd restart

# pptpd
apt-get install pptpd -y

rm -rf /etc/pptpd.conf
touch /etc/pptpd.conf
cat >>/etc/pptpd.conf<<EOF
###############################################################################
# $Id$
#
# Sample Poptop configuration file /etc/pptpd.conf
#
# Changes are effective when pptpd is restarted.
###############################################################################

# TAG: ppp
# Path to the pppd program, default '/usr/sbin/pppd' on Linux
#
#ppp /usr/sbin/pppd

# TAG: option
# Specifies the location of the PPP options file.
# By default PPP looks in '/etc/ppp/options'
#
option /etc/ppp/options.pptpd

# TAG: debug
# Turns on (more) debugging to syslog
#
#debug

# TAG: stimeout
# Specifies timeout (in seconds) on starting ctrl connection
#
# stimeout 10

# TAG: noipparam
#       Suppress the passing of the client's IP address to PPP, which is
#       done by default otherwise.
#
#noipparam

# TAG: logwtmp
# Use wtmp(5) to record client connections and disconnections.
#
logwtmp

# TAG: bcrelay <if>
# Turns on broadcast relay to clients from interface <if>
#
#bcrelay eth1

# TAG: localip
# TAG: remoteip
# Specifies the local and remote IP address ranges.
#
#       Any addresses work as long as the local machine takes care of the
#       routing.  But if you want to use MS-Windows networking, you should
#       use IP addresses out of the LAN address space and use the proxyarp
#       option in the pppd options file, or run bcrelay.
#
# You can specify single IP addresses seperated by commas or you can
# specify ranges, or both. For example:
#
#   192.168.0.234,192.168.0.245-249,192.168.0.254
#
# IMPORTANT RESTRICTIONS:
#
# 1. No spaces are permitted between commas or within addresses.
#
# 2. If you give more IP addresses than MAX_CONNECTIONS, it will
#    start at the beginning of the list and go until it gets 
#    MAX_CONNECTIONS IPs. Others will be ignored.
#
# 3. No shortcuts in ranges! ie. 234-8 does not mean 234 to 238,
#    you must type 234-238 if you mean this.
#
# 4. If you give a single localIP, that's ok - all local IPs will
#    be set to the given one. You MUST still give at least one remote
#    IP for each simultaneous client.
#
# (Recommended)
#localip 192.168.0.1
#remoteip 192.168.0.234-238,192.168.0.245
# or
#localip 192.168.0.234-238,192.168.0.245
#remoteip 192.168.1.234-238,192.168.1.245
localip $client_ip_root.3.1
remoteip $client_ip_root.3.2-254
EOF

rm -rf /etc/ppp/pptpd-options
rm -rf /etc/ppp/options.pptpd
touch /etc/ppp/options.pptpd
cat >>/etc/ppp/options.pptpd<<EOF
name pptpd
refuse-pap
refuse-chap
refuse-mschap
refuse-eap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
# debug
dump
lock
nobsdcomp
novj
novjccomp

logfile /var/log/pptpd.log

# for radius
plugin /usr/lib/pppd/2.4.5/radius.so
plugin /usr/lib/pppd/2.4.5/radattr.so
radius-config-file /etc/radiusclient/radiusclient.conf
EOF

service pptpd restart

# kernel modules
# for l7-filter
cat >>/etc/modules<<EOF
nf_conntrack_netlink
EOF

# l7-filter
apt-get install l7-filter-userspace -y

# l7-filter config
rm -rf /etc/l7-filter.conf
touch /etc/l7-filter.conf
cat >>/etc/l7-filter.conf<<EOF
bittorrent 80
kugoo 80
edonkey 80
ares 80
100bao 80
xunlei 80
EOF

# rc.local
rm -rf /etc/rc.local
touch /etc/rc.local
cat >>/etc/rc.local<<EOF
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

iptables -t nat -A POSTROUTING -s $client_ip_root.0.0/255.255.0.0 -o eth0 -j MASQUERADE
iptables -t mangle -I PREROUTING -s 10.10.0.0/16 -j NFQUEUE
iptables -t mangle -I PREROUTING -d 10.10.0.0/16 -j NFQUEUE
iptables -t mangle -P FORWARD DROP
iptables -t mangle -I FORWARD -m mark --mark 80 -j DROP
iptables -t mangle -A FORWARD -j ACCEPT

for each in /proc/sys/net/ipv4/conf/*
do
echo 0 > \$each/accept_redirects
echo 0 > \$each/send_redirects
done

echo 1 >/proc/sys/net/core/xfrm_larval_drop

ipsec start
nohup l7-filter -f /etc/l7-filter.conf >> /var/log/l7-filter.log 2>> /var/log/l7-filter.err &

exit 0
EOF

chmod 755 /etc/rc.local

clear

printf "
####################################################
#                                                  #
# This is a Shell-Based tool of VPN installation   #
# Version: 0.1.1                                   #
# Author: Northup                                  #
# Website: http://icatvpn.com                      #
#                                                  #
####################################################
If there are no [FAILED] above, then you can
add the VPN server as below to http://icatvpn/admins

ServerIP: $server_ip
Radius Nas Secret: $radius_secret
PSK: $server_psk

DON NOT forget to restart freeradius server after
VPN server inserted.

Installation is complete, PLEASE REBOOT THE SERVER.

"


