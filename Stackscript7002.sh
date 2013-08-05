#!/bin/bash

# Originally By Sun Liwen <sunliwen@gmail.com>
# Updated By Martin Kemp <m.kemp2910@gmail.com>
# Stackscript 7002
 
######
#<udf name="NGINX_VERSION" label="Install nginx from PPA" oneOf="Yes,No" example="See https://launchpad.net/~nginx/+archive/stable">
#<udf name="SSH_PORT" label="SSH port" default="22">
#<udf name="USER_NAME" label="Unprivileged User Account" />
#<udf name="USER_PASSWORD" label="Unprivileged User Password" />
#<udf name="USER_SSHKEY" label="Public Key for User" default="" />
#<udf name="SSH_ALLOW_USERS" label="SSH Allow Users directive, leave blank if you don't know what this is" default="" />
#<udf name="ROOT_EMAIL" label="Email alias for root" />
#<udf name="HOSTNAME" label="Hostname" default="" />
#<udf name="INSTALL_SHOREWALL" label="Install Shorewall? (No will install basic iptables and auto iptable script)" oneOf="Yes,No" />
#<udf name="VPN_SERVICENAME" label="VPN Service Name" default="l2tp" example="l2tp" />
#<udf name="VPN_PSK" label="PSK" default="changeme" example="changeme" />
#<udf name="VPN_IPRANGE" label="IP Range" default="10.0.100" example="10.0.100" />
#<udf name="VPN_USERNAME" label="Username" />
#<udf name="VPN_PASSWORD" label="Password" />
######

set -e

source <ssinclude StackScriptID="7000">

#update system and set hostname
prep_system

#setup firewall
install_firewall

#setup standard user
configure_user

#secure ssh
configure_ssh

#setup postfix
install_postfix

if [ "$INSTALL_SHOREWALL" == "Yes" ]
then
    install_shorewall
else
    install_iptables
fi

#setup nginx
install_nginx

#install monit/munin/security tools/other tools
install_monit
install_munin
install_security
install_tools
install_vpn

#set root .profile
set_root_profile

#cleanup
cleanup

#send notification
notification_email
