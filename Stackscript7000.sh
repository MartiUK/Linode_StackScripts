#!/bin/bash

# By Martin Kemp
# Stackscript 7000

function system_primary_ip {
    # returns the primary IP assigned to eth0
    echo $(ifconfig eth0 | awk -F: '/inet addr:/ {print $2}' | awk '{ print $1 }')
}

function get_rdns {
    # calls host on an IP address and returns its reverse dns

    if [ ! -e /usr/bin/host ]; then
        aptitude -y install dnsutils > /dev/null
    fi
    echo $(host $1 | awk '/pointer/ {print $5}' | sed 's/\.$//')
}

function get_rdns_primary_ip {
    # returns the reverse dns of the primary IP assigned to this system
    echo $(get_rdns $(system_primary_ip))
}

function prep_system
{
    #update system
    #setup hostname
    if [ -z "$HOSTNAME" ]
    then
        export HOSTNAME=$(get_rdns_primary_ip)
    fi
    HOST=$(echo $HOSTNAME | sed 's/\(\[a-z0-9\]\)*\..*/\1/')
    echo "$HOST" >  /etc/hostname
    echo "`system_primary_ip` $HOSTNAME $HOST" >> /etc/hosts
    start hostname
    echo "/usr/sbin/nologin" >> /etc/shells

    #set timezone to UTC
    ln -s -f /usr/share/zoneinfo/Europe/London /etc/localtime
    aptitude update
    aptitude -y safe-upgrade
    aptitude -y install python-software-properties
    aptitude -y install debconf-utils
}

function install_nginx {
#add nginx ppa
if [ $NGINX_VERSION == "Yes" ]
then
add-apt-repository -y ppa:nginx/stable
aptitude update
fi
#Install nginx
aptitude -y install nginx
cat <<EOT > /etc/nginx/fastcgi_config
fastcgi_intercept_errors on;
fastcgi_ignore_client_abort on;
fastcgi_connect_timeout 60;
fastcgi_send_timeout 180;
fastcgi_read_timeout 180;
fastcgi_buffer_size 128k;
fastcgi_buffers 4 256k;
fastcgi_busy_buffers_size 256k;
fastcgi_temp_file_write_size 256k;
fastcgi_max_temp_file_size 0;
fastcgi_index index.php;
EOT
cat <<EOT > /etc/nginx/sites-available/nginx_status
server {
    listen 127.0.0.1:80;
    location /nginx_status {
            stub_status on;
        access_log off;
     }   
}
EOT
ln -s /etc/nginx/sites-available/nginx_status /etc/nginx/sites-enabled/nginx_status
mkdir -p /etc/munin/plugins/
ln -s /usr/share/munin/plugins/nginx_request /etc/munin/plugins/nginx_request
ln -s /usr/share/munin/plugins/nginx_status /etc/munin/plugins/nginx_status
mkdir -p /etc/munin/plugin-conf.d/
cat <<EOT >> /etc/munin/plugin-conf.d/nginx
[nginx*]
env.url http://localhost/nginx_status
EOT
service nginx start
sed -i 's/# gzip_types/gzip_types/' /etc/nginx/nginx.conf
sed -i 's/# gzip_vary/gzip_vary/' /etc/nginx/nginx.conf
}

function notification_email {
#mail root to confirm installation
mail -s "Linode "`cat /etc/hostname`" setup complete" root <<EOT
Your linode setup is complete, if you encounter problems or would like commercial support email sunliwen@gmail.com. Your linode will reboot shortly after this email is sent.
EOT
$(shutdown -r +1) &
}


function install_postfix
{
#Install postfix
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string $HOSTNAME" | debconf-set-selections
echo "postfix postfix/destinations string localhost.localdomain, localhost, $HOSTNAME" | debconf-set-selections
aptitude -y install postfix mailutils
/usr/sbin/postconf -e "inet_interfaces = loopback-only"
#configure root alias
echo "root: $ROOT_EMAIL" >> /etc/aliases
echo "$USER_NAME: root" >> /etc/aliases
echo $HOSTNAME > /etc/mailname
/usr/bin/newaliases
}

function configure_ssh {
#setup ssh
#add ssh key
sudo -u $USER_NAME mkdir /home/$USER_NAME/.ssh
sudo -u $USER_NAME echo "${USER_SSHKEY}" >> /home/$USER_NAME/.ssh/authorized_keys
mkdir -p /root/.ssh/
echo "${USER_SSHKEY}" >> /root/.ssh/authorized_keys
chmod 0600 /home/$USER_NAME/.ssh/authorized_keys /root/.ssh/authorized_keys
chown $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh/authorized_keys
sed -i "s/Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config #set ssh port
#enable internal sftp for chrooting
sed -i 's@Subsystem sftp /usr/lib/openssh/sftp-server@Subsystem sftp internal-sftp@' /etc/ssh/sshd_config
if [[ "$SSH_ALLOW_USERS" != *root* ]]
then
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
else
sed -i 's/PermitRootLogin yes/PermitRootLogin without-password/' /etc/ssh/sshd_config
fi
if [ "$USER_SSHKEY" != "" ]
then
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config #disable ssh password auth if $USER_SSHKEY is not empty
fi
sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config #disable xforwarding
echo "AllowUsers $USER_NAME $SSH_ALLOW_USERS" >> /etc/ssh/sshd_config #only allow access from $USER
/etc/init.d/ssh restart
}

function configure_user
{
#configure ssh/sudo 
useradd -m -s /bin/bash $USER_NAME #add user account 
echo "$USER_NAME:$USER_PASSWORD" | chpasswd #setpassword
#add user to sudoers
echo "$USER_NAME ALL=(ALL) ALL" >> /etc/sudoers
usermod -a -G adm $USER_NAME
#lock out root
passwd -l root
}

function install_shorewall
{
#sets up shorewall firewall
aptitude -y install shorewall shorewall6
cp /usr/share/doc/shorewall/examples/one-interface/* /etc/shorewall/
sed -i 's/BLACKLISTNEWONLY=Yes/BLACKLISTNEWONLY=No/' /etc/shorewall/shorewall.conf
sed -i 's/REJECT/DROP/' /etc/shorewall/policy

echo "#accept http/s" >> /etc/shorewall/rules
echo "ACCEPT       net     \$FW:`system_primary_ip`        tcp 80" >> /etc/shorewall/rules
echo "ACCEPT       net     \$FW:`system_primary_ip`        tcp 443" >> /etc/shorewall/rules

echo '#accept ssh and ratelimit to 5 connections per minute per ip' >> /etc/shorewall/rules
echo "ACCEPT       net     \$FW:`system_primary_ip`        tcp $SSH_PORT   -       -       s:ssh:5/min:1" >> /etc/shorewall/rules

echo "#accept l2tp/s" >> /etc/shorewall/rules
echo "ACCEPT       net     \$FW:`system_primary_ip`        udp 500" >> /etc/shorewall/rules
echo "ACCEPT       net     \$FW:`system_primary_ip`        udp 4500" >> /etc/shorewall/rules

sed -i 's/STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/' /etc/shorewall/shorewall.conf
sed -i 's/startup=0/startup=1/' /etc/default/shorewall

#disable ipv6 by default
cp /usr/share/doc/shorewall6/examples/one-interface/* /etc/shorewall6/
sed -i 's/BLACKLISTNEWONLY=Yes/BLACKLISTNEWONLY=No/' /etc/shorewall6/shorewall6.conf
sed -i 's/REJECT/DROP/' /etc/shorewall6/policy
sed -i 's/STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/' /etc/shorewall6/shorewall6.conf
sed -i 's/startup=0/startup=1/' /etc/default/shorewall6

}

function install_iptables
{
cat <<EOT > /etc/iptables.firewall.rules
*filter

#  Allow all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
-A INPUT -i lo -j ACCEPT
-A INPUT -d 127.0.0.0/8 -j REJECT

#  Accept all established inbound connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#  Allow all outbound traffic - you can modify this to only allow certain traffic
-A OUTPUT -j ACCEPT

#  Allow HTTP and HTTPS connections from anywhere (the normal ports for websites and SSL).
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

#  Allow SSH connections
#
#  The -dport number should be the same port number you set in sshd_config
#
-A INPUT -p tcp -m state --state NEW --dport 22 -j ACCEPT

#  Allow ping
-A INPUT -p icmp -j ACCEPT

#  Log iptables denied calls
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

#  Drop all other inbound - default deny unless explicitly allowed policy
-A INPUT -j DROP
-A FORWARD -j DROP

COMMIT
EOT

cat <<EOT > /etc/network/if-pre-up.d/firewall
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.firewall.rules
EOT

chmod +x /etc/network/if-pre-up.d/firewall

}

function install_monit
{
#install and enable monit
 aptitude -y install monit
 sed -i 's/startup=0/startup=1/' /etc/default/monit
 mkdir -p /etc/monit/conf.d/
 sed -i "s/# set daemon  120/set daemon 120/" /etc/monit/monitrc
 sed -i "s/#   with start delay 240/with start delay 240/" /etc/monit/monitrc
 sed -i "s/# set logfile syslog facility log_daemon/set logfile \/var\/log\/monit.log/" /etc/monit/monitrc
 sed -i "s/# set mailserver mail.bar.baz,/set mailserver localhost/" /etc/monit/monitrc
 sed -i "s/# set eventqueue/set eventqueue/" /etc/monit/monitrc
 sed -i "s/#     basedir \/var\/monit/basedir \/var\/monit/" /etc/monit/monitrc
 sed -i "s/#     slots 100 /slots 100/" /etc/monit/monitrc
 sed -i "s/# set alert sysadm@foo.bar/set alert root@localhost reminder 180/" /etc/monit/monitrc
 sed -i "s/# set httpd port 2812 and/ set httpd port 2812 and/" /etc/monit/monitrc
 sed -i "s/#    use address localhost/use address localhost/" /etc/monit/monitrc
 sed -i "s/#    allow localhost/allow localhost/" /etc/monit/monitrc
 sed -i "s/# set mail-format { from: monit@foo.bar }/set mail-format { from: monit@`hostname -f` }/" /etc/monit/monitrc
}

function install_munin
{
#install munin
aptitude -y install munin munin-node libcache-cache-perl libdbd-mysql-perl
sed -i 's/host \*/host 127.0.0.1/' /etc/munin/munin-node.conf
sed -i "s/localhost.localdomain/`hostname -f`/" /etc/munin/munin.conf
echo "munin: root" >> /etc/aliases
sed -i "s#\[mysql\*\]#[mysql*]\nenv.mysqladmin /usr/bin/mysqladmin#" /etc/munin/plugin-conf.d/munin-node
rm /etc/munin/plugins/nfs*
ln -s /usr/share/munin/plugins/postfix_mailstats /etc/munin/plugins/
ln -s /usr/share/munin/plugins/netstat /etc/munin/plugins/
if [ -x /usr/bin/newaliases ]
then
/usr/bin/newaliases
fi
}

function install_security
{
#install chrootkit rkhunter logwatch
aptitude -y install chkrootkit rkhunter logwatch logcheck libsys-cpu-perl logcheck fail2ban
set +e
echo "yes" | cpan 'Sys::MemInfo'
echo "yes" | cpan 'Sys::MemInfo'
set -e
sed -i 's/#ALLOWHIDDENDIR=\/dev\/.initramfs/ALLOWHIDDENDIR=\/dev\/.initramfs/' /etc/rkhunter.conf
sed -i 's/#ALLOWHIDDENDIR=\/dev\/.udev/ALLOWHIDDENDIR=\/dev\/.udev/' /etc/rkhunter.conf
sed -i 's/DISABLE_TESTS="suspscan hidden_procs deleted_files packet_cap_apps apps"/DISABLE_TESTS="suspscan hidden_procs deleted_files packet_cap_apps apps os_specific"/' /etc/rkhunter.conf
rkhunter --propupd
sed -i 's/--output mail/--output mail --detail 10 --range "since 1 days ago" --archives --numeric --service All/' /etc/cron.daily/00logwatch
}

function install_tools
{
#install full vim, nano, less, htop (nice version of top), iotop (top for disk io), logrotate (rotates logs..), lynx (text webbrowser), mytop (top for mysql), screen (terminal emulator), sqlite3 (command line interface for sqlite databases)
aptitude -y install vim nano less htop iotop logrotate lynx mytop nmap screen sqlite3 cron-apt ntp curl pflogsumm bar apt-show-versions iftop build-essential
echo 'SYSLOGON="always"' >> /etc/cron-apt/config
echo 'MAILON="upgrade"' >> /etc/cron-apt/config
}

function install_ubuntu_stock_kernel
{
#installs ubuntu virtual kernel which works best on linode
#sets console to hvc0 so you can access via lish
#turns off barrier which breaks booting with 3.2+ kernels
#switches to ext4 but retains backwards compatablity with ext3
aptitude -y install linux-virtual grub
update-grub -y
sed -i 's#kopt=root=.* ro#kopt=root=/dev/xvda ro#' /boot/grub/menu.lst
sed -i 's#groot=.*#groot=(hd0)#' /boot/grub/menu.lst
sed -i 's/defoptions=quiet splash/defoptions=quiet console=hvc0/' /boot/grub/menu.lst
sed -i 's/# indomU=detect/# indomU=true/' /boot/grub/menu.lst
sed -i 's/noatime/barrier=0,noatime/' /etc/fstab
sed -i 's/ext3/ext4/' /etc/fstab
update-grub -y
chmod 0600 /boot/grub/menu.lst
cat <<EOT >/etc/init/hvc0.conf
# hvc - getty
#
# This service maintains a getty on hvc0 from the point the system is
# started until it is shut down again.

start on stopped rc RUNLEVEL=[2345]
stop on runlevel [!2345]

respawn
exec /sbin/getty -8 38400 hvc0
EOT
}

function set_root_profile
{
#Black       0;30     Dark Gray     1;30
#Blue        0;34     Light Blue    1;34
#Green       0;32     Light Green   1;32
#Cyan        0;36     Light Cyan    1;36
#Red         0;31     Light Red     1;31
#Purple      0;35     Light Purple  1;35
#Brown       0;33     Yellow        1;33
#Light Gray  0;37     White         1;37
cat <<EOT >> /root/.profile
PS1='\[\033[0;33m\]root@'
#add hostname
PS1=\$PS1\$(hostname -f)'\n'
#add ipv4 addresses
PS1=\$PS1\$(ifconfig | grep -v '127.0.0.1' | awk -F: '/inet addr:/ {print \$2}' | awk '{ print \$1 }')
#add ipv6 addresses
PS1=\$PS1'\n'\$(ifconfig | grep 'Global' | awk -F /  '/inet6 addr: / {print \$1}' | awk '{ print \$3 }')
#add current working dir and close colours
PS1=\$PS1'\n\$PWD:\$\033[00m\]\n'
export PS1
EOT

}

function cleanup
{
#disable services not required
if [ -f /etc/init/atd.conf ]
then
stop atd
mv /etc/init/atd.conf /etc/init/atd.conf.noexec
fi
sed -i 's/true/false/' /etc/default/whoopsie
update-locale
#tweak min free kbytes to get around page allocation failures on newer kernels
echo "vm.min_free_kbytes=6144" > /etc/sysctl.d/60-page.conf 
}

function install_vpn
{
#L2TPD/IPSEC
echo "openswan  openswan/install_x509_certificate   boolean false" | debconf-set-selections
echo "openswan  openswan/runlevel_changes   note" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -q -y openswan
rm -rf /etc/ipsec.conf
touch /etc/ipsec.conf
cat  <<EOT > /etc/ipsec.conf
version 2.0
config setup
    nat_traversal=yes
    virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12
    oe=off
    protostack=netkey

conn L2TP-PSK-NAT
    rightsubnet=vhost:%priv,%no
    also=L2TP-PSK-noNAT

conn L2TP-PSK-noNAT
    authby=secret
    pfs=no
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    left=`system_primary_ip`
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
EOT
cat <<EOT > /etc/ipsec.secrets
`system_primary_ip` %any:   PSK "$VPN_PSK"
EOT

apt-get install -y xl2tpd
touch /etc/xl2tpd/xl2tpd.conf
cat <<EOT > /etc/xl2tpd/xl2tpd.conf
[global]
ipsec saref = yes
[lns default]
ip range = $VPN_IPRANGE.2-$VPN_IPRANGE.254
local ip = $VPN_IPRANGE.1
refuse chap = yes
refuse pap = yes
require authentication = yes
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOT

rm -rf /etc/ppp/options.xl2tpd
touch /etc/ppp/options.xl2tpd
cat <<EOT > /etc/ppp/options.xl2tpd
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
name $VPN_SERVICENAME
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
EOT
cat <<EOT > /etc/ppp/chap-secrets
$VPN_USERNAME   $VPN_SERVICENAME    $VPN_PASSWORD   *
EOT
cat <<EOT > /etc/rc.local
#!/bin/sh -e
iptables --table nat --append POSTROUTING --jump MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward
for each in /proc/sys/net/ipv4/conf/*
do
    echo 0 > \$each/accept_redirects
    echo 0 > \$each/send_redirects
done
/etc/init.d/ipsec restart
exit 0
EOT
clear
iptables --table nat --append POSTROUTING --jump MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward
for each in /proc/sys/net/ipv4/conf/*
do
    echo 0 > $each/accept_redirects
    echo 0 > $each/send_redirects
done
xl2tpd
/etc/init.d/ipsec restart
ipsec verify
clear
/etc/init.d/ipsec restart
ipsec verify
}
