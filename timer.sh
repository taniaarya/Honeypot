#!/bin/bash

# $1 = ctid
# $2 = ct ip
# $3 = mitm port
# $4 = session id
# $5 = filesystem
# $6 = attacker ip

# kicks attacker out after 1 hour
sleep 120

# kill the tail script
pkill -f "tailing_script.sh $1"

# kill the tailing process started by the tailscript
pkill -f "tail -n 0 -F /var/lib/lxc/$1/rootfs/var/log/auth.log"

# adds firewall rules to block out attacker, and re
iptables --table filter --delete INPUT --source $6 --destination 172.20.0.1 --in-interface enp4s1 --jump ACCEPT
iptables --table filter --delete INPUT --protocol tcp --destination 172.20.0.1 --dport $3 --jump DROP
iptables --table filter --insert INPUT --protocol tcp --source $6 --destination 172.20.0.1 --in-interface enp4s1 --dport $3 --jump DROP
#iptables --table filter --insert FORWARD --protocol tcp --source $6 --destination $2 --dport 22 --jump DROP


# calls recycling script passing ctid, ctip, and mitm port
/root/Honeypot_Scripts/recycling_script.sh $1 $2 $3 &

# calls data collection script with session id and filesystem
/root/Honeypot_Scripts/call_data_collection.sh $4 $5 &

# makes sure disk space is good
/root/Honeypot_Scripts/check_health.sh &


