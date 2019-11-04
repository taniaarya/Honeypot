#!/bin/bash

# $1 = ctid
# $2 = ct ip
# $3 = mitm port
# $4 = session id
# $5 = filesystem
# $6 = attacker ip
# $7 = timestamp

# kicks attacker out after 30 minutes
sleep 1800

# time attacker is kicked out
disConnTime=$(date +%H:%M:%S)

# kill the tail script
#pkill -f "tailing_script.sh $1"

# kill the tailing process started by the tailscript
#pkill -f "tail -n 0 -F /var/lib/lxc/$1/rootfs/var/log/auth.log"

#echo "killing node /root/MITM/mitm/index.js HACS200_2C $3 $2 $1 true mitm.js"
#pkill -f "node /root/MITM/mitm/index.js HACS200_2C $3 $2 $1 true mitm.js"

# allows mitm process to be fully killed before adding firewall rules
#sleep 25

#ps_aux=$(ps aux | grep node)
#echo "$ps_aux"

# calls recycling script passing ctid, ctip, mitm port, and timestamp
echo "calling recyling /root/Honeypot_Scripts/recycling_script.sh $1 $2 $3 $6"
/root/Honeypot_Scripts/recycling_script.sh $1 $2 $3 $6 $7 > /root/Logs/recycling/$7>&1 &

# calls data collection script with session id and filesystem, ctid, attacker ip
echo "calling data_collection /root/Honeypot_Scripts/call_data_collection.sh $4 $5 $1 $6 $disConnTime"
/root/Honeypot_Scripts/call_data_collection2.sh $4 $5 $1 $6 $disConnTime > /root/Logs/data_collection/$7>&1 &

# makes sure disk space is good
/root/Honeypot_Scripts/check_health.sh &


