#!/bin/bash

# $1 = ctid
# $2 = ct ip
# $3 = attacker ip
# $4 = MITM session id

sleep 605

if [ -f "/tmp/login_$1" ]
then
        startTime=$(tail -1 /tmp/login_$1)
        endTime=$(date -u +%s)
        elapsed=$(($endTime-$startTime))
        $echo "elapsed time is $elapsed"
        if [ $elapsed -ge 600 ]
        then
                rm /tmp/login_$1
                iptables --table filter --delete FORWARD --source $3 --destination $2 --in-interface enp4s2 --out-interface vmbr0 --jump ACCEPT
                iptables --table filter --delete FORWARD --protocol tcp --destination $2 --dport 22 --jump DROP
                iptables --table filter --insert FORWARD --source $3 --destination $2 --in-interface enp4s2 --out-interface vmbr0 --jump DROP
                file=$(pct exec $1 "ls | grep International_Branches")
                file_system="No"
                if [[ $file = "Accepted" ]]
                then
                  file_system="Yes"
                fi
                /root/Honeypot_Scripts/RecyclingScript.bash $1 $3 $2
                /root/Honeypot_Scripts/tailing_script.sh $4 $file_system
                exit 0
        fi
fi
exit 0
