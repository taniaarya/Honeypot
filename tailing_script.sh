#!/bin/bash

# $1 = ctid
# $2 = container ip

#pct unmount $1
#sleep 60
#pct mount $1
numConn=0
connMade=0
conn=""
ip=0
timestamp="test"
session=""
tail -n 0 -F /var/lib/lxc/$1/rootfs/var/log/auth.log | while read a; do
    	accept=$(echo "$a" | awk -F";" '{print $6}')
    	closed=$(echo "$a" | awk -F" " '{print $6,$7,$8}')
    	if [[ $accept = "Accepted" ]]
    	then
            	if [ $connMade -eq 0 ]
            	then
                timestamp=$(date +%Y_%m_%d-%H:%M:%S)
                # echo "The timestamp is $timestamp"
                mkdir -p /root/Logs/$1/
            	fi
            	ip=$(tail -1 /root/MITM_data/logins/$1.txt | awk -F\; '{print $2}')
              session=$(tail -1 /root/MITM_data/logins/$1.txt | awk -F\; '{print $3}')
            	#echo "ip is $ip"
              numConn=$((numConn+1))
            	#echo "Accepted: numConn is $numConn"
              connMade=1
            	if [ $numConn -eq 1 ]
            	then
                      #echo "Adding rules"
                    	if [ $1 -eq 101 ]
                      then
                        rm /tmp/login_$1
                        pkill -f "timer $1"
                        iptables --table filter --delete FORWARD --protocol tcp --destination $2 --dport 22 --jump DROP
                        iptables --table filter --delete FORWARD --source $ip --destination $2 --in-interface enp4s2 --out-interface vmbr0 --jump ACCEPT
                        iptables --table filter --insert FORWARD 6 --protocol tcp --destination $2 --dport 22 --jump DROP
                        iptables --table filter --insert FORWARD --source $ip --destination $2 --in-interface enp4s2 --out-interface vmbr0 --jump ACCEPT
            	fi

    	elif [[ $closed = "pam_unix(sshd:session): session closed" ]]
    	then
            	#echo "Disconnected: numConn is $numConn"
            	if [ $numConn -ne 0 ]
            	then
                        numConn=$((numConn-1))
            	fi
            	if [ $numConn -eq 0 ] && [ $connMade -eq 1 ]
            	then
                    #echo "Deleting Rules"
                    date -u +%s > /tmp/login_$1
                    nohup /root/Honeypot_Scripts/timer $1 $2 $ip $session &
            	fi
    	fi
    	if [ $connMade -eq 1 ]
    	then
            	echo "$a" >> /root/Logs/$1/$timestamp
    	fi
done
