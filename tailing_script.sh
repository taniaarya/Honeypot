#!/bin/bash

# $1 = ctid
# $2 = container ip

#pct unmount $1
#sleep 60
#pct mount $1

numConn=0 # tracks number of connections made
connMade=0 # boolean tracking if a connection has already been made
conn="" # checks if auth.log shows attacker is "accepted" or "disconnected"
ip=0 # attacker ip
timestamp="test" # timestamp of attacker entry
session="" # mitm session id

# tails auth.log file and reads every new line
tail -n 0 -F /var/lib/lxc/$1/rootfs/var/log/auth.log | while read a; do
    	
      accept=$(echo "$a" | awk -F";" '{print $6}') # checks for keyword "Accepted"
    	closed=$(echo "$a" | awk -F" " '{print $6,$7,$8}') #checks for keyword "pam_unix(sshd:session): session closed"
    	
      # if the connection has been accepted, a new atacker is in the honeypot
      if [[ $accept = "Accepted" ]]
    	then
              # checks if no previous connections have been made
            	if [ $connMade -eq 0 ]
            	then
                # records time of entry
                timestamp=$(date +%Y-%m-%d-%H:%M:%S)
                # echo "The timestamp is $timestamp"
                # makes directory to store auth.log file in
                mkdir -p /root/Logs/$1/
            	fi

              # extracts attacker ip and session id from MITM login file
            	ip=$(tail -1 /root/MITM_data/logins/$1.txt | awk -F\; '{print $2}')
              session=$(tail -1 /root/MITM_data/logins/$1.txt | awk -F\; '{print $3}')
            	#echo "ip is $ip"

              # increases connection count
              numConn=$((numConn+1))
            	#echo "Accepted: numConn is $numConn"
              # sets boolean to true
              connMade=1
            	
              # checks if this is the only connection to add respective ip rules
              if [ $numConn -eq 1 ]
            	then
                  # echo "Adding rules"
                  # removes sentinnel file
                  rm /tmp/login_$1
                  
                  # kills the timer
                  pkill -f "timer $1"

                  # removes rules in case of overlap
                  iptables --table filter --delete FORWARD --protocol tcp --destination $2 --dport 22 --jump DROP
                  iptables --table filter --delete FORWARD --source $ip --destination $2 --in-interface enp4s2 --out-interface vmbr0 --jump ACCEPT
                  # addes firewall rules to drop all ssh traffic except for attacker ip
                  iptables --table filter --insert FORWARD 6 --protocol tcp --destination $2 --dport 22 --jump DROP
                  iptables --table filter --insert FORWARD --source $ip --destination $2 --in-interface enp4s2 --out-interface vmbr0 --jump ACCEPT
            	fi

      # checks if the attacker has disconnected
    	elif [[ $closed = "pam_unix(sshd:session): session closed" ]]
    	then
            	#echo "Disconnected: numConn is $numConn"
              # decrement number of connections by 1
            	if [ $numConn -ne 0 ]
            	then
                        numConn=$((numConn-1))
            	fi
              # checks if this was the last connection
            	if [ $numConn -eq 0 ] && [ $connMade -eq 1 ]
            	then
                    # adds the disconnect timestamp to the login file
                    date -u +%s > /tmp/login_$1
                    # starts the 10 minute timer
                    nohup /root/Honeypot_Scripts/timer $1 $2 $ip $session &
            	fi
    	fi
      # if a connection as been made, copies line to Log folder on host
    	if [ $connMade -eq 1 ]
    	then
            	echo "$a" >> /root/Logs/$1/$timestamp
    	fi
done
