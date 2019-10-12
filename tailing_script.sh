#!/bin/bash

# $1 = ctid
# $2 = container ip
# $3 = file_system
# $4 = mitm port

#pct unmount $1
#sleep 60
#pct mount $1

numConn=0 # tracks number of connections made
connMade=0 # boolean tracking if a connection has already been made
conn="" # checks if auth.log shows attacker is "accepted" or "disconnected"
ip=0 # attacker ip
timestamp="test" # timestamp of attacker entry
session="" # mitm session id
disConnTime = ""

# tails auth.log file and reads every new line
tail -n 0 -F /var/lib/lxc/$1/rootfs/var/log/auth.log | while read a; do
      
      accept=$(echo "$a" | awk -F" " '{print $6}') # checks for keyword "Accepted"
      closed=$(echo "$a" | awk -F" " '{print $6,$7,$8}') #checks for keyword "pam_unix(sshd:session): session closed"
    	
      # if the connection has been accepted, a new atacker is in the honeypot
      if [[ $accept = "Accepted" ]]
      then
              # extracts attacker ip and session id from MITM login file
            	ip=$(tail -1 /root/MITM_data/logins/$1.txt | awk -F\; '{print $2}')
              session=$(tail -1 /root/MITM_data/logins/$1.txt | awk -F\; '{print $3}')
            	echo "ip is $ip"

              # checks if no previous connections have been made
            	if [ $connMade -eq 0 ]
            	then
                # records time of entry
                timestamp=$(date +%Y-%m-%d-%H:%M:%S)
                echo "The timestamp is $timestamp"
                # makes directory to store auth.log file in
                mkdir -p /root/Logs/$1/
                /root/Honeypot_Scripts/timer.sh $1 $2 $4 $session $3 $ip > /root/Logs/timer$1>&1 &
            	fi

              # increases connection count
              numConn=$((numConn+1))
            	echo "Accepted: numConn is $numConn"
              # sets boolean to true
              connMade=1
            	
              # checks if this is the only connection to add respective ip rules
              if [ $numConn -eq 1 ]
            	then
                  echo "Adding rules"

                  # removes rules in case of overlap
		  if [ $connMade -ne 0 ]
	          then
                  	iptables --table filter --delete INPUT --protocol tcp --destination 172.20.0.1 --dport $4 --jump DROP
                  	iptables --table filter --delete INPUT --source $ip --destination 172.20.0.1 --in-interface enp4s1 --protocol tcp --dport $4 --jump ACCEPT
		  fi
		  # addes firewall rules to drop all ssh traffic except for attacker ip
                  iptables --table filter --insert INPUT 5 --protocol tcp --destination 172.20.0.1 --dport $4 --jump DROP
                  iptables --table filter --insert INPUT --source $ip --destination 172.20.0.1 --in-interface enp4s1 --protocol tcp --dport $4 --jump ACCEPT
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
		echo "Disconnected: numConn is $numConn"
		echo "connMade: $connMade"
              # checks if this was the last connection
            	if [ $numConn -eq 0 ] && [ $connMade -eq 1 ]
            	then
                    disConnTime=$(date +%H:%M:%S)
                                     
                    # calls recycling script passing ctid, ctip, and mitm port
                    /root/Honeypot_Scripts/recycling_script.sh $1 $2 $4 $ip &

                    # calls data collection script with session id and filesystem, ctid, attacker ip
                    /root/Honeypot_Scripts/call_data_collection.sh $session $3 $1 $ip $disConnTime &

		    # makes sure disk space is good
		    /root/Honeypot_Scripts/check_health.sh &
            	fi
    	fi

      # if a connection as been made, copies line to Log folder on host
    	if [ $connMade -eq 1 ]
    	then
            	echo "$a" >> /root/Logs/$1/$timestamp
    	fi
done
