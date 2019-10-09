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

# tails auth.log file and reads every new line
tail -n 0 -F /var/lib/lxc/$1/rootfs/var/log/auth.log | while read a; do
      
      accept=$(echo "$a" | awk -F" " '{print $6}') # checks for keyword "Accepted"
      closed=$(echo "$a" | awk -F" " '{print $6,$7,$8}') #checks for keyword "pam_unix(sshd:session): session closed"
    	
      # if the connection has been accepted, a new atacker is in the honeypot
      if [[ $accept = "Accepted" ]]
      then
              # checks if no previous connections have been made
            	if [ $connMade -eq 0 ]
            	then
                # records time of entry
                timestamp=$(date +%Y-%m-%d-%H:%M:%S)
                echo "The timestamp is $timestamp"
                # makes directory to store auth.log file in
                mkdir -p /root/Logs/$1/
            	fi

              # extracts attacker ip and session id from MITM login file
            	ip=$(tail -1 /root/MITM_data/logins/$1.txt | awk -F\; '{print $2}')
              session=$(tail -1 /root/MITM_data/logins/$1.txt | awk -F\; '{print $3}')
            	echo "ip is $ip"

              # increases connection count
              numConn=$((numConn+1))
            	echo "Accepted: numConn is $numConn"
              # sets boolean to true
              connMade=1
            	
              # checks if this is the only connection to add respective ip rules
              if [ $numConn -eq 1 ]
            	then
                  echo "Adding rules"
                  # Logic: The attacker disconnects and numConn = 0 --> /tmp/login file is made & disconnect timer is started
                  # After __ sec, if the attacker hasnt come back, kill the container
                  # if the attacker comes back, delete /tmp/login and kill the timer
                  # repeat
                  #rm /tmp/login_$1
                  
                  # kills the timer
                  #pkill -f "timer $1"

                  # removes rules in case of overlap
		  if [ $connMade -eq 0 ]
	          then
                  	iptables --table filter --delete INPUT --protocol tcp --destination 172.20.0.1 --dport $4 --jump DROP
                  	iptables --table filter --delete INPUT --source $ip --destination 172.20.0.1 --in-interface enp4s1 --jump ACCEPT
		  fi
		  # addes firewall rules to drop all ssh traffic except for attacker ip
                  iptables --table filter --insert INPUT 6 --protocol tcp --destination 172.20.0.1 --dport $4 --jump DROP
                  iptables --table filter --insert INPUT --source $ip --destination 172.20.0.1 --in-interface enp4s1 --jump ACCEPT
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
                    # adds the disconnect timestamp to the login file
                    #date -u +%s > /tmp/login_$1
                    # starts the 10 minute timer
                    #nohup /root/Honeypot_Scripts/timer $1 $2 $ip $session &

                    # adds firewall rules to block out attacker, and re
                    iptables --table filter --delete INPUT --source $ip --destination 172.20.0.1 --in-interface enp4s1 --jump ACCEPT
                    iptables --table filter --delete INPUT --protocol tcp --destination 172.20.0.1 --dport $4 --jump DROP
                    iptables --table filter --insert INPUT --source $ip --destination 172.20.0.1 --in-interface enp4s1 --dport $4 --jump DROP

                    # checks if the self-created directories exist on the container to determine whether or not container had filesystem installed
                    
                    #file=$(pct exec $1 "ls | grep International_Branches")
                    #file_system="No"
                    #if [[ $file = "International_Branches" ]]
                    #then
                    #  file_system="Yes"
                    #fi
                    
                    # calls recycling script passing ctid, attacker ip, and ctip
                    /root/Honeypot_Scripts/recycling_script.sh $1 $2 $4

                    # calls data collection script with session id and filesystem
                    python3.6 /root/Honeypot_Scripts/data_collection.py $session $3
            	fi
    	fi

      # if a connection as been made, copies line to Log folder on host
    	if [ $connMade -eq 1 ]
    	then
            	echo "$a" >> /root/Logs/$1/$timestamp
    	fi
done
