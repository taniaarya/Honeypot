#!/bin/bash

pdisk=$(/bin/df -BM --total | /bin/grep total | /usr/bin/awk '{print $4}'| sed 's/.$//')
pram=$(/usr/bin/free --mega | /bin/grep "Mem" | /usr/bin/awk '{print $7}')

if [ $pdisk -le 1000 ]
then
	/usr/local/bin/python3.6 /root/Honeypot_Scripts/send_health_update.py $pdisk $pram
elif [ $pram -le 1000 ]
then
	/usr/local/bin/python3.6 /root/Honeypot_Scripts/send_health_update.py $pdisk $pram
fi
exit 0
