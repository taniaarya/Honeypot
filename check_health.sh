#!/bin/bash

pdisk=$(/bin/df -BM --total | /bin/grep total | /usr/bin/awk '{print $4}'| sed 's/.$//')

if [ $pdisk -le 1000 ]
then
	echo "here"
	/usr/local/bin/python3.6 /root/Honeypot_Scripts/send_health_update.py $pdisk
fi
exit 0
