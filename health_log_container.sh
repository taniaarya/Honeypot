#!/bin/bash

date=$(/bin/date)
cram=$(/usr/sbin/pct exec $1 -- /usr/bin/free --mega | /bin/grep Mem | /usr/bin/awk '{print $7}')
cdisk=$(/usr/sbin/pct exec $1 -- /bin/df -BM --total | /bin/grep total | /usr/bin/awk '{print $4}')
cdisk_length=$(/usr/bin/expr length $cdisk)
cdisk_length=$((cdisk_length-1))
cdisk=$(/bin/echo $cdisk | /usr/bin/cut -c1-$cdisk_length)
cload=$(/usr/sbin/pct exec $1 -- /usr/bin/uptime | /usr/bin/awk '{print $NF}')
crxkb=$(/usr/sbin/pct exec $1 -- /sbin/ifconfig eth0 | /bin/grep RX| /usr/bin/awk 'NR==2{print $3}')
crxkb_length=$(/usr/bin/expr length $crxkb)
crxkb=$(/bin/echo $crxkb | /usr/bin/cut -c2-$crxkb_length)
#crxkb=$(bc <<< $crxmb/1024)
ctxkb=$(/usr/sbin/pct exec $1 -- /sbin/ifconfig eth0 | /bin/grep TX | /usr/bin/awk 'NR==2{print $7}')
ctxkb_length=$(/usr/bin/expr length $ctxkb)
ctxkb=$(/bin/echo $ctxkb | /usr/bin/cut -c2-$ctxkb_length)
#ctxkb=$(bc <<< $ctxmb/1024)

if [ $1 -eq 101 ]
then
	log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/10WP00Gvlu2ZmFNLv0u0APAG0IhS1JBWdGjQpifkqGAM/edit#gid=0 -d "$date,$cram,$cdisk,$cload,$crxkb,$ctxkb"
elif [ $1 -eq 102 ]
then
	log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/10WP00Gvlu2ZmFNLv0u0APAG0IhS1JBWdGjQpifkqGAM/edit#gid=1962965854 -d "$date,$cram,$cdisk,$cload,$crxkb,$ctxkb"
elif [ $1 -eq 103 ]
then
	log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/10WP00Gvlu2ZmFNLv0u0APAG0IhS1JBWdGjQpifkqGAM/edit#gid=1687537876 -d "$date,$cram,$cdisk,$cload,$crxkb,$ctxkb"
elif [ $1 -eq 104 ]
then
	log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/10WP00Gvlu2ZmFNLv0u0APAG0IhS1JBWdGjQpifkqGAM/edit#gid=356872969 -d "$date,$cram,$cdisk,$cload,$crxkb,$ctxkb"	
fi
