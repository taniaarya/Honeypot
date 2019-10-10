#!/bin/bash

date=$(/bin/date)
pram=$(/usr/bin/free --mega | /bin/grep "Mem" | /usr/bin/awk '{print $7}')
pdisk=$(/bin/df -BM --total | /bin/grep total | /usr/bin/awk '{print $4}')
pdisk_length=$(/usr/bin/expr length $pdisk)
pdisk_length=$((pdisk_length-1))
pdisk=$(/bin/echo $pdisk | /usr/bin/cut -c1-$pdisk_length)
pload=$(/usr/bin/uptime | /usr/bin/awk '{print $NF}')
prxmb=$(/sbin/ifconfig enp4s2 | /bin/grep RX | /usr/bin/awk 'NR==1{print $5}')
prxkb=$((prxmb/1024))
ptxmb=$(/sbin/ifconfig enp4s2 | /bin/grep TX | /usr/bin/awk 'NR==1{print $5}')
ptxkb=$((ptxmb/1024))
 
cram=$(/usr/sbin/pct exec 101 -- /usr/bin/free --mega | /bin/grep Mem | /usr/bin/awk '{print $7}')
cdisk=$(/usr/sbin/pct exec 101 -- /bin/df -BM --total | /bin/grep total | /usr/bin/awk '{print $4}')
cdisk_length=$(/usr/bin/expr length $cdisk)
cdisk_length=$((cdisk_length-1))
cdisk=$(/bin/echo $cdisk | /usr/bin/cut -c1-$cdisk_length)
cload=$(/usr/sbin/pct exec 101 -- /usr/bin/uptime | /usr/bin/awk '{print $NF}')
crxkb=$(/usr/sbin/pct exec 101 -- /sbin/ifconfig eth0 | /bin/grep RX| /usr/bin/awk 'NR==2{print $3}')
crxkb_length=$(/usr/bin/expr length $crxkb)
crxkb=$(/bin/echo $crxkb | /usr/bin/cut -c2-$crxkb_length)
#crxkb=$(bc <<< $crxmb/1024)
ctxkb=$(/usr/sbin/pct exec 101 -- /sbin/ifconfig eth0 | /bin/grep TX | /usr/bin/awk 'NR==2{print $7}')
ctxkb_length=$(/usr/bin/expr length $ctxkb)
ctxkb=$(/bin/echo $ctxkb | /usr/bin/cut -c2-$ctxkb_length)
#ctxkb=$(bc <<< $ctxmb/1024)
 
log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/10WP00Gvlu2ZmFNLv0u0APAG0IhS1JBWdGjQpifkqGAM/edit#gid=356872969 -d "$date,$pram,$pdisk,$pload,$prxkb,$ptxkb,$cram,$cdisk,$cload,$crxkb,$ctxkb"

