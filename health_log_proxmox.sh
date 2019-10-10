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

log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/10WP00Gvlu2ZmFNLv0u0APAG0IhS1JBWdGjQpifkqGAM/edit#gid=1633115840 -d "$date,$pram,$pdisk,$pload,$prxkb,$ptxkb"
