#!/bin/bash

date=$(/bin/date)

log_params="$date"

# Proxmox

# RAM in MB
pram=$(/usr/bin/free --mega | /bin/grep "Mem" | /usr/bin/awk '{print $7}')
log_params="${log_params},$pram"
# Disk space available in MB
pdisk=$(/bin/df -BM --total | /bin/grep total | /usr/bin/awk '{print $4}'| sed 's/.$//')
log_params="${log_params},$pdisk"
# System load for past 15 minutes
pload=$(/usr/bin/uptime | /usr/bin/awk '{print $NF}')
log_params="${log_params},$pload"
# Incoming Network Traffic on the UMD Network interface in KB (RX bytes)
prxmb=$(/sbin/ifconfig enp4s1 | /bin/grep RX | /usr/bin/awk 'NR==1{print $5}')
prxkb=$((prxmb/1024))
log_params="${log_params},$prxkb"
# Outgoing Network Traffic on the UMD Network interface in KB (TX bytes)
ptxmb=$(/sbin/ifconfig enp4s1 | /bin/grep TX | /usr/bin/awk 'NR==1{print $5}')
ptxkb=$((ptxmb/1024))
log_params="${log_params},$ptxkb"

#Containers

declare -a ctids=("101" "102" "103" "104")
for val in ${ctids[@]}; do
  cram=$(/usr/sbin/pct exec 101 -- /usr/bin/free --mega | /bin/grep Mem | /usr/bin/awk '{print $7}')
  log_params="${log_params},$cram"
  cdisk=$(/usr/sbin/pct exec 101 -- /bin/df -BM --total | /bin/grep total | /usr/bin/awk '{print $4}')
  cdisk_length=$(/usr/bin/expr length $cdisk)
  cdisk_length=$((cdisk_length-1))
  cdisk=$(/bin/echo $cdisk | /usr/bin/cut -c1-$cdisk_length)
  log_params="${log_params},$cdisk"
  cload=$(/usr/sbin/pct exec 101 -- /usr/bin/uptime | /usr/bin/awk '{print $NF}')
  log_params="${log_params},$cload"

  #crxkb=$(/usr/sbin/pct exec 101 -- /sbin/ifconfig eth0 | /bin/grep RX| /usr/bin/awk 'NR==2{print $3}')
  #crxkb_length=$(/usr/bin/expr length $crxkb)
  #crxkb=$(/bin/echo $crxkb | /usr/bin/cut -c2-$crxkb_length)
  #log_params="${log_params},$crxkb"
  #ctxkb=$(/usr/sbin/pct exec 101 -- /sbin/ifconfig eth0 | /bin/grep TX | /usr/bin/awk 'NR==2{print $7}')
  #ctxkb_length=$(/usr/bin/expr length $ctxkb)
  #ctxkb=$(/bin/echo $ctxkb | /usr/bin/cut -c2-$ctxkb_length) 
  #log_params="${log_params},$ctxkb"

done

log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/10WP00Gvlu2ZmFNLv0u0APAG0IhS1JBWdGjQpifkqGAM/edit#gid=0 -d "$log_params"

