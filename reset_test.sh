#!/bin/bash

pkill node
pkill tail

/root/Honeypot_Project/firewall/firewall_rules.sh

nohup node /root/MITM/mitm/index.js HACS200_2C 10000 172.20.0.2 101 true mitm.js > /root/Logs/mitm_file101>&1 &
nohup node /root/MITM/mitm/index.js HACS200_2C 10001 172.20.0.3 102 true mitm.js > /root/Logs/mitm_file102>&1 &
nohup node /root/MITM/mitm/index.js HACS200_2C 10002 172.20.0.4 103 true mitm.js > /root/Logs/mitm_file103>&1 &
nohup node /root/MITM/mitm/index.js HACS200_2C 10003 172.20.0.5 104 true mitm.js > /root/Logs/mitm_file104>&1 &

nohup /root/Honeypot_Scripts/tailing_script.sh 101 172.20.0.2 "Yes" 10000 > /root/Logs/tail101>&1 &
nohup /root/Honeypot_Scripts/tailing_script.sh 102 172.20.0.3 "Yes" 10001 > /root/Logs/tail102>&1 &
nohup /root/Honeypot_Scripts/tailing_script.sh 103 172.20.0.4 "Yes" 10002 > /root/Logs/tail103>&1 &
nohup /root/Honeypot_Scripts/tailing_script.sh 104 172.20.0.5 "Yes" 10003 > /root/Logs/tail104>&1 &

