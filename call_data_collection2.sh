#!/bin/bash

echo "Starting call to data collection"
/usr/local/bin/python3.6 /root/Honeypot_Scripts/data_collection2.py $1 $2 $3 $4 $5 &
exit 0
