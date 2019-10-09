#!/bin/bash

echo "Starting call to data collection"
/usr/local/bin/python3.6 /root/Honeypot_Scripts/data_collection.py $1 $2
exit 0
