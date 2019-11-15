#!/bin/bash

recycle=$(/bin/ps aux | /bin/grep recycl | /usr/bin/wc -l)
data=$(/bin/ps aux | /bin/grep data_coll | /usr/bin/wc -l)

if [ $recycle -eq 1 ] && [ $data -eq 1 ]
then
  /root/Honeypot_Scripts/reset_test.sh
fi