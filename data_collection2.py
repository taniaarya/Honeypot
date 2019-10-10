import sys
import gzip
from attacker_levels import attacker_levels
from datetime import datetime
import os
import subprocess
import slack

# $1 = session id
# $2 = file system - "yes" or "no"?

# Stores command line arguments in variables
session = sys.argv[1]

# filepath for MITM sessions (uses argument given)
filepath = "/root/MITM_data/sessions/{}.gz".format(session)

with gzip.open(filepath, "rt", encoding="utf-8") as file:
  line = fp.readline()
  print(line)



  
