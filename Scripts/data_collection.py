import sys
import gzip
from Scripts import attacker_levels
from datetime import datetime

session = sys.argv[1]

filepath = f"/root/MITM_data/sessions/{session}.gz"

with gzip.open(filepath) as file:
  lines = file.readlines()
  ctid = lines[2].split("Container ID: ")[-1]
  identifier = f"root@CT{ctid}:~# "
  ip = lines[3].split("Attacker IP Address: ")[-1]
  date = lines[7].split(" ")[1]   # Date in YYYY-MM-DD format
  time_in = lines[7].split(" ")[-1]  # time in 24 hrs HH:MM:SS...
  command_list = []
  level = 0

  for line in lines:
    if identifier in line:
      command = line.split(identifier)[-1]
      if "|" in command:
        command_list.extend(command.split("|"))
      else:
        command_list.append(command)
      if command in attacker_levels:
        level = attacker_levels.get(command)
  
  num_commands = command_list.__len__
  time_out = lines[-1].split(" ")[1][:-1]
  datetime_in = datetime.strptime(time_in, "%H:%M:%S")
  datetime_out = datetime.strptime(time_out, "%H:%M:%S")
  elapsed_timedelta = datetime_out - datetime_in
  elapsed_time = f"{elapsed_timedelta.minutes}"

  



  