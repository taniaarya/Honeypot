import sys
import gzip
from attacker_levels import attacker_levels
from datetime import datetime
import re

session = sys.argv[1]

filepath = "/root/MITM_data/sessions/{}.gz".format(session)

with gzip.open(filepath) as file:
  lines = file.readlines()
  str_ctid = lines[2].decode("utf-8").rstrip()
  ctid = str_ctid.split("Container ID: ")[-1]
  identifier = "root@CT{}:".format(ctid)
  ip = lines[3].decode("utf-8").split("Attacker IP Address: ")[-1].rstrip()
  date = lines[7].decode("utf-8").split(" ")[1]   # Date in YYYY-MM-DD format
  time_in = lines[7].decode("utf-8").split(" ")[-1][:-5]  # time in 24 hrs HH:MM:SS...
  command_list = []
  level = 0

  for line in lines:
    line = line.decode("utf-8").encode("ascii", "ignore").decode("utf-8")
    #re.sub(r'[^\x00-\x7f]', r'', line)
    #line = line.decode("utf-8")
    if identifier in line:
      command = line.split(identifier)[-1].rstrip()
      command = command[command.find("#")+2:]
      command = command.replace("\x08", "").replace("\x07", "")
      #re.sub(r'[^\x00-\x7f]', r'', command)s
      if "|" in command:
        command_list.extend(command.split("|"))
      else:
        command_list.append(command)
      if command in attacker_levels:
        level = attacker_levels.get(command)
  
  num_commands = len(command_list)
  time_out = lines[-1].decode("utf-8").split(" ")[1][:-1][:-4]
  datetime_in = datetime.strptime(time_in, "%H:%M:%S")
  datetime_out = datetime.strptime(time_out, "%H:%M:%S")
  elapsed_timedelta = datetime_out - datetime_in
  duration_in_s = elapsed_timedelta.total_seconds()
  minutes = divmod(duration_in_s, 60)[0]
  elapsed_time = "{}".format(elapsed_timedelta.min)

  print("CTID: {}".format(ctid))
  print("IP: {}".format(ip))
  print("Date: {}".format(date))
  print("Time in: {}".format(time_in))
  print("Time out: {}".format(time_out))
  print("Elapsed time (min): {}".format(minutes))
  print("Num commands: {}".format(num_commands))
  print("Commands run: {}".format(command_list))


  



  
