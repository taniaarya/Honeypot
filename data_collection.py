import sys
import gzip
import attacker_levels
from datetime import datetime

session = sys.argv[1]

filepath = "/root/MITM_data/sessions/{}.gz".format(session)

with gzip.open(filepath) as file:
  lines = file.readlines()
  str_ctid = lines[2].decode("utf-8")
  ctid = str_ctid.split("Container ID: ")[-1]
  identifier = "root@CT{}:~# ".format(ctid)
  ip = lines[3].decode("utf-8").split("Attacker IP Address: ")[-1]
  date = lines[7].decode("utf-8").split(" ")[1]   # Date in YYYY-MM-DD format
  time_in = lines[7].decode("utf-8").split(" ")[-1]  # time in 24 hrs HH:MM:SS...
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
  
  num_commands = len(command_list)
  time_out = lines[-1].decode("utf-8").split(" ")[1][:-1]
  datetime_in = datetime.strptime(time_in, "%H:%M:%S")
  datetime_out = datetime.strptime(time_out, "%H:%M:%S")
  elapsed_timedelta = datetime_out - datetime_in
  elapsed_time = "{}".format(elapsed_timedelta.minutes)

  print("CTID: {}".format(ctid))
  print("IP: {}".format(ip))
  print("Date: {}".format(date))
  print("Time in: {}".format(time_in))
  print("Time out: {}".format(time_out))
  print("Elapsed time (min): {}".format(elapsed_time))
  print("Num commands: {}".format(num_commands))
  print("Commands run: {}".format(command_list))


  



  
