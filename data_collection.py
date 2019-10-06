import sys
import gzip
from attacker_levels import attacker_levels
from datetime import datetime
import os
import subprocess

session = sys.argv[1]
file_system = sys.argv[2]

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
      commands = command.split("|")
      for com in commands:
        com = com.replace("\x08", "").replace("\x07", "").strip()
        command_list.append(com)
        if com in attacker_levels.keys():
            level = max(level, attacker_levels.get(com))
      if len(com) == 0:
        level = 1

  num_commands = len(command_list)
  time_out = lines[-1].decode("utf-8").split(" ")[1][:-1][:-4]
  datetime_in = datetime.strptime(time_in, "%H:%M:%S")
  datetime_out = datetime.strptime(time_out, "%H:%M:%S")
  elapsed_timedelta = datetime_out - datetime_in
  duration_in_s = elapsed_timedelta.total_seconds()
  #minutes = divmod(duration_in_s, 60)[0]
  #elapsed_time = "{}".format(elapsed_timedelta.min)

  print("CTID: {}".format(ctid))
  print("IP: {}".format(ip))
  print("Date: {}".format(date))
  print("Time in: {}".format(time_in))
  print("Time out: {}".format(time_out))
  print("Elapsed time (min): {}".format(duration_in_s))
  print("Num commands: {}".format(num_commands))
  print("Level: {}".format(level))
  print("Commands run: {}".format(command_list))

  str_list = ' : '.join(command_list)

  #execute = "{},{},{},{},{},{},{},{},{}".format(file_system, ip, date, time_in, time_out,
                                                 #duration_in_s, num_commands, level,
                                                 #str_list)
  execute = []
  first_half = ["log", "-k", "/root/Honeypot_Scripts/hacs.json", "-s"]
  execute.extend(first_half)
  if ctid == 101:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=0")
  elif ctid == 102:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=1766837841")
  elif ctid == 103:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=221991272")
  elif ctid == 104:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=747273361")
  last_half = ["-d", file_system, ip, date, time_in, time_out, duration_in_s, num_commands, level, str_list]
  execute.extend(last_half)
  subprocess.call(execute)
  '''
  if ctid == 101:
    os.system("log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=0 -d {}".format(execute))
  elif ctid == 102:
    os.system("log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=1766837841 -d {}".format(execute))
  elif ctid == 103:
    os.system("log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=221991272 -d {}".format(execute))
  elif ctid == 104:
    os.system("log -k /root/Honeypot_Scripts/hacs.json -s https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=747273361 -d {}".format(execute))
  '''

  



  
