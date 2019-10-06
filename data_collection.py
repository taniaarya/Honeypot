import sys
import gzip
from attacker_levels import attacker_levels
from datetime import datetime
import os
import subprocess

session = sys.argv[1]
file_system = sys.argv[2]

filepath = "/root/MITM_data/sessions/{}.gz".format(session)

with gzip.open(filepath, "rt", encoding="utf-8") as file:
  lines = file.readlines()
  #str_ctid = lines[2].decode("utf-8").rstrip()
  str_ctid = lines[2].rstrip()
  ctid = str_ctid.split("Container ID: ")[-1]
  identifier = "root@CT{}:".format(ctid)
  #ip = lines[3].decode("utf-8").split("Attacker IP Address: ")[-1].rstrip()
  ip = lines[3].split("Attacker IP Address: ")[-1].rstrip()
  #date = lines[7].decode("utf-8").split(" ")[1]   # Date in YYYY-MM-DD format
  date = lines[7].split(" ")[1]   # Date in YYYY-MM-DD format
  #time_in = lines[7].decode("utf-8").split(" ")[-1][:-5]  # time in 24 hrs HH:MM:SS...
  time_in = lines[7].split(" ")[-1][:-5]  # time in 24 hrs HH:MM:SS...
  command_list = []
  level = 0

  for line in lines:
    #line = line.decode("utf-8").encode("ascii", "ignore").decode("utf-8")
    if identifier in line:
      command = line.split(identifier)[-1].rstrip()
      command = command[command.find("#")+2:]
      commands = command.split("|")
      for com in commands:
        com = com.replace("\x08", "").replace("\x07", "").strip()
        command_list.append(com)
        for key in attacker_levels.keys():
          if key in com:
            level = max(level, attacker_levels.get(key))
  if len(command_list) == 0:
    level = 1

  num_commands = len(command_list)
  time_out = lines[-1].decode("utf-8").split(" ")[1][:-1][:-4]
  datetime_in = datetime.strptime(time_in, "%H:%M:%S")
  datetime_out = datetime.strptime(time_out, "%H:%M:%S")
  elapsed_timedelta = datetime_out - datetime_in
  duration_in_s = elapsed_timedelta.total_seconds()
  #minutes = divmod(duration_in_s, 60)[0]
  #elapsed_time = "{}".format(elapsed_timedelta.min)
  parsed_command_list = []
  for command in command_list:
    parsed_command_list.append(command.split(" ")[0])

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
  #str_parsed_list = "; ".join(parsed_command_list)

  execute = []
  first_half = ["log", "-k", "/root/Honeypot_Scripts/hacs.json", "-s"]
  execute.extend(first_half)
  if "101" in ctid:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=0")
  elif "102" in ctid:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=1766837841")
  elif "103" in ctid:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=221991272")
  elif "104" in ctid:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=747273361")
  execute.append("-d")

  last_half_list = [str(file_system), str(ip), str(date), str(time_in), str(time_out), str(duration_in_s), str(num_commands), str(level), str(str_list)]
  last_half = ",".join(last_half_list)
  execute.append(last_half)
  print(execute)
  subprocess.call(execute)

  
  #channel = "#2c_attackers"
  #slack_client = SlackClient(token)
  message = ":rotating_light::rotating_light: Incoming Attacker :rotating_light::rotating_light:\n"
  message += "Attacker IP: " + str(ip) + "\n"
  message += "File System: " + str(file_system) + "\n"
  message += "Level: " + str(level) + "\n"
  message += "Date: " + str(date) + "\n"
  message += "Time in: " + str(time_in) + "\n"
  message += "Time out: " + str(time_out) + "\n"
  message += "Elapsed Time (sec): " + str(duration_in_s) + "\n"
  message += "Number of Commands: " + str(num_commands) + "\n"
  message += "Commands run: " + "\n".join(last_half_list)
  #slack_client.api_call("chat.postMessage", channel=channel, text=message, username="y'all been compromised")
  
  execute_mail = ["echo", "-e", message, "|", "mail", "-s", "Y'all been hacked", "tarya@terpmail.umd.edu"]
  subprocess.call(execute_mail)


  



  
