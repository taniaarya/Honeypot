import sys
import gzip
from attacker_levels import attacker_levels
from datetime import datetime
import os
import subprocess
import slack
import time
import re

# $1 = session id
# $2 = file system - "yes" or "no"?
# $3 = ctid
# $4 = sttacker ip
# $5 = time_out

time.sleep(60)

# Stores command line arguments in variables
session = sys.argv[1]
file_system = sys.argv[2]
ctid = sys.argv[3]
ip = sys.argv[4]
time_out = sys.argv[5]

identifier = "@CT{}:".format(ctid)
date = ""
time_in = ""

command_list = []
level = 0

# checks if new command exists and researchers needs to be notified
mail_new_command = ""


# stores email to be sent
#EMAIL = os.getenv('HP_EMAIL')

# gets slack token
TOKEN = os.getenv('SLACK_TOKEN')
slack_client = slack.WebClient(token=TOKEN)

# filepath for MITM sessions (uses argument given)
filepath = "/root/MITM_data/sessions/{}.gz".format(session)

# unzips and opens session file
try:
  with gzip.open(filepath, "rt", encoding="utf-8") as file:
    line = file.readline()
    while line:
      #ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
      #line = ansi_escape.sub('', line)
      #line = line.replace("\x08", "").replace("\x07", "").strip()
      if "Date: " in line:
        # extracts date from 8th line in YYYY-MM-DD format
        date = line.split(" ")[1]
        # extracts time in 24 hr HH:MM:SS format (cuts off extraneous seconds)
        time_in = line.split(" ")[-1][:-5]

      elif "Attacker IP Address: " in line:
        mitm_ip = line.split("Attacker IP Address: ")[-1].rstrip()
        if ip != mitm_ip:
          ip = mitm_ip

      elif identifier in line and "Attacker Stream Below" not in line and "Attacker Keystrokes" not in line or "Noninteractive mode attacker command:" in line:
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        line = ansi_escape.sub('', line)
        line = line.replace("\x08", "").replace("\x07", "").strip() 
        print(line)
        if "Noninteractive mode attacker command:" in line:
          command = line.split("Noninteractive mode attacker command: ")[-1].rstrip()
        else:
          command = line.split(identifier)[-1].rstrip()
        # removes current directory and preceding characters from parsed command
        if("~#" in command):  
          command = command[command.find("#")+2:]
        elif ("~$" in command):
          command = command[command.find("$")+2:]
        
        # if the user used a pip to connect multiple commands, counts them as individual commands
        commands = command.split("|")

        for com in commands:
          # removes extraneous hex characters and adds to master list of commands
          # FIX
          #com = com.replace("\x08", "").replace("\x07", "").strip()
          command_list.append(com)
          # checks if command matches any commands in attacker levels dictionary
          found_key = False
          
          #loops through all commands in dictionary
          for key in attacker_levels.keys():
            if key in com:
              # sets level to the highest match
              level = max(level, attacker_levels.get(key))
              found_key = True
          # if the command run matches none of the commands in the dictionary, mails it to researchers
          if not found_key:
            mail_new_command += "{}\n\t".format(com)
      line = file.readline()

    # attacker is level 1 if no commands are run
    if len(command_list) == 0:
      level = 1

    print(command_list)

    # gets number of commands run
    num_commands = len(command_list)

    # converts string time to datetime object in order to calculate elapsed time
    datetime_in = datetime.strptime(time_in, "%H:%M:%S")
    datetime_out = datetime.strptime(time_out, "%H:%M:%S")
    elapsed_time = datetime_out - datetime_in
    # calculates elapsed time in seconds
    duration_in_s = elapsed_time.total_seconds()
    
    # creates string version of command list separated by " : "
    str_list = ' : '.join(command_list)

    # builds subprocess call to log data in Google Sheets API
    execute = []
    # adds directory for logging key
    first_half = ["log", "-k", "/root/Honeypot_Scripts/hacs.json", "-s"]
    execute.extend(first_half)
    
    # appends respective google sheet id
    if "101" in ctid:
      execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=0")
    elif "102" in ctid:
      execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=1766837841")
    elif "103" in ctid:
      execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=221991272")
    elif "104" in ctid:
      execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=747273361")
    
    execute.append("-d")
    
    # builds list of entries that will be uploaded to the sheet
    last_half_list = [str(ctid), str(file_system), str(ip), str(date), str(time_in), str(time_out), str(duration_in_s), str(num_commands), str(level), str(str_list), str(session)]
    # separates each entry by a comma
    last_half = ",".join(last_half_list)
    execute.append(last_half)
    
    # executes logging
    subprocess.call(execute)

    
    message = ":rotating_light::rotating_light: Y'all been compromised :rotating_light::rotating_light:\n"
    # forms email message 
    #message = ""
    message += "Container ID: " + str(ctid) + "\n"
    message += "Attacker IP: " + str(ip) + "\n"
    message += "File System: " + str(file_system) + "\n"
    message += "Level: " + str(level) + "\n"
    message += "Date: " + str(date) + "\n"
    message += "Time in: " + str(time_in) + "\n"
    message += "Time out: " + str(time_out) + "\n"
    message += "Elapsed Time (sec): " + str(duration_in_s) + "\n"
    message += "MITM Session ID: " + str(session) + "\n"
    message += "Number of Commands: " + str(num_commands) + "\n"
    message += "Commands run: \n\t" + "\n\t".join(command_list)
    #slack_client.api_call("chat.postMessage", channel=channel, text=message, username="y'all been compromised")
    try:
      response = slack_client.chat_postMessage(channel='#2c_attackers', text=message, username="Incoming Attacker")
    except:
      pass

    if mail_new_command != "":
      message = ":bookmark::bookmark: Y'all be slacking on that dictionary :bookmark::bookmark:\n"
      message += "New Commands Found: \n\t"
      message += mail_new_command + "\n\t"
      try:
        response = slack_client.chat_postMessage(channel='#2c_attackers', text=message, username="New Command Found")
      except:
        print(response)
        pass 
except EOFError:
  # attacker is level 1 if no commands are run
  if len(command_list) == 0:
    level = 1
  print(command_list)
  # gets number of commands run
  num_commands = len(command_list)
  
  # converts string time to datetime object in order to calculate elapsed time
  datetime_in = datetime.strptime(time_in, "%H:%M:%S")
  datetime_out = datetime.strptime(time_out, "%H:%M:%S")
  elapsed_time = datetime_out - datetime_in
  # calculates elapsed time in seconds
  duration_in_s = elapsed_time.total_seconds()
    
  # creates string version of command list separated by " : "
  str_list = ' : '.join(command_list)

  # builds subprocess call to log data in Google Sheets API
  execute = []
  # adds directory for logging key
  first_half = ["log", "-k", "/root/Honeypot_Scripts/hacs.json", "-s"]
  execute.extend(first_half)
    
  # appends respective google sheet id
  if "101" in ctid:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=0")
  elif "102" in ctid:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=1766837841")
  elif "103" in ctid:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=221991272")
  elif "104" in ctid:
    execute.append("https://docs.google.com/spreadsheets/d/1D4AcKhWjwQPbfSssV-UOeht6kDiC2DBKovljgUsMlss/edit#gid=747273361")
    
  execute.append("-d")
    
  # builds list of entries that will be uploaded to the sheet
  last_half_list = [str(ctid), str(file_system), str(ip), str(date), str(time_in), str(time_out), str(duration_in_s), str(num_commands), str(level), str(str_list), str(session)]
  # separates each entry by a comma
  last_half = ",".join(last_half_list)
  execute.append(last_half)
    
  # executes logging
  subprocess.call(execute)

    
  message = ":rotating_light::rotating_light: Y'all been compromised :rotating_light::rotating_light:\n"
  # forms email message 
  #message = ""
  message += "Container ID: " + str(ctid) + "\n"
  message += "Attacker IP: " + str(ip) + "\n"
  message += "File System: " + str(file_system) + "\n"
  message += "Level: " + str(level) + "\n"
  message += "Date: " + str(date) + "\n"
  message += "Time in: " + str(time_in) + "\n"
  message += "Time out: " + str(time_out) + "\n"
  message += "Elapsed Time (sec): " + str(duration_in_s) + "\n"
  message += "MITM Session ID: " + str(session) + "\n"
  message += "Number of Commands: " + str(num_commands) + "\n"
  message += "Commands run: \n\t" + "\n\t".join(command_list)
  #slack_client.api_call("chat.postMessage", channel=channel, text=message, username="y'all been compromised")
  try:
    response = slack_client.chat_postMessage(channel='#2c_attackers', text=message, username="Incoming Attacker")
  except:
    pass

  if mail_new_command != "":
    message = ":bookmark::bookmark: Y'all be slacking on that dictionary :bookmark::bookmark:\n"
    message += "New Commands Found: \n\t"
    message += mail_new_command + "\n\t"
    try:
      response = slack_client.chat_postMessage(channel='#2c_attackers', text=message, username="New Command Found")
    except:
      print(response)
      pass 
except Exception:
  try:
    session = sys.argv[1]
    file_system = sys.argv[2]
    ctid = sys.argv[3]
    ip = sys.argv[4]
    time_out = sys.argv[5]

    message = ":vertical_traffic_light::vertical_traffic_light: Big Oof :vertical_traffic_light::vertical_traffic_light:\n"
    message += "Container ID: " + str(ctid) + "\n"
    message += "Attacker IP: " + str(ip) + "\n"
    message += "File System: " + str(file_system) + "\n"
    message += "Time out: " + str(time_out) + "\n"
    message += "MITM Session ID: " + str(session) + "\n"
    response = slack_client.chat_postMessage(channel='#2c_attackers', text=message, username="MITM Data Not Collected")
  except:
    print(response)
    pass 
