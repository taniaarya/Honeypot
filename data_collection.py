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
file_system = sys.argv[2]

# stores email to be sent
EMAIL = os.getenv('HP_EMAIL')

# gets slack token
TOKEN = os.getenv('SLACK_TOKEN')
slack_client = slack.WebClient(token=TOKEN)

# filepath for MITM sessions (uses argument given)
filepath = "/root/MITM_data/sessions/{}.gz".format(session)

# unsips and opens session file
with gzip.open(filepath, "rt", encoding="utf-8") as file:
  lines = file.readlines()
  # takes third line of mitm file with container ID, removes whitespaces, and extracts ctid
  ctid = lines[2].rstrip().split("Container ID: ")[-1]
  identifier = "root@CT{}:".format(ctid)
  
  # extracts attacker ip address from 4th line of mitm file
  ip = lines[3].split("Attacker IP Address: ")[-1].rstrip()
  
  # extracts date from 8th line in YYYY-MM-DD format
  date = lines[7].split(" ")[1]
  
  # extracts time in 24 hr HH:MM:SS format (cuts off extraneous seconds)
  time_in = lines[7].split(" ")[-1][:-5] 
  
  command_list = []
  level = 0

  # loops and process lines of file
  for line in lines:
    # we only want to process lines with the full output of the user's commands, not the keystrokes
    if identifier in line:
      # extracts command from line
      command = line.split(identifier)[-1].rstrip()
      # removes current directory and preceding characters from parsed command
      command = command[command.find("#")+2:]
      # if the user used a pip to connect multiple commands, counts them as individual commands
      commands = command.split("|")

      # checks if new command exists and researchers needs to be notified
      mail_new_command = ""

      for com in commands:
        # removes extraneous hex characters and adds to master list of commands
        # FIX
        com = com.replace("\x08", "").replace("\x07", "").strip()
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
          mail_new_command += "{}\n".format(com)

      # sets up new command mailing
      if mail_new_command != "":
        response = slack_client.chat_postMessage(channel='#2c_attackers', text=mail_new_command, username="New Command Found")
        '''
        execute_new_mail = ["echo", "-e", mail_new_command, "|", "mail", "-s", "New Command Found", EMAIL]
        subprocess.call(execute_new_mail)
        '''
  
  # attacker is level 1 if no commands are run
  if len(command_list) == 0:
    level = 1

  # gets number of commands run
  num_commands = len(command_list)

  # extracts time out from last line of file 
  time_out = lines[-1].split(" ")[1][:-1][:-4]

  # converts string time to datetime object in order to calculate elapsed time
  datetime_in = datetime.strptime(time_in, "%H:%M:%S")
  datetime_out = datetime.strptime(time_out, "%H:%M:%S")
  elapsed_time = datetime_out - datetime_in
  # calculates elapsed time in seconds
  duration_in_s = elapsed_time.total_seconds()
  
  '''
  # rough parsing of individual commands run
  parsed_command_list = []
  for command in command_list:
    parsed_command_list.append(command.split(" ")[0])
  '''

  '''
  # print statements for debugging
  print("CTID: {}".format(ctid))
  print("IP: {}".format(ip))
  print("Date: {}".format(date))
  print("Time in: {}".format(time_in))
  print("Time out: {}".format(time_out))
  print("Elapsed time (min): {}".format(duration_in_s))
  print("Num commands: {}".format(num_commands))
  print("Level: {}".format(level))
  print("Commands run: {}".format(command_list))
  '''
  
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
  last_half_list = [str(file_system), str(ip), str(date), str(time_in), str(time_out), str(duration_in_s), str(num_commands), str(level), str(str_list)]
  # separates each entry by a comma
  last_half = ",".join(last_half_list)
  execute.append(last_half)
  
  # executes logging
  subprocess.call(execute)

  
  message = ":rotating_light::rotating_light: Incoming Attacker :rotating_light::rotating_light:\n"
  # forms email message 
  #message = ""
  message += "Conatiner ID: " + str(ctid) + "\n"
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
  response = slack_client.chat_postMessage(channel='#2c_attackers', text=message, username="Y'all been compromised")
  
  '''
  # sets up command to send email
  execute_mail = ["echo", "-e", message, "|", "mail", "-s", "Y'all been hacked", EMAIL]
  # sends email
  subprocess.call(execute_mail)
  '''


  



  
