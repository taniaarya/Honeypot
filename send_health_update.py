import sys
import os
import slack

disk_space = sys.argv[1]
ram = sys.argv[2]

TOKEN = os.getenv('SLACK_TOKEN')
slack_client = slack.WebClient(token=TOKEN)

message = ":warning::warning: The Honeypot is SICK :warning::warning:\n"
message += "The disk space is at {}MB\n".format(disk_space)
message += "The RAM is at {}MB\n".format(ram)
response = slack_client.chat_postMessage(channel='#2c_attackers', text=message, username="Health Update")

