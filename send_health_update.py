import sys

disk_space = sys.argv[1]

TOKEN = os.getenv('SLACK_TOKEN')
slack_client = slack.WebClient(token=TOKEN)

message = ":warning::warning: The Honeypot is SICK :warning::warning:\n"
message += "The disk space is at {}\n".format(disk_space)
response = slack_client.chat_postMessage(channel='#2c_attackers', text=message, username="Health Update")

