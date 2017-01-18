import os
import sys
import time
from slackclient import SlackClient
import sqlite3 as lite
import pythonwhois
import Automater
import tempfile
import re



# Database Shizzle.. Comment out if you dont' want to use DB

db = lite.connect('kompromat.db')
dbe = db.cursor()


# Uncomment if you want to use environment variables
#BOT_ID = os.environ.get("BOT_ID")
#TOKEN = os.environment.get("TOKEN")

# Specify your bot credz
BOT_ID='your bot id'
TOKEN='your bot token'

# constants
AT_BOT = "<@" + BOT_ID + ">"

# instantiate Slack & Twilio clients
slack_client = SlackClient(TOKEN)

def majikz(looksy):

    # Create the temp file because Automater needs to write to it

    fh = tempfile.NamedTemporaryFile(mode="w+")
    # This si what gets passed to Automater.. You can modify this if you want
    # -b is bot purty
    sys.argv = ["," "-b", "-o", fh.name, looksy]

    fh.seek(0)
    # Tell people the bot is working on it
    textpost("Running some majikz on " + looksy );

    # Run the goods on the value you passed
    Automater.main();
    data = fh.read()

    # Post it to the channel it was recieved in
    textpost(data);
    fh.close()

# Check if this is an IP address and return a result
def validip(ip):
    if re.match(r'^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$', ip):
        return True
    else:
        return False
# Make sure this is a valid hostname
def isvaliddomain(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

# Post the response to channel
def textpost(response):

    slack_client.api_call("chat.postMessage", channel=channel, text=response, as_user=True)

def handle_command(command, channel):
    """
        Receives commands directed at the bot and determines if they
        are valid commands. If so, then acts on the commands. If not,
        returns back what it needs for clarification.
    """

    if command == 'help':

        response = "Try out the command list"
        textpost(response);
    # If you don't want to use a DB you can comment this out
    if command == 'list':

        dbe.execute("SELECT * from commands")
        rows=dbe.fetchall()

        #response = rows
        for row in rows:
          textpost(row);

    if command.split()[0] == "domain":
        # Handle the hyperlink stuff that Slack sends
        if '<' in command:
            looksy = command.split()[1].split('|')[1][:-1]
        # Handle is it didn't auto hyper link it
        else:
            looksy = command.split()[1]
        # If the domain is bootleg tell me about it
        if isvaliddomain(looksy) == False:
            textpost("This is an invalid domain");
        # If everything is gravy send it to the channel
        else:
            majikz(looksy)

    if command.split()[0] == "hash":
        looksy = command.split()[1]

        # Run it and post it to channel
        majikz(looksy)

    if command.split()[0] == "ip":
        looksy = command.split()[1]

        if validip(looksy) == False:
            textpost("This is an invalid IP");
        else:
        # Run it and post it to channel
            majikz(looksy)

def parse_slack_output(slack_rtm_output):
    """
        The Slack Real Time Messaging API is an events firehose.
        this parsing function returns None unless a message is
        directed at the Bot, based on its ID.
    """
    output_list = slack_rtm_output
    if output_list and len(output_list) > 0:
        for output in output_list:
            if output and 'text' in output and AT_BOT in output['text']:
                # return text after the @ mention, whitespace removed
                return output['text'].split(AT_BOT)[1].strip().lower(), \
                       output['channel']
    return None, None


if __name__ == "__main__":
    READ_WEBSOCKET_DELAY = 1 # 1 second delay between reading from firehose
    if slack_client.rtm_connect():
        print("StarterBot connected and running!")
        while True:
            command, channel = parse_slack_output(slack_client.rtm_read())
            if command and channel:
                handle_command(command, channel)
            time.sleep(READ_WEBSOCKET_DELAY)
    else:
        print("Connection failed. Invalid Slack token or bot ID?")
