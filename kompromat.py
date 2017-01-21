import os
import sys
import time
from slackclient import SlackClient
import sqlite3 as lite
import Automater
import tempfile
import re
import logging
import validators
import urllib2
from urllib2 import URLError, HTTPError
import hashlib

# Setup logging
logging.basicConfig(filename='kompromat.log',level=logging.INFO)

# Database Shizzle.. Comment out if you dont' want to use DB

db = lite.connect('kompromat.db')
dbe = db.cursor()


# Uncomment if you want to use environment variables
#BOT_ID = os.environ.get("BOT_ID")
#TOKEN = os.environment.get("TOKEN")

# Specify your bot credz
BOT_ID='YOURBOTID'
TOKEN='YOURBOTTOKEN'

# constants
AT_BOT = "<@" + BOT_ID + ">"

# instantiate Slack & Twilio clients
slack_client = SlackClient(TOKEN)

def majikz(channel,looksy,dm,username):

    # Create the temp file because Automater needs to write to it

    fh = tempfile.NamedTemporaryFile(mode="w+")
    # This si what gets passed to Automater.. You can modify this if you want
    # -b is bot purty
    sys.argv = ["," "-b", "-o", fh.name, looksy]

    fh.seek(0)
    # Tell people the bot is working on it
    if dm == False:
        textpost(channel,"@%s Running some majikz on " % username + looksy );
    else:
        textpost(channel,"Running some majikz on " + looksy );

    # Run the goods on the value you passed
    Automater.main();
    data = fh.read()

    # Post it to the channel it was recieved in
    if dm == False:
        textpost(channel,"@%s" %username + data);
    else:
        textpost(channel,data);
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
def textpost(channel,response):

    slack_client.api_call("chat.postMessage", channel=channel, text=response, as_user=True)

# Look up user name from slack
def s_user_lookup(username):
    user_info = slack_client.api_call("users.info", user=username)
    if user_info:
        return user_info['user']['name']
    return None

def validate_url(url):
    result = validators.url(url)
    print result
    return result

def download_url(location):
    # Verify if its a url
    # Download the file
    try:
        url = location
        file_name = url.split('/')[-1]
        u = urllib2.urlopen(url)
        f = open("files/" + file_name, 'wb')
        meta = u.info()
        dsize = meta.getheaders("Content-Length")[0]
        if int(dsize) < 9999999:
            print "File is less than 10M Downloading"
            with f as local_file:
                local_file.write(u.read())
                local_file.close()
                hash = hashlib.md5()
                with open("files/" + file_name, 'rb') as sum:
                    for chunk in iter(lambda: sum.read(4096), b""):
                        hash.update(chunk)
                    print "File: %s Downloaded with Hash: %s" % (file_name, hash.hexdigest())
                    return file_name, hash.hexdigest()
        else:
            return False

    except HTTPError, e:
        print "HTTP Error:", e.code, location
    except URLError, e:
        print "URL Error:", e.reason, location
    return

def do_something(username,command,channel,dm):
    logging.info(username + " ran " + command)

    if command.split()[0] == "download":
        filedl = command.split()[1]
        if filedl.startswith('<') and filedl.endswith('>'):
            filedl = filedl[1:-1]
            if validate_url(filedl) == True:
                print filedl + " Came back good"
                file_name, hash = download_url(filedl)
                response = "File: %s Hash: %s download complete" % (file_name,hash)
                textpost(channel,response)

    if command == 'help':
        if dm == True:
            response = "Try out the command list"
        else:
            response = "@%s Try out the command list" % username
        textpost(channel,response);

    # If you don't want to use a DB you can comment this out
    if command == 'list':

            dbe.execute("SELECT * from commands")
            rows=dbe.fetchall()

            #response = rows
            for row in rows:
                textpost(channel,row);
    # Who runs barter town?
    if command.lower().startswith("who runs barter town"):
            textpost(channel,"https://aznbadger.files.wordpress.com/2010/10/master-blaster.jpg")

    # Domain lookup
    if command.split()[0] == "domain":
        # Handle the hyperlink stuff that Slack sends
        if '<' in command:
            looksy = command.split()[1].split('|')[1][:-1]
        # Handle is it didn't auto hyper link it
        else:
            looksy = command.split()[1]
        # If the domain is bootleg tell me about it
        if isvaliddomain(looksy) == False:
            textpost(channel,"This is an invalid domain");
        # If everything is gravy send it to the channel
        else:
            majikz(channel,looksy,dm,username)
    # Hash lookup
    if command.split()[0] == "hash":
        looksy = command.split()[1]

        # Run it and post it to channel
        majikz(channel,looksy,dm,username)

    # IP lookup
    if command.split()[0] == "ip":
        looksy = command.split()[1]
        if validip(looksy) == False:
            textpost(channel,"This is an invalid IP");
        else:
        # Run it and post it to channel
            majikz(channel,looksy,dm,username)

def parse_output(slack_rtm_output):
    slack_payload = slack_rtm_output
    if slack_payload and len(slack_payload) > 0:
        #print slack_payload
        for payload in slack_payload:

            # Handle slackbot
            if payload and 'username' in payload and 'slackbot' in payload['username']:
                return

            # Handle files
            if payload and 'channel' in payload and 'text' in payload and 'username' \
            in payload and 'subtype' in payload and 'file_share' in payload['subtype'] \
            and payload['channel'].startswith('D'):
                print "File Share"

            # Handle DMs
            if payload and 'channel' in payload and 'text' in payload and BOT_ID \
            not in payload['text'] and BOT_ID not in payload['user'] and payload['channel'].startswith('D'):
                logging.info("Recieved a DM from %s" % s_user_lookup(payload['user']))

                do_something(s_user_lookup(payload['user']),payload['text'],payload['channel'],True)

            # Handle Mentions
            if payload and 'text' in payload and AT_BOT in payload['text']:
                # return text after the @ mention, whitespace removed
                logging.info("Processing a mention from %s" % s_user_lookup(payload['user']))
                do_something(s_user_lookup(payload['user']),payload['text'].split(AT_BOT)[1].strip().lower(),payload['channel'],False)

    return

if __name__ == "__main__":
    READ_WEBSOCKET_DELAY = 1 # 1 second delay between reading from firehose
    if slack_client.rtm_connect():
        logging.info("StarterBot connected and running!")
        while True:

            parse_output(slack_client.rtm_read())

            time.sleep(READ_WEBSOCKET_DELAY)
    else:
        logging.info("Connection failed. Invalid Slack token or bot ID?")
