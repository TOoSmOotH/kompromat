# import os
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
import requests
import json

# Load the configuration son

with open('config.json', 'r') as cfg:
    config = json.load(cfg)


# Setup logging

logging.basicConfig(filename=config["logFile"], level=config["logLevel"])


# Database Shizzle.. Comment out if you don't want to use DB

db = lite.connect(config["userDB"])
dbe = db.cursor()

# Uncomment if you want to use environment variables
# BOT_ID = os.environ.get("BOT_ID")
# TOKEN = os.environment.get("TOKEN")

# Specify your bot credz

BOT_ID = config["bot_id"]
TOKEN = config["bot_token"]

# Viper INFO
# VIPERSERVER = "http://192.168.2.157:8080"

# constants
AT_BOT = "<@" + BOT_ID + ">"

# instantiate Slack & Twilio clients
slack_client = SlackClient(TOKEN)

# Automater looks up stuff on the internets.


def auto_mater(channel, looksy, dm, username):

    # Create the temp file because Automater needs to write to it

    fh = tempfile.NamedTemporaryFile(mode="w+")

    # This is what gets passed to Automater.. You can modify this if you want
    # -b is bot purty

    sys.argv = ["," "-b", "-o", fh.name, looksy]

    fh.seek(0)

    # Tell people the bot is working on it

    if dm is False:
        text_post(channel, "@%s Running some Automater on " % username + looksy)

    else:
        text_post(channel, "Running some Automater on " + looksy)

    # Run the goods on the value you passed

    Automater.main()
    data = fh.read()

    # Post it to the channel it was received in
    
    if dm is False:
        text_post(channel, "@%s" % username + data)
    else:
        text_post(channel, data)

    fh.close()

# Validation Section.


def validate_url(url):
    result = validators.url(url)
    print result
    return result


def validate_ip(ip):
    result = validators.ipv4(ip)
    return result


def is_valid_domain(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


# Post text to a channel


def text_post(channel, response):

    slack_client.api_call("chat.postMessage", channel=channel, text=response, as_user=True)


# Look up user name from slack


def s_user_lookup(username):
    user_info = slack_client.api_call("users.info", user=username)
    if user_info:
        return user_info['user']['name']
    return None


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
                sha_hash = hashlib.sha256()
                with open("files/" + file_name, 'rb') as summary:
                    for chunk in iter(lambda: summary.read(4096), b""):
                        sha_hash.update(chunk)
                    print "File: %s Downloaded with Hash: %s. Try @bot viper search <hash>" \
                          % (file_name, sha_hash.hexdigest())
                    return file_name, sha_hash.hexdigest()
        else:
            return False

    except HTTPError, e:
        print "HTTP Error:", e.code, location
    except URLError, e:
        print "URL Error:", e.reason, location
    return


# def viper_stuff(task, hizash):
#    if task == "list_tags":
#        try:
#            url = VIPERSERVER + "/tags/list"
#            print url
#            u = urllib2.urlopen(url)
#            data = u.read()
#            return data
#
#        except HTTPError, e:
#            print "HTTP Error:", e.code
#        except URLError, e:
#            print "URL Error:", e.reason
#        return

#    if task == "list_projects":
#        try:
#            url = VIPERSERVER + "/projects/list"
#            print url
#            u = urllib2.urlopen(url)
#            data = u.read()
#            return data

#        except HTTPError, e:
#            print "HTTP Error:", e.code
#        except URLError, e:
#            print "URL Error:", e.reason
#        return

#    if task == "search":
#        viper_search(hash)


#def viper_upload(file_name):

#    r = requests.post(VIPERSERVER + "/file/add", data={'tags': 'huntingparty'},
#                      files={'file': open("files/" + file_name, 'rb')})
#    if 'message' and 'added' in r.text:
#        print "woot"
#        return "Success"
#    else:
#        print "something broke"
#        return "failsauce"


# def viper_search(search_value, term):
#    r = requests.post(VIPERSERVER + "/file/find", data={'project': 'all', term: search_value})
#
#    dizzy = r.json()

#    if dizzy.has_key("../"):
#        yield "junk"

#    else:
#        for project_name, result_list in dizzy.iteritems():
#            for result in result_list:
#                for field, value in result.iteritems():
#                    yield "##%s##:   %s" % (field, value)


#def viper_command(command, hash):
#    r = requests.post(VIPERSERVER + "/modules/run", data={'sha256': hash, 'cmdline': command})

    # dizzy = r.json()
#    dizzy = json.loads(r.json())
#    # print dizzy
#    print "dizzy: %r" % dizzy
#    print [type(h) is dict and h.get("type") for h in dizzy]
#    if "error" in [type(h) is dict and h.get("type") for h in dizzy]:
#        print "has type"
#    else:
#        print "good"


def do_something(username, command, channel, dm):
    logging.info(username + " ran " + command)

#    if command.split()[0] == "viper":
#        task = command.split()[1]
#        if task == "list_tags":
#            hizash = 0
#            viper_result = viper_stuff(task, hizash)
#            text_post(channel, viper_result)

#        if task == "list_projects":
#            hizash = 0
#            viper_result = viper_stuff(task, hizash)

#            text_post(channel, viper_result)

#        if task == "search":
#            term = command.split()[2]
#            hizash = command.split()[3]
#            print term
#            text_post(channel, "\n".join(list(viper_search(hizash, term))))

#        if task == "command":
#            m = re.compile(r'viper command ("[^"]+") ([a-f0-9]{32,})')
#            matches = m.findall(command)
#            cmd = matches[0][0].strip('"')
#            hizash = matches[0][1]
#            print viper_command(cmd, hizash)
             # text_post(channel, "\n".join(list(viper_command(cmd,hizash))))

    if command.split()[0] == "download":
        file_download = command.split()[1]
        if file_download.startswith('<') and file_download.endswith('>'):
            file_download = file_download[1:-1]
            if validate_url(file_download) is True:
                print file_download + " Came back good"
                file_name, file_hash = download_url(file_download)
                response = "File: %s SHA256 Hash: %s download complete. Doing some stuff to it." % (file_name, file_hash)
                text_post(channel, response)

#                searchy = list(viper_search(hash, "md5"))

#                if searchy[0] == "junk":
#                    print "We don't have this file yet"
#                    uppy = viper_upload(file_name)
#                    if uppy == "Success":
#                        print "File was added"
#                        text_post(channel, "\n".join(list(viper_search(hash, "sha256"))))
#                else:
#                    print "we have shit"

                # Check to see if it is in viper already
                # viper_search(hash)

    if command == 'help':
        if dm is True:
            response = "Try out the command list"
        else:
            response = "@%s Try out the command list" % username
        text_post(channel, response)

    # If you don't want to use a DB you can comment this out
    if command == 'list':

            dbe.execute("SELECT * from commands")
            rows = dbe.fetchall()

            # response = rows
            for row in rows:
                text_post(channel, row)

    # Who runs barter town?

    if command.lower().startswith("who runs barter town"):
            text_post(channel, "https://aznbadger.files.wordpress.com/2010/10/master-blaster.jpg")

    # Domain lookup
    if command.split()[0] == "domain":
        # Handle the hyperlink stuff that Slack sends
        if '<' in command:
            looksy = command.split()[1].split('|')[1][:-1]
        # Handle is it didn't auto hyper link it
        else:
            looksy = command.split()[1]
        # If the domain is bootleg tell me about it

        if is_valid_domain(looksy) is False:
            text_post(channel, "This is an invalid domain")
        # If everything is gravy send it to the channel
        else:
            auto_mater(channel, looksy, dm, username)
    # Hash lookup
    if command.split()[0] == "hash":
        looksy = command.split()[1]

        # Run it and post it to channel
        auto_mater(channel, looksy, dm, username)
        # text_post(channel, "Checking to see if we have it in Hunting Party ViperDB")
        # vsearch = viper_search(looksy,"md5")
        # text_post(channel,vsearch);
        # text_post(channel, "\n".join(list(viper_search(looksy, "md5"))))

    # IP lookup
    if command.split()[0] == "ip":
        looksy = command.split()[1]
        if validate_ip(looksy) is False:
            text_post(channel, "This is an invalid IP")
        else:
            # Run it and post it to channel
            auto_mater(channel, looksy, dm, username)


def parse_slack_output(slack_rtm_output):

    slack_payload = slack_rtm_output

    if slack_payload and len(slack_payload) > 0:
        # print slack_payload
        for payload in slack_payload:

            # Handle slackbot
            if payload and 'username' in payload and 'slackbot' in payload['username']:
                return

            # Handle files
            if payload and 'channel' in payload and 'text' in payload and 'username' in payload and 'subtype' \
                    in payload and 'file_share' in payload['subtype'] and payload['channel'].startswith('D'):
                print "File Share"

            # Handle DMs
            if payload and 'channel' in payload and 'text' in payload and BOT_ID \
                    not in payload['text'] and BOT_ID not in payload['user'] and payload['channel'].startswith('D'):

                logging.info("Received a DM from %s" % s_user_lookup(payload['user']))

                do_something(s_user_lookup(payload['user']), payload['text'], payload['channel'], True)

            # Handle Mentions
            if payload and 'text' in payload and AT_BOT in payload['text']:
                # return text after the @ mention, whitespace removed
                logging.info("Processing a mention from %s" % s_user_lookup(payload['user']))
                do_something(s_user_lookup(payload['user']), payload['text'].split(AT_BOT)[1].strip().lower(),
                             payload['channel'], False)

    return

if __name__ == "__main__":
    READ_WEBSOCKET_DELAY = 1  # 1 second delay between reading from fire hose
    if slack_client.rtm_connect():
        logging.info("StarterBot connected and running!")
        while True:

            parse_slack_output(slack_client.rtm_read())

            time.sleep(READ_WEBSOCKET_DELAY)
    else:
        logging.info("Connection failed. Invalid Slack token or bot ID?")
