#!/usr/bin/env python2

import weechat
import subprocess
from os import path
import json

weechat.register("weecrypt", "shak-mar", "0.1", "None",
                 "asymmetric encryption for weechat using gpg", "", "")

channel_whitelist = []
gpg_identifiers = {}
max_length = 300
buffers = {}
config_path = "~/.weecrypt.json"

# Load the configuration
if path.isfile(path.expanduser(config_path)):
    with open(path.expanduser(config_path)) as f:
        config = json.loads(f.read())
        channel_whitelist = config["channels"]
        gpg_identifiers = config["gpg_identifiers"]

else:
    weechat.prnt("",
                 "Error: Cant find configuration file at: %s." % config_path)


# Retrieve your own nick
def my_nick(server_name):
    return weechat.info_get("irc_nick", server_name)


# Returns all nicks in a channel, except your own
def other_nicks(channel_name, server_name):
    nicks = []
    infolist = weechat.infolist_get("irc_nick", "",
                                    server_name + "," + channel_name)
    rc = weechat.infolist_next(infolist)
    while rc:
        nick = weechat.infolist_string(infolist, "name")
        if nick != my_nick(server_name):
            nicks.append(nick)
        rc = weechat.infolist_next(infolist)

    return nicks


# Encrypt a message for all possible recipients
def encrypt(message, to_nicks):
    # Assemble the command
    command = ["gpg2", "--armor", "--encrypt"]
    for nick in to_nicks:
        if nick in gpg_identifiers:
            command.extend(["--recipient", gpg_identifiers[nick]])

    # Only encrypt if there are receipients
    if len(command) > 3:
        # Run the command and collect its output
        p = subprocess.Popen(command,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        encoded, _ = p.communicate(message.encode())
        encoded = encoded.decode().strip()
        return encoded
    return ""


# Decrypt a received message
def decrypt(message):
    p = subprocess.Popen(["gpg2", "--armor", "--decrypt"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    decoded, _ = p.communicate(message.encode())
    decoded = decoded.decode().strip()
    return decoded


# Parse an IRC message into a useable format
def parse_message(irc_message, server=None):
    # parse the message
    message_dict = {"message": irc_message}
    if server:
        message_dict["server"] = server
    parsed = weechat.info_get_hashtable("irc_message_parse", message_dict)
    # remove the channel part from PRIVMSG arguments
    message = ":".join(parsed["arguments"].split(":")[1:])
    return(parsed, message)


# Message qualifies for en- or decryption
def encryption_target(parsed, server_name):
    channel = parsed["channel"]
    return\
        channel in channel_whitelist or\
        channel in gpg_identifiers or\
        (channel == my_nick(server_name) and parsed["nick"] in gpg_identifiers)


# This method modifies how received IRC messages are displayed
def in_modifier(data, modifier, server_name, irc_message):
    global buffers

    parsed, message = parse_message(irc_message, server=server_name)
    buffer_id = "%s-%s-%s" % (parsed["nick"], parsed["channel"], server_name)

    # Continue only if it's an encryption target
    if not encryption_target(parsed, server_name):
        return irc_message

    def build_message(message):
        return ":%s PRIVMSG %s :%s" % \
               (parsed["host"], parsed["channel"], message)

    # Start buffering
    if message.startswith("crypt:"):
        buffers[buffer_id] = ""

    # Currently buffering
    if buffer_id in buffers:
        buffers[buffer_id] += message

        # Finished buffering: decrypt the message
        if message.endswith(":crypt"):

            # Turn the message into the original ASCII armor
            split = buffers[buffer_id].split(":")
            message = ":".join(split[1:-1])
            # Put the newlines back, as GPG needs them
            message = message.replace("\\n", "\n", -1)

            del buffers[buffer_id]

            return build_message(decrypt(message))

        # Don't print anything while buffering
        else:
            return ""

    return build_message("<unencrypted>: %s" % message)

weechat.hook_modifier("irc_in2_privmsg", "in_modifier", "")


# This method modifies how IRC messages are sent
def out_modifier(data, modifier, server_name, irc_message):
    def build_message(message):
        return "PRIVMSG %s :%s" % (parsed["channel"], message)

    parsed, message = parse_message(irc_message, server=server_name)

    # Don't encrypt messages from unencrypted_cmd
    if message.startswith("<unencrypted>: "):
        return build_message(message[15:])

    # Continue only if it's an encryption target
    if not encryption_target(parsed, server_name):
        return irc_message

    new_message = ""
    # Message sent over a channel
    if parsed["channel"].startswith("#"):
        receipients = other_nicks(parsed["channel"], server_name)
        new_message = "crypt:%s:crypt" % encrypt(message, receipients)

    # Private message
    else:
        new_message = "crypt:%s:crypt" % encrypt(message, [parsed["channel"]])

    # Encode the newlines, as they are not allowed by the IRC protocol
    new_message = new_message.replace("\n", "\\n", -1)

    # The message has to be split into multiple messages, as ASCII armors
    # are longer than the longest legal IRC message
    messages = []

    chunks = len(new_message) / max_length
    if len(new_message) % max_length != 0:
        chunks += 1

    for i in range(chunks):
        chunk = new_message[max_length * i:max_length * (i + 1)]
        messages.append(build_message(chunk))

    return "\n".join(messages)

weechat.hook_modifier("irc_out_privmsg", "out_modifier", "")


# Send an unencrypted message
def unencrypted_cmd(data, buffer, args):
    weechat.command(buffer, "<unencrypted>: %s" % "".join(args))
    return weechat.WEECHAT_RC_OK

weechat.hook_command("unencrypted", "sends an unencrypted message",
                     "<message>", "message: message to be sent",
                     "", "unencrypted_cmd", "")
