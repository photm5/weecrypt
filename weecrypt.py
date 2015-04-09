#!/usr/bin/env python2

import weechat
import subprocess

weechat.register("weecrypt", "shak-mar", "0.1", "None",
                 "asymmetric encryption for weechat using gpg", "", "")

channel_whitelist = ["#yourchannel"]
in_stream = False
stream_buffer = ""


def my_nick(server_name):
    return weechat.info_get("irc_nick", server_name)


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


def encrypt(message, to_nick):
    p = subprocess.Popen(["base64", "-w", "0"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    encoded, _ = p.communicate(message.encode())
    encoded = encoded.decode().strip()
    return encoded


def decrypt(message):
    p = subprocess.Popen(["base64", "-d", "-w", "0"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    decoded, _ = p.communicate(message.encode())
    decoded = decoded.decode().strip()
    return decoded


def parse_message(irc_message, server=None):
    # parse the message
    message_dict = {"message": irc_message}
    if server:
        message_dict["server"] = server
    parsed = weechat.info_get_hashtable("irc_message_parse", message_dict)
    # remove the channel part from PRIVMSG arguments
    message = ":".join(parsed["arguments"].split(":")[1:])
    return(parsed, message)


def in_modifier(data, modifier, server_name, irc_message):
    global in_stream
    global stream_buffer

    parsed, message = parse_message(irc_message, server=server_name)

    if parsed["channel"] not in channel_whitelist:
        return irc_message

    def build_message(message):
        return ":%s PRIVMSG %s :%s" % \
               (parsed["host"], parsed["channel"], message)

    if message.startswith("crypt:"):
        in_stream = True
        stream_buffer = ""

    if in_stream:
        stream_buffer += message

    if in_stream and message.endswith(":crypt"):
        in_stream = False
        split = stream_buffer.split(":")
        l = len(split)
        for i in range(1, l - 2, 2):
            if split[i] == my_nick(server_name):
                return build_message(decrypt(split[i + 1]))

    if in_stream:
        return ""

    return build_message(message)

weechat.hook_modifier("irc_in2_privmsg", "in_modifier", "")


def out_modifier(data, modifier, server_name, irc_message):
    parsed, message = parse_message(irc_message, server=server_name)

    if parsed["channel"] not in channel_whitelist:
        return irc_message

    new_message = "crypt:"
    for nick in other_nicks(parsed["channel"], server_name):
        new_message += nick + ":" + encrypt(message, nick) + ":"

    def build_message(add_end=True):
        message = "PRIVMSG %s :%s" % (parsed["channel"], new_message)
        if add_end:
            message += "crypt"
        return message

    last_irc_message = build_message()
    send_irc_message = last_irc_message
    while len(last_irc_message) > 512:
        new_message = last_irc_message[512:]
        last_irc_message = build_message(False)
        send_irc_message += "\n" + last_irc_message
    return send_irc_message

weechat.hook_modifier("irc_out_privmsg", "out_modifier", "")
