# weecrypt

#### asymmetric encryption for weechat using gpg

weecrypt is a plugin for the [weechat IRC client](https://weechat.org/) that
encrypts your communication via [GPG](https://www.gnupg.org/).

Table of contents
-----------------
- [Installation](#installation)
- [Setting it up](#setting-it-up)
- [Messages that are not encrypted](#messages-that-are-not-encrypted)
- [Known Issues](#known-issues)

## Installation
To install it, run these commands in your shell:
```bash
git clone https://github.com/shak-mar/weecrypt.git
mkdir -p ~/.weechat/python/autoload/
cd ~/.weechat/python/autoload/
ln -s ~/weecrypt/weecrypt.py weecrypt.py
```

If your weechat is already running, you'll have reload your python plugins:
```
/python reload
```

## Setting it up
**Note**: This guide assumes you already have a working GPG setup. If you
dont't, you'll have to [set it up][gpg_guide] first.

After installing `weecrypt` there is a little bit of configuration that needs
to be done. The configuration is read from a JSON-encoded file at
`~/.weecrypt.json`:

```json
{
    "gpg_identifiers": {
        "irc_nick": "key identifier"
    },
    "channels": ["#yourchannel"]
}
```

### The `gpg_identifiers` option
`gpg_identifiers` is a dict mapping IRC nicknames to GPG key identifiers. A key
identifier is something unique to the key, such as an email, name or ID.

This is necessary because weecrypt needs to know who to encrypt your message
for. Conversly, only the people in the dictionary will receive encrypted
messages.

**Note:** It might be a good idea to put variations of the nicknames, such as
`nickname1` or `nickname_`, in there as well, as clients will use those when
reconnecting while having connection troubles.

### The `channels` option
Only traffic on whitelisted channels and private messages to nicknames in the
`gpg_identifiers` dict will be encrypted.

This is useful because you won't be able to convince all of your friends to use
encryption or you might want to use big public channels.

### Disabling logging in weechat
Unfortunately, because of the way `weecrypt` is implemented, the logger will
log all communications after they were decrypted, you therefore **have** to
disable logging at the very least for the channels and users in question.

weechat's logging options can be found under `~/.weechat/logger.conf`.

To simply disable all logging, modify the `auto_log` option:
```
auto_log = off
```

To disable loggin for a specific channel or user set its loglevel to zero.
For example:
```
[level]
irc.freenode.#yourchannel = 0
irc.freenode.yourfriend = 0
```

## Messages that are not encrypted

When you receive a message that is not encrypted in a whitelisted channel, it
will be prefixed with `<unencrypted>: `. If you want to write an unencrypted
message yourself, you can use the `/unencrypted` command.

**Note:** Also, if you write a message that starts with `<unencrypted>: `, it
will not be encrypted in order to avoid confusion between encrypted and raw
messages.

## Decryption failure

When you leave your computer running while you aren’t there, messages you
receive won’t be decrypted correctly, because you aren’t there to enter your
passphrase. In that case, the messages will be replaced with `Decryption failed,
try /weecrypt_retry.`. As soon as you use the `/weecrypt_retry` command, you
will be prompted for your passphrase by the gpg-agent again, and the decrypted
message will be displayed to you in the server buffer.

## Known Issues
### There is a delay between you sending and your friends receiving the message
This is because ASCII armored GPG messages are quite big and IRC commands are
limited in length. Therefore, `weecrypt` splits the message into smaller chunks
and reassembles them on the other end. In order to avoid flooding, weechat
waits a little between sending out commands. All this makes for a little slower
communication speed, but you'll have to tolerate that in order to chat
securely.

[gpg_guide]: http://www.dewinter.com/gnupg_howto/english/GPGMiniHowto.html
