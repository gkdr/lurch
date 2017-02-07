# lurch
/lʊʁç/. In German, an Axolotl is a type of Lurch. This plugin brings Axolotl, by now renamed to double ratchet, to libpurple applications such as [Pidgin](https://www.pidgin.im/) by implementing [OMEMO](https://conversations.im/omemo/).

(Plus I thought the word sounds funny, especially when pronounced by a speaker of English.)

## Can it talk to other OMEMO clients?
__Yes__, it was (briefly) tested with:
* [Conversations](https://conversations.im/)
* [The gajim OMEMO plugin](https://dev.gajim.org/gajim/gajim-plugins/wikis/OmemoGajimPlugin)
* [Mancho's libpurple plugin](https://git.imp.fu-berlin.de/mancho/libpurple-omemo-plugin)

## Do encrypted group chats work?
Yes.

## Does it work in Finch?
Mostly, but I only tried it briefly.

It only uses libpurple functions, so if they are implemented in the client correctly, they should work.
That being said, indicating encrypted chats by setting the topic does not seem to work in Finch (maybe just because window titles are very short). The encryption itself does work though, which you can confirm by looking at the sent/received messages in the debug log.

## Installation
1. Install the (submodules') dependencies (`libpurple-dev`, `libmxml-dev`, `libsqlite3-dev`, `libgcrypt20-dev`)
1. `git clone https://github.com/gkdr/lurch/`
2. `cd lurch`
3. `git submodule update --init`
4. `make`
5. A final `make install` should copy the compiled plugin into your libpurple plugin dir.
6. The next time you start Pidgin (or another libpurple client), you should be able to activate it in the "Plugins" window.

## Usage
This plugin will set the window title to notify the user if encryption is enabled or not. If it is, it will generally not send plaintext messages. If a plaintext message is received in a chat that is supposed to be encrypted, the user will be warned.

For conversations with one other user, it is automatically activated if the other user is using OMEMO too. If you do not want this, you can blacklist the user by typing `/lurch blacklist add` in the conversation window.

In groupchats, encryption has to be turned on first by typing `/lurch enable`. This is a client-side setting, so every participant has to do this in order for it to work. Warning messages are displayed if it does not work for every user in the conference, hopefully helping to fix the issue.

The same restrictions as with other OMEMO applications apply though - each user has to have every other user in his buddy list, otherwise the information needed to build a session is not accessible. Thus, it is recommended to set it to members-only.
Additionally, the room has to be set to non-anonymous so that the full JID of every user is accessible - otherwise, the necessary information cannot be fetched.

More information on the available commands can be found by typing `/lurch help` in any conversation window.

## Caveats
libpurple does not have support for Carbons or MAM, both used to deliver functionality that the OMEMO protocol can do in theory, which is messages to multiple devices and catchup with messages that were sent while a device was offline.
It should not be hard to fix but should be rather done on libpurple's side. I'm looking into it.

Of course this plugin is _highly experimental_, so you should not trust your life on it.
