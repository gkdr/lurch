# lurch
/lʊʁç/. In German, an Axolotl is a type of Lurch. This plugin brings Axolotl, by now renamed to double ratchet, to libpurple applications such as [Pidgin](https://www.pidgin.im/) by implementing [OMEMO](https://conversations.im/omemo/).

(Plus I thought the word sounds funny, especially when pronounced by a speaker of English.)

## Installation
### Linux (and MacOS?)
1. Install the (submodules') dependencies (`libpurple-dev`, `libmxml-dev`, `libxml2-dev`, `libsqlite3-dev`, `libgcrypt20-dev`)
1. `git clone https://github.com/gkdr/lurch/`
2. `cd lurch`
3. `git submodule update --init` (If you just pull a newer version, remember to also update the submodules as they might have changed!)
4. `make`
5. A final `make install` should copy the compiled plugin into your libpurple plugin dir.
6. The next time you start Pidgin (or another libpurple client), you should be able to activate it in the "Plugins" window.

### Windows
Thanks to EionRobb, Windows users can use the dlls he compiled and provides here: https://eion.robbmob.com/lurch/

### More
The current version of libpurple does not come with [Message Carbons](https://xmpp.org/extensions/xep-0280.html) support, i.e. if you have multiple devices, your Pidgin might not receive that message, and if you write messages on other devices, you do not see them either.

Lucky for you, I wrote another plugin to fix this! You can find it here: https://github.com/gkdr/carbons
Be aware that both are really experimental and might not work well, especially not together.

## Usage
This plugin will set the window title to notify the user if encryption is enabled or not. If it is, it will generally not send plaintext messages. If a plaintext message is received in a chat that is supposed to be encrypted, the user will be warned.

For conversations with one other user, it is automatically activated if the other user is using OMEMO too. If you do not want this, you can blacklist the user by typing `/lurch blacklist add` in the conversation window.

In groupchats, encryption has to be turned on first by typing `/lurch enable`. This is a client-side setting, so every participant has to do this in order for it to work. Warning messages are displayed if it does not work for every user in the conference, hopefully helping to fix the issue.

The same restrictions as with other OMEMO applications apply though - each user has to have every other user in his buddy list, otherwise the information needed to build a session is not accessible. Thus, it is recommended to set it to members-only.
Additionally, the room has to be set to non-anonymous so that the full JID of every user is accessible - otherwise, the necessary information cannot be fetched.

More information on the available commands can be found by typing `/lurch help` in any conversation window.

## Answers
### Can it talk to other OMEMO clients?
__Yes__, it was (briefly) tested with:
* [Conversations](https://conversations.im/)
* [The gajim OMEMO plugin](https://dev.gajim.org/gajim/gajim-plugins/wikis/OmemoGajimPlugin)
* [Mancho's libpurple plugin](https://git.imp.fu-berlin.de/mancho/libpurple-omemo-plugin)

### Do encrypted group chats work?
Yes.

### Does it work in Finch?
Mostly, but I only tried it briefly.

It only uses libpurple functions, so if they are implemented in the client correctly, they should work.
That being said, indicating encrypted chats by setting the topic does not seem to work in Finch (maybe just because window titles are very short). The encryption itself does work though, which you can confirm by looking at the sent/received messages in the debug log.

## Caveats
If you don't install the additional plugin mentioned above, this is probably not the right thing to use if you have multiple clients running at the same time, as there is no message carbons support in libpurple as of now.
MAM for "catchup" and offline messages is also not supported by libpurple.

Again: This plugin is _highly experimental_, so you should not trust your life on it.
