# lurch
In German, an Axolotl is a type of Lurch. This plugin brings Axolotl, by now renamed to double ratchet, to libpurple applications such as [Pidgin](https://www.pidgin.im/) by implementing [OMEMO](https://conversations.im/omemo/).

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
That being said, indicating encrypted chats by setting the topic does not seem to work in Finch. The encryption itself does work though.

## Dependencies (aside from libpurple)
* [axc](https://github.com/gkdr/axc)
* [libomemo](https://github.com/gkdr/libomemo)

## Installation
1. Create a folder `lib`, and put the source code of the dependencies in there. You do not have to "install" the libs, the makefile in this project will call the right targets in their makefiles later on.
2. Install the used libs' dependencies (which boils down to SQLite, OpenSSL, Mini-XML, and the libaxolotl-c that comes with axc.).
3. In case you don't have it yet, install `libpurple-dev`.)
4. Type `make lurch` (or just `make`). This will compile the plugin, the two libs you just got, and link everything together into one file.
5. To easily copy it in your plugin dir, type `make install`.
6. The next time you start Pidgin (or a different libpurple client), you should be able to activate it in the "Plugins" window.

## Usage
This plugin will set the topic to notify the user if encryption is enabled or not. If it is, it will generally not send plaintext messages. If a plaintext message is received, the user will be warned.

For conversations with one other user, it is automatically activated if the other user is using lurch too. If you do not want this, you can blacklist the user by typing `/lurch blacklist add` in the conversation window.


In groupchats, encryption has to be turned on first by typing `/lurch enable`. This is a client-side setting, so every participant has to do this in order for it to work.

The same restrictions as with other OMEMO applications apply - each user has to have every other user in his buddy list, otherwise the information needed to build a session is not accessible. Thus, it is recommended to set it to members-only.
Additionally, the room has to be set to non-anonymous so that the full JID of every user is accessible.

More information can be found by typing `/lurch help` in any conversation window.

## Caveats
libpurple does not have support for Carbons or MAM, both used to deliver functionality that the OMEMO protocol can do in theory, which is messages to multiple devices and catchup with messages that were sent while a device was offline.
It should not be hard to fix but should be rather done on libpurple's side. I'm looking into it.

Of course this plugin is _highly experimental_, so you should not trust your life on it.
