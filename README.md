# lurch
In German, an Axolotl is a type of Lurch. This plugin brings Axolotl, by now renamed to double ratchet, to libpurple applications such as [Pidgin](https://www.pidgin.im/) by implementing [OMEMO](https://conversations.im/omemo/).

(Plus I thought the word sounds funny, especially when pronounced by a speaker of English.)

## Dependencies (aside from libpurple)
* [axc](https://github.com/gkdr/axc)
* [libomemo](https://github.com/gkdr/libomemo)

## Installation
1. Create a folder `lib`, and put the source code of the dependencies in there.
2. Install the used libs' dependencies.
3. [Get the Pidgin source code](https://www.pidgin.im/download/) and put it in the root directory of this repository, same as the makefile. (The plugin was developed with 2.11.0, and that is also what the makefile uses as folder name. If yours is different, you will need to adopt it.)
4. Copy the only sourcefile `lurch.c` into `pidgin-x.y.z/libpurple/plugins`.
5. Type `make lurch`. This will compile the plugin and put it in your `~/.purple/` directory.
6. Done. The next time you start Pidgin (or a different libpurple client), you should be able to activate it in the "Plugins" window.

## Usage
This plugin will set the topic to notify the user if encryption is enabled or not. If it is, it will generally not send plaintext messages. If a plaintext message is received, the user will be warned.

For conversations with one other user, it is automatically activated if the other user is using lurch too. If you do not want this, you can blacklist the user by typing `/lurch blacklist add` in the conversation window.


In groupchats, encryption has to be turned on first by typing `/lurch enable`. This is a client-side setting, so every participant has to do this in order for it to work.

The same restrictions as with other OMEMO applications apply - each user has to have every other user in his buddy list, otherwise the information needed to build a session is not accessible. Thus, it is recommended to set it to members-only.
Additionally, the room has to be set to non-anonymous so that the full JID of every user is accessible.

More information can be found by typing `/lurch help` in any conversation window.

## Caveats
[OMEMO's now official XEP](https://xmpp.org/extensions/xep-0384.html) changed the used double ratchet implementation from Axolotl to Olm (which is also an amphibian, we are all very creative with names it seems). I noticed this way too late and am still using libaxolotl. No, not even Signal - I did not update the dependency in axc for reasons outlined in its own readme.

For this reason, lurch uses its own namespace and is not interoperable with any other OMEMO applications at this moment.
If there is enough interest, I will fix this at some point.
