# lurch 0.6.5
/lʊʁç/. In German, an Axolotl is a type of Lurch, which simply means 'amphibian'. This plugin brings Axolotl, by now renamed to double ratchet, to libpurple applications such as [Pidgin](https://www.pidgin.im/) by implementing [OMEMO](https://conversations.im/omemo/).

(Plus I thought the word sounds funny, especially when pronounced by a speaker of English.)

## News
0.6.5 is out and you should get it as it contains important security updates.

If you use any text-formatting, through XHTML-IM a whole plaintext copy of your text was sent along with the ciphertext, which is obviously bad.
The `<html>` tags and any additional `<body>` tags are now stripped from the message.

Also, the tag is now appended to the key, i.e. is part of the data which is encrypted with the double ratchet session.

## Installation
### Linux (Arch package)

``` bash
sudo pacman -S base-devel git pidgin libpurple mxml sqlite libxml2 libgcrypt
git clone https://aur.archlinux.org/libpurple-lurch-git.git
cd libpurple-lurch-git
makepkg
sudo pacman -U *.xz
```

### Linux
First, install the (submodules') dependencies (`libpurple-dev`, `libmxml-dev`, `libxml2-dev`, `libsqlite3-dev`, `libgcrypt20-dev`).

Unfortunately, _Debian Stable_ comes with an older version of _mxml_ (2.6).
See issues #30 and #35 on some hints how to get a newer version from the _Testing_ repositories (2.7 is required).

For some hints on how to get the required libraries on macOS, see issue #8.

On Arch/Parabola you can install the following packages:

``` bash
sudo pacman -S base-devel git pidgin libpurple mxml sqlite libxml2 libgcrypt
```

Then, get the source code, including all submodules and their submodules:

``` bash
git clone https://github.com/gkdr/lurch/
cd lurch
git submodule update --init --recursive
```

If you just pull a newer version, remember to also update the submodules as they might have changed!

Then build and install with:

``` bash
make
make install-home
```

Which copies the compiled plugin into your local libpurple plugin directory.

The next time you start Pidgin, or another libpurple client, you should be able to activate it in the "Plugins" window.

## MacOS variations

Install dependencies using Homebrew.

```
brew install glib libxml2 libmxml sqlite libgcrypt hg
```

Get a copy of the libpurple soure (from Pidgin), and prepare it so we can use it
during the build.

```
hg clone https://bitbucket.org/pidgin/main pidgin
cd pidgin
hg checkout v2.10.12
./configure $(./configure --help | grep -i -- --disable | awk '{ print $1 }')
```

```
make LIBPURPLE_CFLAGS=-I${PWD}/pidgin/libpurple LIBPURPLE_LDFLAGS=/Applications/Adium.app/Contents/Frameworks/libpurple.framework/libpurple LJABBER=
```

### Windows
Thanks to EionRobb, Windows users can use the dlls he compiled and provides here: https://eion.robbmob.com/lurch/

1. Download the plugin .dll itself and put it in the `Program Files\Pidgin\plugins` directory. If you want to talk to other OMEMO clients, use _lurch-compat.dll_.
2. Download _libgcrypt-20.dll_ and _libgpg-error-0.dll_ and put them in the `Program Files\Pidgin` directory.

These instructions can also be found at the provided link.

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

It is __recommended__ you confirm the fingerprints look the same on each device, including among your own.To do this, you can e.g. display all fingerprints participating in a conversation using `/lurch show fp conv`.

More information on the available commands can be found by typing `/lurch help` in any conversation window.

## It doesn't work!
If something does not work as expected, don't hesitate to open an issue.
You can also reach me on the Pidgin IRC channel (#pidgin on freenode) as `_riba`, or send me an email.

It will usually be helpful (i.e. I will probably ask for it anyway) if you provide me with some information from the debug log, which you can find at _Help->Debug Window_ in Pidgin.

In case it is more serious and Pidgin crashes, I will have to ask you for a backtrace.
You can obtain it in the following way:
* Open Pidgin in gdb: `gdb pidgin`
* Run it: `run`
* Do whatever you were doing to make it crash
* When it does crash, type `bt` (or `backtrace`)
* Copy the whole thing

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
