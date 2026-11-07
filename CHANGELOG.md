# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Updated _libomemo_ submodule to `0.8.2`.
  This publishes PEP nodes for devicelist and bundle items with ID `current`, as recommended in the XEP, likely fixing some compatibility bugs such as the own device disappearing from the devicelist seen by other clients.
- Relatedly, at login, the own devicelist is requested as the item `current` instead of the newest item, so lurch reads the same list as other clients.
- The vendored libomemo is rebuilt when its sources change.
- Exposed `lurch_util_axc_log_func()` in the `.h` file so its unit tests can properly access it, fixing a new compile error.
- Removed unused variable from `lurch_bundle_request_cb()`.
- Crash on receiving an encrypted message that is not of type `chat`, e.g. without a type at all.
- Silently not publishing the devicelist and bundle on servers that advertise PEP on the account's JID, like _Prosody_. ([#194](https://github.com/gkdr/lurch/issues/194))
- Publish with the `open` access model and the item ID `current`, so that users without a presence subscription can fetch the bundle.
- Request the devicelist when a conversation is opened, instead of relying on PEP notifications which need a presence subscription.
- Sending messages which were encrypted for no device at all, while displaying them as sent.
- Mistaking the devicelist of a JID that merely starts with the own JID for the own one.


## [0.7.0] - 2021-02-12
### Added
- This file.
- An API reachable through _libpurple_ signals. See `lurch_api.h` for details and usage.
- Testing setup using _cmocka_ and tests for new modules.
- CI setup running the tests in _appveyor_ and reporting coverage results to _codecov_.
- The possibility to dynamically link against the submodule libaries. ([#151](https://github.com/gkdr/lurch/pull/151)) (thanks, [@fortysixandtwo](https://github.com/fortysixandtwo)!)

### Changed
- A new `/command` handler using the API, replacing the old implementation. The commands are a bit different and some are new.
- Updated _libomemo_ submodule to 0.7.1. See the [changelog](https://github.com/gkdr/libomemo/blob/master/CHANGELOG.md) for details.
- Updated _axc_ submodule to 0.3.4. See the [changelog](https://github.com/gkdr/axc/blob/master/CHANGELOG.md) for details.

### Removed
- The `lurch_initialised` setting in the `accounts.xml`.

### Fixed
- Warnings are no longer displayed at level "error".
- Use constants instead of magic numbers for conversation type checks.
- Some forgotten module name parameters for libpurple logging functions.
- Report skipped messages in conversation window and not just the debug log. ([#150](https://github.com/gkdr/lurch/pull/150)) (thanks, [@agx](https://github.com/agx)!)
- Failing tests on certain platforms. ([#153](https://github.com/gkdr/lurch/pull/153)) (thanks, [@agx](https://github.com/agx)!)
- Format the DB filenames in the README as code so they're not rendered as `mailto:` links. ([#130](https://github.com/gkdr/lurch/pull/130)) (thanks, [@msiism](https://github.com/msiism)!)
- Some memory handling improvements. ([#160](https://github.com/gkdr/lurch/pull/160), [#161](https://github.com/gkdr/lurch/pull/161)) (thanks, [@root-hardenedvault](https://github.com/root-hardenedvault)!)

## [0.6.8] and below
Lost to git commit logs and GitHub releases page.
