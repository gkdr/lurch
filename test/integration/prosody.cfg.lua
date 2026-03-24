-- Prosody 13.x config for lurch integration tests
-- Minimal setup: localhost vhost, no TLS, PEP enabled

admins = {}
daemonize = false
plugin_paths = { "/etc/prosody/modules" }

modules_enabled = {
    "disco";
    "roster";
    "saslauth";
    "caps";
    "pep";
    "pep_server_disco";
    "carbons";
    "ping";
    "admin_shell";
}

modules_disabled = {
    "tls";
    "s2s";
    "limits";
}

c2s_require_encryption = false
s2s_secure_auth = false
allow_registration = false
authentication = "internal_hashed"
storage = "internal"

log = {
    debug = "*console";
}

pep_max_items = 10000

VirtualHost "localhost"
