-- Advertise PEP identity at the server level (host-disco-info).
-- Prosody's mod_pep advertises it only on account-level disco, but
-- libpurple 2.x discovers PEP by checking the server domain's disco#info.
module:add_identity("pubsub", "pep", module.host);
