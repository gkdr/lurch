/*
 * Server-side state inspection for the lurch integration tests.
 *
 * Reads the Prosody container's PEP storage through non-interactive
 * `prosodyctl shell` commands, so phases can assert on what the server
 * actually stores instead of on lurch's local cache of it. The
 * container runtime and name come from the environment
 * (LURCH_TEST_RT, LURCH_TEST_CONTAINER), which run.sh sets.
 */

#include "test_harness.h"

#define DEVICELIST_NODE OMEMO_NS ".devicelist"

/* Runs one non-interactive `prosodyctl shell` command inside the test
 * container and returns its stdout (caller frees), or NULL if the
 * command can't be run or exits non-zero. Logs the command and its
 * output, so a failed server assertion can be diagnosed from the log
 * alone. */
static char *prosody_shell(const char *const *args) {
    const char *rt = getenv("LURCH_TEST_RT");
    const char *container = getenv("LURCH_TEST_CONTAINER");
    if (!rt || !container) {
        fprintf(stderr, "[server] LURCH_TEST_RT / LURCH_TEST_CONTAINER not set, "
                        "cannot inspect server state\n");
        return NULL;
    }

    GPtrArray *argv = g_ptr_array_new();
    g_ptr_array_add(argv, (gpointer) rt);
    g_ptr_array_add(argv, "exec");
    g_ptr_array_add(argv, (gpointer) container);
    g_ptr_array_add(argv, "prosodyctl");
    g_ptr_array_add(argv, "shell");
    for (int i = 0; args[i]; i++) {
        g_ptr_array_add(argv, (gpointer) args[i]);
    }
    g_ptr_array_add(argv, NULL);

    char *cmdline = g_strjoinv(" ", (char **) argv->pdata);
    fprintf(stderr, "[server] $ %s\n", cmdline);
    g_free(cmdline);

    char *out = NULL;
    char *err = NULL;
    int status = 0;
    GError *gerr = NULL;
    gboolean ok = g_spawn_sync(NULL, (char **) argv->pdata, NULL,
                               G_SPAWN_SEARCH_PATH, NULL, NULL,
                               &out, &err, &status, &gerr);
    g_ptr_array_free(argv, TRUE);

    if (!ok) {
        fprintf(stderr, "[server] spawn failed: %s\n", gerr->message);
        g_error_free(gerr);
        return NULL;
    }

    fprintf(stderr, "[server] %s%s", out ? out : "", err ? err : "");
    g_free(err);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[server] command failed (status %d)\n", status);
        g_free(out);
        return NULL;
    }
    return out;
}

/* Extracts every <device id='N'/> from a devicelist item's XML, in
 * document order. The shell's output decoration around the XML doesn't
 * matter because only the device elements are matched. */
static GList *parse_device_ids(const char *xml) {
    GList *ids = NULL;
    GRegex *re = g_regex_new("<device[^>]*\\sid=['\"](\\d+)['\"]", 0, 0, NULL);
    GMatchInfo *mi = NULL;

    g_regex_match(re, xml, 0, &mi);
    while (g_match_info_matches(mi)) {
        char *num = g_match_info_fetch(mi, 1);
        uint32_t *id = g_new(uint32_t, 1);
        *id = (uint32_t) g_ascii_strtoull(num, NULL, 10);
        ids = g_list_append(ids, id);
        g_free(num);
        g_match_info_next(mi, NULL);
    }

    g_match_info_free(mi);
    g_regex_unref(re);
    return ids;
}

/* Frees a single ServerItem; GDestroyNotify-shaped for g_list_free_full. */
static void server_item_free(gpointer data) {
    ServerItem *item = data;
    g_free(item->id);
    g_list_free_full(item->device_ids, g_free);
    g_free(item);
}

/* Frees a list returned by server_devicelist_items. */
void server_items_free(GList *items) {
    g_list_free_full(items, server_item_free);
}

/* Reads every item of bare_jid's devicelist node, as Prosody stores
 * them: `list_items` gives the item IDs (one per line), then
 * `get_item` fetches each one's XML. Returns 0 on success (a missing or
 * empty node yields an empty list), -1 if the server couldn't be
 * queried. */
int server_devicelist_items(const char *bare_jid, GList **items_out) {
    *items_out = NULL;

    const char *list_args[] = { "pubsub", "list_items", bare_jid, DEVICELIST_NODE, NULL };
    char *listing = prosody_shell(list_args);
    if (!listing) {
        return -1;
    }

    GList *items = NULL;
    char **lines = g_strsplit(listing, "\n", -1);
    for (int i = 0; lines[i]; i++) {
        char *line = g_strstrip(lines[i]);
        /* Non-interactive output is one bare item ID per line, then an
         * "OK: N items" summary; interactive mode prefixes "| ". */
        if (g_str_has_prefix(line, "|")) {
            line = g_strstrip(line + 1);
        }
        if (!*line || g_str_has_prefix(line, "OK:")) {
            continue;
        }
        char *item_id = line;

        const char *get_args[] = { "pubsub", "get_item", bare_jid, DEVICELIST_NODE, item_id, NULL };
        char *xml = prosody_shell(get_args);
        if (!xml) {
            g_strfreev(lines);
            g_free(listing);
            server_items_free(items);
            return -1;
        }

        ServerItem *item = g_new0(ServerItem, 1);
        item->id = g_strdup(item_id);
        item->device_ids = parse_device_ids(xml);
        items = g_list_append(items, item);
        g_free(xml);
    }

    g_strfreev(lines);
    g_free(listing);
    *items_out = items;
    return 0;
}

/* Formats a uint32_t* list as "a, b, c" for failure messages. */
static char *format_ids(GList *ids) {
    GString *s = g_string_new(NULL);
    for (GList *l = ids; l; l = l->next) {
        g_string_append_printf(s, "%s%u", s->len ? ", " : "", *(uint32_t *) l->data);
    }
    return g_string_free(s, FALSE);
}

/* Returns TRUE if `ids` (a uint32_t* list) contains `id`. */
static gboolean ids_contain(GList *ids, uint32_t id) {
    for (GList *l = ids; l; l = l->next) {
        if (*(uint32_t *) l->data == id) {
            return TRUE;
        }
    }
    return FALSE;
}

/* Asserts the server-side devicelist for bare_jid: exactly one item on
 * the node, with ID 'current', listing exactly the expected IDs. An
 * expected ID of 0 means
 * the caller couldn't find out the device's own ID, which counts as a
 * failure, not as "skip". */
void assert_server_devicelist(const char *name, const char *bare_jid,
                              const uint32_t *expected, int n) {
    char reason[512];

    for (int i = 0; i < n; i++) {
        if (expected[i] == 0) {
            test_fail(name, "own device ID unknown (not in lurch's own devicelist)");
            return;
        }
    }

    GList *items = NULL;
    if (server_devicelist_items(bare_jid, &items) != 0) {
        test_fail(name, "could not read devicelist from server");
        return;
    }

    guint n_items = g_list_length(items);
    if (n_items != 1) {
        GString *desc = g_string_new(NULL);
        for (GList *l = items; l; l = l->next) {
            ServerItem *item = l->data;
            char *ids = format_ids(item->device_ids);
            g_string_append_printf(desc, " [%s: %s]", item->id, ids);
            g_free(ids);
        }
        snprintf(reason, sizeof(reason), "node holds %u items, expected 1:%s",
                 n_items, desc->str);
        g_string_free(desc, TRUE);
        test_fail(name, reason);
        server_items_free(items);
        return;
    }

    ServerItem *item = items->data;
    /* XEP-0384 recommends the fixed item ID 'current', so that every
     * publish overwrites the previous list. */
    if (strcmp(item->id, "current") != 0) {
        char *ids = format_ids(item->device_ids);
        snprintf(reason, sizeof(reason), "item ID is '%s', expected 'current' (lists [%s])",
                 item->id, ids);
        g_free(ids);
        test_fail(name, reason);
        server_items_free(items);
        return;
    }

    gboolean match = (g_list_length(item->device_ids) == (guint) n);
    for (int i = 0; match && i < n; i++) {
        if (!ids_contain(item->device_ids, expected[i])) {
            match = FALSE;
        }
    }

    if (match) {
        test_pass(name);
    } else {
        char *got = format_ids(item->device_ids);
        GString *want = g_string_new(NULL);
        for (int i = 0; i < n; i++) {
            g_string_append_printf(want, "%s%u", i ? ", " : "", expected[i]);
        }
        snprintf(reason, sizeof(reason), "item %s lists [%s], expected [%s]",
                 item->id, got, want->str);
        g_free(got);
        g_string_free(want, TRUE);
        test_fail(name, reason);
    }

    server_items_free(items);
}
