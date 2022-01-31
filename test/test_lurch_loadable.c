// Copyright (c) 2022 Sebastian Pipping <sebastian@pipping.org>
// Licensed under the GPL v2 or later

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <gmodule.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("usage: %s PATH/TO/MODULE.(dll|so) [..]\n", argv[0]);
    return 1;
  }

  bool success = true;
  size_t i = 1;
  for (; i < argc; i++) {
    const char *const filename = argv[i];
    // NOTE: g_module_open does not like opening plain "lurch.(so|dll)":
    //       it needs a path.  So we turn potentially relative filenames
    //       into full absolute ones to avoid unncessary (and misleading)
    //       error "No such file or directory" and to make it work regardless.
    gchar *const absolute_filename = g_canonicalize_filename(filename, NULL);
    if (!absolute_filename) {
      printf("[-] Could not canonicalize "
             "filename %s due to error: %s (code %d)\n",
             filename, strerror(errno), errno);
      success = false;
      continue;
    }

    printf("[*] Opening module %s...\n", filename);
    GModule *const module =
        g_module_open(absolute_filename, G_MODULE_BIND_LOCAL);
    g_free(absolute_filename);
    if (!module) {
      success = false;
      const gchar *const error_details = g_module_error();
      printf("[-] Opening module %s has FAILED: %s\n", filename,
             (char *)error_details);
      continue;
    }
    printf("[+] Opened module %s successfully.\n", filename);

    const gchar *const symbol_name = "purple_init_plugin";
    gpointer dummy;
    printf("[*]   Checking module %s for symbol %s...\n", filename,
           (char *)symbol_name);
    if (g_module_symbol(module, symbol_name, &dummy)) {
      printf("[+]   Symbol %s found.\n", symbol_name);
    } else {
      printf("[-]   Symbol %s NOT found.\n", symbol_name);
      success = false;
    }

    printf("[*] Closing module %s...\n", filename);
    g_module_close(module);
    printf("[+] Closed module %s.\n", filename);
  }

  if (success) {
    printf("[+] Good.\n");
  } else {
    printf("[-] BAD.\n");
  }

  return success ? 0 : 1;
}
