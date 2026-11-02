/*
 * tests/cases/app_mac.py: the macOS front end's own strings (src/mac/mstrings.h) are
 * complete in both languages, valid UTF-8, keep the same "%s" placeholders, use "…" in
 * menus, and the language switch works. Prints "ok N" or the problems.
 */
#include <stdio.h>
#include <string.h>
#include "../../src/mac/mstrings.h"

static int placeholders(const char *s)
{
    int n = 0;
    for (; *s; s++) {
        if (s[0] == '%' && s[1] == '%') { s++; continue; }
        if (s[0] == '%' && s[1] == 's') n++;
    }
    return n;
}

static int utf8_ok(const unsigned char *s)
{
    while (*s) {
        unsigned c = *s, n = c < 0x80 ? 0 : (c & 0xE0) == 0xC0 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : 9;
        if (n == 9 || (n == 1 && c < 0xC2)) return 0;
        s++;
        while (n--) {
            if ((*s & 0xC0) != 0x80) return 0;
            s++;
        }
    }
    return 1;
}

int main(void)
{
    int bad = 0;
    for (int id = 0; id < MS__COUNT; id++) {
        gz_ui_set_korean(1);
        const char *ko = gz_ms(id);
        gz_ui_set_korean(0);
        const char *en = gz_ms(id);
        if (!ko[0] || !en[0]) { printf("empty string %d\n", id); bad++; }
        if (!utf8_ok((const unsigned char *)ko) || !utf8_ok((const unsigned char *)en)) {
            printf("bad UTF-8 %d\n", id);
            bad++;
        }
        if (placeholders(ko) != placeholders(en)) { printf("placeholders differ %d\n", id); bad++; }
        if (id != MS_USAGE && (strstr(ko, "...") || strstr(en, "..."))) {
            printf("menu text with \"...\" instead of an ellipsis %d: %s\n", id, en);
            bad++;
        }
        if (strchr(ko, '_') || strchr(en, '_')) { printf("mnemonic marker in %d\n", id); bad++; }
    }
    gz_ui_set_korean(1);
    if (strcmp(gz_ms(MS_QUIT), "고깃ZIP 종료") || strcmp(gz_ms(MS__COUNT), "") || strcmp(gz_ms(-1), "")) {
        printf("Korean lookup / bounds\n");
        bad++;
    }
    gz_ui_set_korean(0);
    if (strcmp(gz_ms(MS_QUIT), "Quit GogitZIP")) { printf("English lookup\n"); bad++; }
    /* the usage text names every command line mode main.m parses */
    static const char *const modes[] = { "--extract-here", "--extract-smart", "--extract-to", "--extract ", "--test",
                                         "--compress", "--output", "--format", "--level", "--yes", "--lang" };
    for (int k = 0; k < 2; k++) {
        gz_ui_set_korean(k);
        for (size_t i = 0; i < sizeof modes / sizeof modes[0]; i++)
            if (!strstr(gz_ms(MS_USAGE), modes[i])) { printf("usage lacks %s\n", modes[i]); bad++; }
    }
    if (bad) return 1;
    printf("ok %d\n", (int)MS__COUNT);
    return 0;
}
