/*
 * Test driver for src/app/strings.c (UI strings shared by the GTK and Cocoa apps):
 * table completeness (both languages, same placeholders, valid UTF-8), the "%s"
 * formatter, mnemonic stripping and the number formatting helpers.
 * Prints "OK <checks>" or the failures; exit status 1 on failure.
 */
#include <stdio.h>
#include <string.h>
#include "engine.h"
#include "strings.h"

static int fails, checks;

#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int count_ph(const char *s)
{
    int n = 0;
    for (; *s; s++) {
        if (s[0] == '%' && s[1] == 's') { n++; s++; }
        else if (s[0] == '%' && s[1] == '%') s++;
        else if (s[0] == '%') return -100;           /* any other conversion is a bug */
    }
    return n;
}

static int utf8_ok(const char *s)
{
    return gz_utf8_valid((const u8 *)s, strlen(s));
}

static void eq(const char *got, const char *want, const char *what)
{
    CHECK(!strcmp(got, want), "%s: got [%s] want [%s]", what, got, want);
}

int main(void)
{
    /* tables */
    for (int id = 0; id < STR__COUNT; id++) {
        gz_ui_set_korean(1);
        const char *ko = gz_ui_str(id);
        gz_ui_set_korean(0);
        const char *en = gz_ui_str(id);
        CHECK(ko && en && ko[0] && en[0], "id %d empty", id);
        CHECK(utf8_ok(ko) && utf8_ok(en), "id %d not UTF-8", id);
        CHECK(count_ph(ko) == count_ph(en) && count_ph(ko) >= 0, "id %d placeholders ko %d en %d [%s]", id,
              count_ph(ko), count_ph(en), en);
    }
    CHECK(!strcmp(gz_ui_str(-1), "") && !strcmp(gz_ui_str(STR__COUNT), ""), "out of range ids");
    gz_ui_set_korean(1);
    CHECK(gz_ui_korean() && !strcmp(gz_ui_str(STR_TB_EXTRACT), "풀기"), "korean table");
    gz_ui_set_korean(0);
    CHECK(!gz_ui_korean() && !strcmp(gz_ui_str(STR_TB_EXTRACT), "Extract"), "english table");

    /* locale detection */
    CHECK(gz_ui_locale_korean("ko_KR.UTF-8") && gz_ui_locale_korean("ko") && gz_ui_locale_korean("ko-KR") &&
          gz_ui_locale_korean("KO_kr"), "korean locales");
    CHECK(!gz_ui_locale_korean("kok_IN") && !gz_ui_locale_korean("en_US.UTF-8") && !gz_ui_locale_korean("C") &&
          !gz_ui_locale_korean(NULL) && !gz_ui_locale_korean(""), "other locales");

    /* error / note texts */
    for (int c = 0; c < GZ_E_COUNT; c++) CHECK(gz_ui_code_text(c)[0], "code %d", c);
    for (int c = GZ_N_FIRST; c < GZ_N_LAST; c++) CHECK(gz_ui_code_text(c)[0], "note %d", c);
    CHECK(gz_ui_code_text(9999) == gz_ui_code_text(GZ_E_IO), "unknown code");

    /* code pages, methods, levels */
    CHECK(gz_ui_ncodepages >= 8 && gz_ui_codepages[0].cp == 0, "codepage list");
    CHECK(gz_ui_cp_name(949) && !gz_ui_cp_name(12345), "cp names");
    eq(gz_ui_method_name(GZ_WM_LZMA2), "LZMA2", "method");
    CHECK(gz_ui_method_name(GZ_WM_COUNT)[0] == 0 && gz_ui_method_name(-3)[0] == 0, "bad method");
    CHECK(gz_ui_level_name(-1) == gz_ui_level_name(0) && gz_ui_level_name(42) == gz_ui_level_name(9), "levels clamp");

    /* formatter */
    char b[64];
    gz_ui_format(b, sizeof b, "%s files, %s%%", (const char *const[]){ "3", "50" }, 2);
    eq(b, "3 files, 50%", "format");
    gz_ui_format(b, sizeof b, "a%sb%sc", (const char *const[]){ "X" }, 1);
    eq(b, "aXbc", "missing arg");
    gz_ui_format(b, sizeof b, "%s", (const char *const[]){ NULL }, 1);
    eq(b, "", "null arg");
    char small[8];
    u32 n = gz_ui_format(small, sizeof small, "%s", (const char *const[]){ "가나다" }, 1);   /* 9 bytes */
    CHECK(n == 6 && !strcmp(small, "가나"), "utf-8 cut: %u [%s]", n, small);
    n = gz_ui_format(small, 1, "abc", NULL, 0);
    CHECK(n == 0 && small[0] == 0, "cap 1");
    gz_ui_set_korean(1);
    GZ_UI_FMT(b, sizeof b, STR_ST_SELECTED, "3", "1.5 MB");
    eq(b, "3개 선택 (1.5 MB)", "GZ_UI_FMT");
    gz_ui_set_korean(0);

    /* mnemonics */
    gz_ui_plain(b, sizeof b, "파일(_F)");
    eq(b, "파일", "plain ko");
    gz_ui_plain(b, sizeof b, "_File");
    eq(b, "File", "plain en");
    gz_ui_plain(b, sizeof b, "Extract _here");
    eq(b, "Extract here", "plain mid");
    gz_ui_plain(b, sizeof b, "a__b");
    eq(b, "a_b", "plain literal");

    /* numbers */
    static const struct { u64 v; const char *s; } sz[] = {
        { 0, "0 B" }, { 1023, "1023 B" }, { 1024, "1.00 KB" }, { 1536, "1.50 KB" }, { 10 * 1024 + 512, "10.5 KB" },
        { 1052000, "1.00 MB" }, { 1977614336ull, "1.84 GB" }, { 1ull << 40, "1.00 TB" }, { ~0ull, "16.0 EB" },
        { 999ull << 20, "999 MB" },
    };
    for (size_t i = 0; i < sizeof sz / sizeof *sz; i++) {
        gz_ui_fmt_size(b, sizeof b, sz[i].v);
        eq(b, sz[i].s, "size");
    }
    gz_ui_fmt_thousands(b, sizeof b, 1234567);
    eq(b, "1,234,567", "thousands");
    gz_ui_fmt_thousands(b, sizeof b, 999);
    eq(b, "999", "thousands small");
    gz_ui_fmt_thousands(b, sizeof b, ~0ull);
    eq(b, "18,446,744,073,709,551,615", "thousands max");
    gz_ui_fmt_kb(b, sizeof b, 0);
    eq(b, "0 KB", "kb 0");
    gz_ui_fmt_kb(b, sizeof b, 1);
    eq(b, "1 KB", "kb 1");
    gz_ui_fmt_kb(b, sizeof b, 2048 * 1024);
    eq(b, "2,048 KB", "kb");
    gz_ui_fmt_speed(b, sizeof b, 604ull << 20);
    eq(b, "604 MB/s", "speed");
    gz_ui_fmt_duration(b, sizeof b, 65);
    eq(b, "01:05", "duration");
    gz_ui_fmt_duration(b, sizeof b, 3723);
    eq(b, "1:02:03", "duration h");
    gz_ui_fmt_percent(b, sizeof b, 13, 100);
    eq(b, "13%", "percent");
    gz_ui_fmt_percent(b, sizeof b, 5, 0);
    eq(b, "", "percent 0");
    gz_ui_fmt_percent(b, sizeof b, ~0ull - 5, ~0ull - 1);
    CHECK(!strcmp(b, "99%") || !strcmp(b, "100%"), "percent huge [%s]", b);
    gz_ui_fmt_percent(b, sizeof b, 10, GZ_SIZE_UNKNOWN);
    eq(b, "", "percent unknown");
    gz_ui_fmt_percent(b, sizeof b, 5000, 1);
    eq(b, "999%", "percent cap");
    gz_ui_fmt_hex32(b, sizeof b, 0x2CC362F6u);
    eq(b, "2CC362F6", "hex");
    gz_ui_fmt_hex32(b, 4, 0x12345678u);
    eq(b, "123", "hex cut");

    if (fails) { printf("%d of %d checks failed\n", fails, checks); return 1; }
    printf("OK %d\n", checks);
    return 0;
}
