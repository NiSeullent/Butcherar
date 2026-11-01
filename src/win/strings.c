/*
 * 고깃ZIP - string tables
 */
#include "app.h"

#define GZ_SX_KO(id, ko, en) ko,
#define GZ_SX_EN(id, ko, en) en,
static const wchar_t *const s_ko[S__COUNT] = { GZ_STRINGS(GZ_SX_KO) };
static const wchar_t *const s_en[S__COUNT] = { GZ_STRINGS(GZ_SX_EN) };

const wchar_t *const *g_str = s_ko;

void strings_init(int korean) { g_str = korean ? s_ko : s_en; }
int strings_korean(void) { return g_str == s_ko; }
