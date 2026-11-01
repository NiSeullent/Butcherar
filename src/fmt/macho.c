/*
 * 고깃ZIP - Mach-O binaries (32/64-bit, either byte order) and universal ("fat")
 * binaries
 *
 * Universal binaries list one entry per architecture, named like lipo does
 * ("x86_64", "arm64", "arm64e", "i386", "armv7", "ppc" ...); each entry is a thin
 * Mach-O file that opens in place (view), as 7-Zip's Mub handler. FAT_MAGIC_64
 * headers are understood. 0xCAFEBABE is shared with Java class files: a fat
 * header must have 1..32 architectures (class files carry a major version >= 45
 * there) whose slices lie inside the file and start with a Mach-O magic.
 *
 * Thin binaries list their sections as "<segment>/<section>" ("__TEXT/__text";
 * zero-fill sections are empty), segments without sections ("__LINKEDIT") as
 * "<segment>", and data after the image as "[overlay]".
 *
 * Entry fields: off = file offset, usize = csize = bytes, aux = section flags or
 * cpu type (fat), aux32 = cpu subtype (fat), flags = entry kind.
 * Registered GZ_FMT_WEAK like the other executable formats.
 */
#include "exe.h"

#define MO_MAX_CMDS   (16u << 20)      /* bytes of load commands */
#define MO_MAX_ARCH   32

enum { K_SECT = 1, K_SEG, K_ARCH };

static int thin_magic(u32 m, int *be, int *is64)
{
    switch (m) {
    case 0xFEEDFACEu: *be = 0; *is64 = 0; return 1;
    case 0xFEEDFACFu: *be = 0; *is64 = 1; return 1;
    case 0xCEFAEDFEu: *be = 1; *is64 = 0; return 1;
    case 0xCFFAEDFEu: *be = 1; *is64 = 1; return 1;
    }
    return 0;
}

/* ---------------- universal ---------------- */

static void arch_name(gz_xname *w, u32 cpu, u32 sub)
{
    u32 st = sub & 0x00FFFFFFu;
    const char *n = 0;
    switch (cpu) {
    case 7: n = "i386"; break;
    case 0x01000007u: n = st == 8 ? "x86_64h" : "x86_64"; break;
    case 12:
        n = st == 5 ? "armv4t" : st == 6 ? "armv6" : st == 7 ? "armv5" : st == 9 ? "armv7" :
            st == 10 ? "armv7f" : st == 11 ? "armv7s" : st == 12 ? "armv7k" : st == 14 ? "armv6m" :
            st == 15 ? "armv7m" : st == 16 ? "armv7em" : "arm";
        break;
    case 0x0100000Cu: n = st == 2 ? "arm64e" : "arm64"; break;
    case 0x0200000Cu: n = "arm64_32"; break;
    case 18: n = "ppc"; break;
    case 0x01000012u: n = "ppc64"; break;
    case 6: n = "m68k"; break;
    case 10: n = "mc98000"; break;
    case 13: n = "m88k"; break;
    case 14: n = "sparc"; break;
    case 11: n = "hppa"; break;
    case 15: n = "i860"; break;
    }
    if (n) { gz_xn_str(w, n); return; }
    gz_xn_str(w, "cpu");
    gz_xn_num(w, cpu);
    gz_xn_str(w, "_");
    gz_xn_num(w, st);
}

/* number of slices of a valid universal header, 0 if not one */
static u32 fat_check(gz_src *s, const u8 *h, u32 n, int *is64)
{
    if (n < 8) return 0;
    u32 m = rd32be(h), cnt = rd32be(h + 4);
    if ((m != 0xCAFEBABEu && m != 0xCAFEBABFu) || !cnt || cnt > MO_MAX_ARCH) return 0;
    *is64 = m == 0xCAFEBABFu;
    u32 es = *is64 ? 32 : 20;
    if (8 + cnt * es > n) return 0;
    for (u32 i = 0; i < cnt; i++) {
        const u8 *e = h + 8 + i * es;
        u64 off = *is64 ? rd64be(e + 8) : rd32be(e + 8);
        u64 len = *is64 ? rd64be(e + 16) : rd32be(e + 12);
        u8 mg[4];
        int be, b64;
        if (off < 8 + (u64)cnt * es || off >= s->size || len < 28 || len > s->size - off) return 0;
        if (off + 4 <= n) __builtin_memcpy(mg, h + off, 4);
        else if (gz_src_read_exact(s, off, mg, 4)) return 0;
        if (!thin_magic(rd32(mg), &be, &b64)) return 0;
    }
    return cnt;
}

static int fat_open(gz_archive *a, gz_src *s, const u8 *h, u32 n)
{
    int is64;
    u32 cnt = fat_check(s, h, n, &is64);
    if (!cnt) return GZ_E_FORMAT;
    u32 es = is64 ? 32 : 20;
    gz_arc_set_type(a, "Mach-O Universal");
    for (u32 i = 0; i < cnt; i++) {
        const u8 *e = h + 8 + i * es;
        u32 cpu = rd32be(e), sub = rd32be(e + 4);
        gz_xname w;
        gz_xn_reset(&w);
        arch_name(&w, cpu, sub);
        for (u32 j = 0; j < i; j++)                     /* the same arch twice: number it */
            if (rd32be(h + 8 + j * es) == cpu && (rd32be(h + 8 + j * es + 4) & 0xFFFFFF) == (sub & 0xFFFFFF)) {
                gz_xn_str(&w, "_");
                gz_xn_num(&w, i);
                break;
            }
        gz_entry *en;
        int r = gz_exe_add(a, &w, &en);
        if (r) return r;
        en->off = is64 ? rd64be(e + 8) : rd32be(e + 8);
        en->usize = en->csize = is64 ? rd64be(e + 16) : rd32be(e + 12);
        en->aux = cpu;
        en->aux32 = sub;
        en->flags = K_ARCH;
    }
    return GZ_OK;
}

/* ---------------- thin ---------------- */

static void grow_end(u64 *end, u64 fsize, u64 off, u64 len)
{
    if (off >= fsize || !len) return;
    u64 e = len > fsize - off ? fsize : off + len;
    if (e > *end) *end = e;
}

/* tables outside the segments (object files): symbols, relocations, linkedit data */
static void cmd_tables(const u8 *p, u32 id, u32 sz, int be, int is64, u64 fsize, u64 *end)
{
    if (id == 0x2 && sz >= 24) {                                /* LC_SYMTAB */
        grow_end(end, fsize, gz_x32(p + 8, be), (u64)gz_x32(p + 12, be) * (is64 ? 16 : 12));
        grow_end(end, fsize, gz_x32(p + 16, be), gz_x32(p + 20, be));
    } else if (id == 0xB && sz >= 80) {                         /* LC_DYSYMTAB */
        grow_end(end, fsize, gz_x32(p + 56, be), (u64)gz_x32(p + 60, be) * 4);   /* indirect symbols */
        grow_end(end, fsize, gz_x32(p + 64, be), (u64)gz_x32(p + 68, be) * 8);   /* external relocs  */
        grow_end(end, fsize, gz_x32(p + 72, be), (u64)gz_x32(p + 76, be) * 8);   /* local relocs     */
    } else if (sz >= 16 && (id == 0x1D || id == 0x1E || id == 0x26 || id == 0x29 || id == 0x2B ||
                            id == 0x2E || id == 0x33 || id == 0x34 || id == 0x80000033u ||
                            id == 0x80000034u)) {                 /* linkedit_data_command */
        grow_end(end, fsize, gz_x32(p + 8, be), gz_x32(p + 12, be));
    } else if ((id == 0x22 || id == 0x80000022u) && sz >= 48) { /* LC_DYLD_INFO(_ONLY) */
        for (u32 k = 0; k < 5; k++) grow_end(end, fsize, gz_x32(p + 8 + 8 * k, be), gz_x32(p + 12 + 8 * k, be));
    }
}

/* entries beyond the byte budget (hostile overlapping sections) are left out */
static int add_range(gz_archive *a, const gz_xname *w, u64 fsize, u64 off, u64 len, u32 kind, u64 aux, u64 *end,
                     u64 *budget)
{
    if (off > fsize) off = fsize;
    if (len > fsize - off) len = fsize - off;
    if (len && off + len > *end) *end = off + len;
    if (len > *budget) return GZ_OK;
    *budget -= len;
    gz_entry *e;
    int r = gz_exe_add(a, w, &e);
    if (r) return r;
    e->off = off;
    e->usize = e->csize = len;
    e->flags = (u16)kind;
    e->aux = aux;
    return GZ_OK;
}

static int thin_open(gz_archive *a, gz_src *s, const u8 *h, gz_ctx *c)
{
    int be, is64;
    if (!thin_magic(rd32(h), &be, &is64)) return GZ_E_FORMAT;
    u32 hs = is64 ? 32 : 28;
    u32 ncmds = gz_x32(h + 16, be), cs = gz_x32(h + 20, be);
    u64 fsize = s->size;
    if (s->size < hs || cs > MO_MAX_CMDS || cs > fsize - hs) return GZ_E_FORMAT;
    u8 *cmd = (u8 *)gz_alloc((size_t)cs + 8);
    if (!cmd) return GZ_E_NOMEM;
    int r = gz_src_read_exact(s, hs, cmd, cs);
    u64 end = hs + (u64)cs, budget = 4 * fsize + (64u << 20);
    u32 pos = 0;
    for (u32 i = 0; i < ncmds && !r; i++) {
        if (cs - pos < 8) break;
        if ((i & 1023) == 0 && gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        const u8 *p = cmd + pos;
        u32 id = gz_x32(p, be), sz = gz_x32(p + 4, be);
        if (sz < 8 || sz > cs - pos) break;
        int seg64 = id == 0x19;
        cmd_tables(p, id, sz, be, is64, fsize, &end);
        if (id == 0x1 || seg64) {
            u32 base = seg64 ? 72 : 56, ss = seg64 ? 80 : 68;
            if (sz < base) { pos += sz; continue; }
            u64 fo = seg64 ? gz_x64(p + 40, be) : gz_x32(p + 32, be);
            u64 fl = seg64 ? gz_x64(p + 48, be) : gz_x32(p + 36, be);
            u32 ns = gz_x32(p + (seg64 ? 64 : 48), be);
            if (ns > (sz - base) / ss) ns = (sz - base) / ss;
            grow_end(&end, fsize, fo, fl);
            gz_xname w;
            if (!ns) {
                if (fl) {
                    gz_xn_reset(&w);
                    gz_xn_part8(&w, p + 8, 16);
                    r = add_range(a, &w, fsize, fo, fl, K_SEG, 0, &end, &budget);
                }
            }
            for (u32 k = 0; k < ns && !r; k++) {
                const u8 *q = p + base + k * ss;
                u64 so = gz_x32(q + (seg64 ? 48 : 40), be);
                u64 sl = seg64 ? gz_x64(q + 40, be) : gz_x32(q + 36, be);
                u32 fl2 = gz_x32(q + (seg64 ? 64 : 56), be), t = fl2 & 0xFF;
                grow_end(&end, fsize, gz_x32(q + (seg64 ? 56 : 48), be), (u64)gz_x32(q + (seg64 ? 60 : 52), be) * 8);
                if (t == 0x1 || t == 0xC || t == 0x12 || !so) sl = 0;      /* zero fill */
                gz_xn_reset(&w);
                gz_xn_part8(&w, q[16] ? q + 16 : p + 8, 16);
                gz_xn_str(&w, "/");
                gz_xn_part8(&w, q, 16);
                r = add_range(a, &w, fsize, so, sl, K_SECT, fl2, &end, &budget);
            }
        }
        pos += sz;
    }
    gz_free(cmd);
    if (r) return r;
    if (end > fsize) end = fsize;
    return gz_exe_add_overlay(a, s, end, fsize - end, "[overlay]");
}

/* ---------------- format interface ---------------- */

static int mo_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u32 n = s->size < 65536 ? (u32)s->size : 65536;
    if (n < 28) return GZ_E_FORMAT;
    u8 *h = (u8 *)gz_alloc(n);
    if (!h) return GZ_E_NOMEM;
    int r = gz_src_read_exact(s, 0, h, n);
    if (!r) r = rd32be(h) == 0xCAFEBABEu || rd32be(h) == 0xCAFEBABFu ? fat_open(a, s, h, n) : thin_open(a, s, h, c);
    gz_free(h);
    return r;
}

static void mo_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    const char *m = "";
    if (e->flags == K_SECT) {
        u32 t = (u32)e->aux & 0xFF;
        m = t == 1 || t == 0xC || t == 0x12 ? "zerofill" : (e->aux & 0x80000000u) ? "code" :
            t == 2 ? "cstring" : t == 0x13 ? "tlv" : "data";
    } else if (e->flags == K_SEG) {
        m = "segment";
    }
    u32 i = 0;
    for (; m[i] && i + 1 < cap; i++) buf[i] = m[i];
    if (cap) buf[i] = 0;
}

static int mo_probe(gz_src *s, const u8 *h, u32 n)
{
    int be, is64;
    if (n >= 28 && thin_magic(rd32(h), &be, &is64)) return 90;
    return fat_check(s, h, n, &is64) ? 85 : 0;
}

GZ_FORMAT(gz_fmt_macho)
const gz_format gz_fmt_macho = {
    "Mach-O", "dylib bundle macho o", GZ_FMT_WEAK,
    mo_probe, mo_open, 0, gz_exe_extract_range, 0, 0, mo_method, gz_exe_view_range, 0
};
