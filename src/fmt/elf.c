/*
 * 고깃ZIP - ELF executables, shared objects, object files and core dumps
 * (32/64-bit, little and big endian)
 *
 * Entries: one per section (".text", ".rodata" ...; SHT_NOBITS sections such as
 * ".bss" are listed empty, the SHT_NULL entry is left out). Files without section
 * headers (stripped to the program headers, core dumps) list their segments as
 * "segment<n>_<TYPE>". Data after everything the headers describe (an SFX payload,
 * e.g. 7-Zip's 7zCon.sfx + archive) is "[overlay]", viewable in place.
 * Extended numbering (e_shnum / e_shstrndx / e_phnum escapes in section 0) is
 * supported. Registered GZ_FMT_WEAK so archives appended to an ELF stub open as
 * the archive.
 *
 * Entry fields: off = file offset, usize = csize = bytes, method = section type
 * (low 16 bits) or segment type, flags = 1 for segments, aux = sh_type / p_type.
 */
#include "exe.h"

#define ELF_MAX_SECT  (1u << 20)
#define ELF_MAX_SEG   (1u << 16)
#define ELF_MAX_STR   (16u << 20)      /* section name table kept in memory */

typedef struct {
    gz_src *s;
    u64 fsize;
    int be, is64;
    u64 end;                        /* end of all described data */
    u64 budget;                     /* bytes the entries may still cover (overlaps) */
} elf_ctx;

static void grow_end(elf_ctx *x, u64 off, u64 len)
{
    if (off >= x->fsize) return;
    u64 e = len > x->fsize - off ? x->fsize : off + len;
    if (e > x->end) x->end = e;
}

static const char *const k_sht[20] = {
    "NULL", "PROGBITS", "SYMTAB", "STRTAB", "RELA", "HASH", "DYNAMIC", "NOTE", "NOBITS", "REL",
    "SHLIB", "DYNSYM", 0, 0, "INIT_ARRAY", "FINI_ARRAY", "PREINIT_ARRAY", "GROUP", "SYMTAB_SHNDX", "RELR"
};

static const char *const k_pt[8] = { "NULL", "LOAD", "DYNAMIC", "INTERP", "NOTE", "SHLIB", "PHDR", "TLS" };

static void type_text(gz_xname *w, u32 t, int seg)
{
    const char *n = 0;
    if (seg) {
        if (t < 8) n = k_pt[t];
        else if (t == 0x6474E550u) n = "GNU_EH_FRAME";
        else if (t == 0x6474E551u) n = "GNU_STACK";
        else if (t == 0x6474E552u) n = "GNU_RELRO";
        else if (t == 0x6474E553u) n = "GNU_PROPERTY";
    } else {
        if (t < 20) n = k_sht[t];
        else if (t == 0x6FFFFFF6u) n = "GNU_HASH";
        else if (t == 0x6FFFFFFDu) n = "VERDEF";
        else if (t == 0x6FFFFFFEu) n = "VERNEED";
        else if (t == 0x6FFFFFFFu) n = "VERSYM";
        else if (t == 0x70000003u) n = "ARM_ATTRIBUTES";
    }
    if (n) { gz_xn_str(w, n); return; }
    static const char hx[] = "0123456789ABCDEF";
    char b[11];
    b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 8; i++) b[2 + i] = hx[(t >> (28 - 4 * i)) & 15];
    b[10] = 0;
    gz_xn_str(w, b);
}

/* entries beyond the byte budget (hostile overlapping sections) are left out */
static int add_range(gz_archive *a, elf_ctx *x, const gz_xname *w, u64 off, u64 len, u32 type, int seg)
{
    if (off > x->fsize) off = x->fsize;
    if (len > x->fsize - off) len = x->fsize - off;
    grow_end(x, off, len);
    if (len > x->budget) return GZ_OK;
    x->budget -= len;
    gz_entry *e;
    int r = gz_exe_add(a, w, &e);
    if (r) return r;
    e->off = off;
    e->usize = e->csize = len;
    e->aux = type;
    e->flags = (u16)seg;
    return GZ_OK;
}

static int elf_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 h[64];
    if (s->size < 52 || gz_src_read_exact(s, 0, h, s->size < 64 ? 52 : 64)) return GZ_E_FORMAT;
    if (rd32(h) != 0x464C457Fu || (h[4] != 1 && h[4] != 2) || (h[5] != 1 && h[5] != 2)) return GZ_E_FORMAT;
    elf_ctx x = { s, s->size, h[5] == 2, h[4] == 2, 0, 4 * s->size + (64u << 20) };
    if (x.is64 && s->size < 64) return GZ_E_FORMAT;
    int be = x.be;
    u64 phoff, shoff;
    u32 ehsize, phes, phn, shes, shn, shstr;
    if (x.is64) {
        phoff = gz_x64(h + 32, be); shoff = gz_x64(h + 40, be);
        ehsize = gz_x16(h + 52, be); phes = gz_x16(h + 54, be); phn = gz_x16(h + 56, be);
        shes = gz_x16(h + 58, be); shn = gz_x16(h + 60, be); shstr = gz_x16(h + 62, be);
    } else {
        phoff = gz_x32(h + 28, be); shoff = gz_x32(h + 32, be);
        ehsize = gz_x16(h + 40, be); phes = gz_x16(h + 42, be); phn = gz_x16(h + 44, be);
        shes = gz_x16(h + 46, be); shn = gz_x16(h + 48, be); shstr = gz_x16(h + 50, be);
    }
    u32 shmin = x.is64 ? 64 : 40, phmin = x.is64 ? 56 : 32;
    x.end = GZ_MAX((u64)ehsize, (u64)(x.is64 ? 64 : 52));
    if (x.end > x.fsize) x.end = x.fsize;
    if (shoff >= x.fsize || shes < shmin) { shoff = 0; shn = 0; }
    /* extended numbering lives in section 0 */
    u8 s0[64];
    if (shoff && !gz_src_read_exact(s, shoff, s0, shmin)) {
        u64 sz0 = x.is64 ? gz_x64(s0 + 32, be) : gz_x32(s0 + 20, be);
        if (!shn) shn = sz0 > ELF_MAX_SECT ? ELF_MAX_SECT : (u32)sz0;
        if (shstr == 0xFFFF) shstr = gz_x32(s0 + (x.is64 ? 40 : 24), be);
        if (phn == 0xFFFF) phn = gz_x32(s0 + (x.is64 ? 44 : 28), be);
    } else {
        shn = 0;
    }
    if (shn > ELF_MAX_SECT) shn = ELF_MAX_SECT;
    if (shn && (u64)shn * shes > x.fsize - shoff) shn = (u32)((x.fsize - shoff) / shes);
    if (phoff >= x.fsize || phes < phmin) phn = 0;
    if (phn > ELF_MAX_SEG) phn = ELF_MAX_SEG;
    if (phn && (u64)phn * phes > x.fsize - phoff) phn = (u32)((x.fsize - phoff) / phes);
    if ((u64)phn * phes > (16u << 20)) phn = (16u << 20) / phes;
    if (shn) grow_end(&x, shoff, (u64)shn * shes);
    if (phn) grow_end(&x, phoff, (u64)phn * phes);

    u8 *tab = 0, *names = 0;
    int r = GZ_OK;
    /* section name table */
    u64 nt_off = 0, nt_len = 0;
    if (shn && shstr < shn) {
        u8 e[64];
        if (!gz_src_read_exact(s, shoff + (u64)shstr * shes, e, shmin)) {
            nt_off = x.is64 ? gz_x64(e + 24, be) : gz_x32(e + 16, be);
            nt_len = x.is64 ? gz_x64(e + 32, be) : gz_x32(e + 20, be);
            if (nt_off >= x.fsize) nt_len = 0;
            else if (nt_len > x.fsize - nt_off) nt_len = x.fsize - nt_off;
            if (nt_len > ELF_MAX_STR) nt_len = ELF_MAX_STR;
            names = (u8 *)gz_alloc((size_t)nt_len + 1);
            if (!names) return GZ_E_NOMEM;
            if (nt_len && gz_src_read_exact(s, nt_off, names, (u32)nt_len)) nt_len = 0;
        }
    }
    /* sections, read in chunks of the table */
    const u32 chunk = 1024;
    if (shn) {
        tab = (u8 *)gz_alloc((size_t)chunk * shes);
        if (!tab) { gz_free(names); return GZ_E_NOMEM; }
    }
    for (u32 i0 = 0; i0 < shn && !r; i0 += chunk) {
        u32 m = GZ_MIN(chunk, shn - i0);
        if (gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        if ((r = gz_src_read_exact(s, shoff + (u64)i0 * shes, tab, m * shes))) break;
        for (u32 k = 0; k < m && !r; k++) {
            const u8 *e = tab + (size_t)k * shes;
            u32 nm = gz_x32(e, be), type = gz_x32(e + 4, be);
            u64 off = x.is64 ? gz_x64(e + 24, be) : gz_x32(e + 16, be);
            u64 len = x.is64 ? gz_x64(e + 32, be) : gz_x32(e + 20, be);
            if (type == 0) continue;                      /* SHT_NULL */
            gz_xname w;
            gz_xn_reset(&w);
            u32 l = 0;
            if (nm < nt_len) while (nm + l < nt_len && names[nm + l] && l < 512) l++;
            if (l) gz_xn_part8(&w, names + nm, l);
            else { gz_xn_str(&w, "["); gz_xn_num(&w, i0 + k); gz_xn_str(&w, "]"); }
            if (type == 8) len = 0;                       /* SHT_NOBITS */
            r = add_range(a, &x, &w, off, len, type, 0);
        }
    }
    gz_free(tab);
    gz_free(names);
    if (r) return r;
    /* segments: listed when there are no sections, always counted for the image end */
    if (phn) {
        tab = (u8 *)gz_alloc((size_t)phn * phes);
        if (!tab) return GZ_E_NOMEM;
        if ((r = gz_src_read_exact(s, phoff, tab, phn * phes))) { gz_free(tab); return r; }
        int list = a->n == 0;
        for (u32 i = 0; i < phn && !r; i++) {
            const u8 *e = tab + (size_t)i * phes;
            u32 type = gz_x32(e, be);
            u64 off = x.is64 ? gz_x64(e + 8, be) : gz_x32(e + 4, be);
            u64 len = x.is64 ? gz_x64(e + 32, be) : gz_x32(e + 16, be);
            if (!list) { grow_end(&x, off, len); continue; }
            if (type == 0) continue;
            gz_xname w;
            gz_xn_reset(&w);
            gz_xn_str(&w, "segment");
            gz_xn_num(&w, i);
            gz_xn_str(&w, "_");
            type_text(&w, type, 1);
            r = add_range(a, &x, &w, off, len, type, 1);
        }
        gz_free(tab);
        if (r) return r;
    }
    if (!a->n && x.end >= x.fsize) return GZ_E_FORMAT;   /* nothing to show */
    return gz_exe_add_overlay(a, s, x.end, x.fsize - x.end, "[overlay]");
}

static void elf_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    gz_xname w;
    gz_xn_reset(&w);
    if (e->aux || e->flags) type_text(&w, (u32)e->aux, e->flags);   /* overlay: none */
    u32 n = GZ_MIN(w.n, cap ? cap - 1 : 0);
    __builtin_memcpy(buf, w.b, n);
    if (cap) buf[n] = 0;
}

static int elf_probe(gz_src *s, const u8 *h, u32 n)
{
    (void)s;
    if (n < 52 || rd32(h) != 0x464C457Fu || (h[4] != 1 && h[4] != 2) || (h[5] != 1 && h[5] != 2) || h[6] != 1)
        return 0;
    return 90;
}

GZ_FORMAT(gz_fmt_elf)
const gz_format gz_fmt_elf = {
    "ELF", "elf so o ko axf prx mod", GZ_FMT_WEAK,
    elf_probe, elf_open, 0, gz_exe_extract_range, 0, 0, elf_method, gz_exe_view_range, 0
};
