/*
 * 고깃ZIP - ZIP reader
 *   ZIP64, SFX/prefix data, data descriptors, NTFS/Unix timestamps,
 *   Info-ZIP Unicode Path (0x7075), WinZip AES (0x9901), ZipCrypto.
 *   Methods: Store, Deflate, Deflate64.
 */
#include "arc.h"
#include "crc32.h"

#define SIG_LOCAL   0x04034b50u
#define SIG_CENTRAL 0x02014b50u
#define SIG_EOCD    0x06054b50u
#define SIG_EOCD64  0x06064b50u
#define SIG_LOC64   0x07064b50u

static int read_exact(gz_src *s, u64 off, void *buf, u32 n)
{
    return gz_src_read_exact(s, off, buf, n);
}

static void parse_extra(gz_entry *e, const u8 *x, u32 xn, u32 *z64_need, const u8 **uni, u32 *unin,
                        u32 raw_crc)
{
    u32 i = 0;
    while (i + 4 <= xn) {
        u32 id = rd16(x + i), sz = rd16(x + i + 2);
        const u8 *d = x + i + 4;
        if (i + 4 + sz > xn) break;
        if (id == 0x0001) {                 /* ZIP64 */
            u32 p = 0;
            if ((*z64_need & 1) && p + 8 <= sz) { e->usize = rd64(d + p); p += 8; }
            if ((*z64_need & 2) && p + 8 <= sz) { e->csize = rd64(d + p); p += 8; }
            if ((*z64_need & 4) && p + 8 <= sz) { e->off = rd64(d + p); p += 8; }
            *z64_need = 0;
        } else if (id == 0x000A && sz >= 32) {   /* NTFS */
            u32 p = 4;
            while (p + 4 <= sz) {
                u32 tag = rd16(d + p), tsz = rd16(d + p + 2);
                if (tag == 1 && tsz >= 24 && p + 4 + 24 <= sz) {
                    u64 mt = rd64(d + p + 4);
                    if (mt) { e->mtime = mt; e->mtime_kind = GZ_MT_FILETIME; }
                    break;
                }
                p += 4 + tsz;
            }
        } else if (id == 0x5455 && sz >= 5) {    /* extended timestamp */
            if ((d[0] & 1) && e->mtime_kind != GZ_MT_FILETIME) {
                i32 t = (i32)rd32(d + 1);
                e->mtime = gz_unix_to_filetime(t);
                e->mtime_kind = GZ_MT_FILETIME;
            }
        } else if (id == 0x7075 && sz >= 5) {    /* Info-ZIP Unicode Path */
            if (d[0] == 1 && rd32(d + 1) == raw_crc) { *uni = d + 5; *unin = sz - 5; }
        } else if (id == 0x9901 && sz >= 7) {    /* WinZip AES */
            e->aes_ver = (u8)rd16(d);
            e->aes_strength = d[4];
            e->aes_method = rd16(d + 5);
        }
        i += 4 + sz;
    }
}

static int zip_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o; (void)c;
    u64 size = s->size;
    if (size < 22) return GZ_E_FORMAT;
    u32 tail = size < 65557 + 20 ? (u32)size : 65557 + 20;
    u8 *buf = (u8 *)gz_alloc(tail);
    if (!buf) return GZ_E_NOMEM;
    u64 tail_off = size - tail;
    int r = read_exact(s, tail_off, buf, tail);
    if (r) { gz_free(buf); return r; }

    /* locate End Of Central Directory */
    i64 eocd = -1;
    for (i64 p = (i64)tail - 22; p >= 0; p--) {
        if (rd32(buf + p) != SIG_EOCD) continue;
        u32 clen = rd16(buf + p + 20);
        if ((u64)p + 22 + clen > tail) continue;
        u64 cds = rd32(buf + p + 12), cdo = rd32(buf + p + 16);
        if (cds + (cdo == 0xffffffffu ? 0 : cdo) > tail_off + (u64)p &&
            cds != 0xffffffffu && cdo != 0xffffffffu) continue;
        eocd = p;
        break;
    }
    if (eocd < 0) { gz_free(buf); return GZ_E_FORMAT; }

    const u8 *E = buf + eocd;
    u64 eocd_pos = tail_off + (u64)eocd;
    u32 disk = rd16(E + 4), cd_disk = rd16(E + 6);
    u64 count = rd16(E + 10);
    u64 cd_size = rd32(E + 12), cd_off = rd32(E + 16);
    u32 clen = rd16(E + 20);
    u64 cd_end = eocd_pos;            /* where the central directory should end */

    /* ZIP64 locator directly before EOCD */
    if (eocd >= 20 && rd32(E - 20) == SIG_LOC64) {
        u64 z64off = rd64(E - 20 + 8);
        u64 loc_pos = eocd_pos - 20;
        u8 z[56];
        int ok = 0;
        if (z64off + 56 <= loc_pos && !read_exact(s, z64off, z, 56) && rd32(z) == SIG_EOCD64) ok = 1;
        if (!ok && loc_pos >= 56 && !read_exact(s, loc_pos - 56, z, 56) && rd32(z) == SIG_EOCD64) {
            z64off = loc_pos - 56; ok = 1;
        }
        if (ok) {
            disk = rd32(z + 16); cd_disk = rd32(z + 20);
            count = rd64(z + 32);
            cd_size = rd64(z + 40);
            cd_off = rd64(z + 48);
            cd_end = z64off;
        }
    }
    if (clen) {
        a->comment_raw = (u8 *)gz_alloc(clen);
        if (a->comment_raw) { __builtin_memcpy(a->comment_raw, E + 22, clen); a->comment_len = clen; }
    }
    gz_free(buf);
    if (disk != 0 || cd_disk != 0) return GZ_E_METHOD;     /* split archives */
    if (cd_size > cd_end) return GZ_E_FORMAT;

    /* SFX / prefixed data: the real offsets are shifted */
    u64 shift = 0;
    if (cd_end - cd_size >= cd_off) shift = (cd_end - cd_size) - cd_off;
    else return GZ_E_FORMAT;
    a->sfx_shift = shift;
    if (cd_size > (1u << 30)) return GZ_E_NOMEM;

    u8 *cd = (u8 *)gz_alloc((size_t)cd_size + 8);
    if (!cd && cd_size) return GZ_E_NOMEM;
    r = cd_size ? read_exact(s, cd_off + shift, cd, (u32)cd_size) : GZ_OK;
    if (r) { gz_free(cd); return r; }

    a->win_names = 1;
    if (count < (1u << 24) && count > 0) {
        a->e = (gz_entry *)gz_alloc((size_t)count * sizeof(gz_entry));
        if (a->e) a->cap = (u32)count;
    }
    a->raw = 0;
    size_t p = 0;
    while (p + 46 <= cd_size) {
        const u8 *c = cd + p;
        if (rd32(c) != SIG_CENTRAL) break;
        u32 nlen = rd16(c + 28), xlen = rd16(c + 30), cmlen = rd16(c + 32);
        if (p + 46 + nlen + xlen + cmlen > cd_size) break;
        gz_entry *e;
        if (gz_arc_add_entry(a, &e)) { gz_free(cd); return GZ_E_NOMEM; }
        u32 made = rd16(c + 4) >> 8;
        e->flags = rd16(c + 8);
        e->method = rd16(c + 10);
        e->dos_time = rd16(c + 12);
        e->mtime = ((u64)rd16(c + 14) << 16) | rd16(c + 12);
        e->mtime_kind = GZ_MT_DOS;
        e->crc = rd32(c + 16);
        e->csize = rd32(c + 20);
        e->usize = rd32(c + 24);
        u32 ext = rd32(c + 38);
        e->off = rd32(c + 42);
        e->name_enc = (e->flags & 0x800) ? GZ_NE_UTF8 : GZ_NE_LEGACY;
        e->has_crc = 1;
        const u8 *name = c + 46;
        e->raw_len = (u16)nlen;
        e->raw_off = (u32)(name - cd);       /* temporarily relative to cd */

        u32 need = 0;
        if (e->usize == 0xffffffffu) need |= 1;
        if (e->csize == 0xffffffffu) need |= 2;
        if (e->off == 0xffffffffu) need |= 4;
        const u8 *uni = 0;
        u32 unin = 0;
        u32 raw_crc = gz_crc32(0, name, nlen);
        parse_extra(e, name + nlen, xlen, &need, &uni, &unin, raw_crc);
        if (uni && unin) {
            e->uni_off = (u32)(uni - cd);
            e->uni_len = (u16)unin;
        }
        e->off += shift;

        if (e->flags & 1) {
            e->enc = (e->method == 99) ? GZ_ENC_AES : GZ_ENC_ZIPCRYPTO;
            if (e->flags & 0x40) e->enc = GZ_ENC_AES;     /* strong encryption: unsupported */
        }
        if (e->method == 99 && !e->aes_strength) e->aes_strength = 3;
        if (e->enc == GZ_ENC_AES && e->aes_ver == 2 && e->crc == 0) e->has_crc = 0;

        /* attributes / directory */
        if (made == 3 || made == 19) {               /* Unix / OS X */
            u32 mode = ext >> 16;
            if ((mode & 0xF000) == 0x4000) e->is_dir = 1;
            if ((mode & 0xF000) == 0xA000) e->is_link = 1;
            e->unix_mode = mode;
            if (mode && !(mode & 0200)) e->attr |= 1;
            if (ext & 0x10) e->is_dir = 1;
        } else {
            e->attr = ext & 0x27;                    /* RO, hidden, system, archive */
            if (ext & 0x10) e->is_dir = 1;
        }
        if (nlen && (name[nlen - 1] == '/' || name[nlen - 1] == '\\')) e->is_dir = 1;
        if (e->is_dir) e->attr |= 0x10;
        p += 46 + nlen + xlen + cmlen;
    }
    /* move name storage into a->raw (the whole central directory) */
    a->raw = cd;
    a->raw_len = (size_t)cd_size;
    a->raw_cap = (size_t)cd_size + 8;
    if (a->n == 0 && count != 0) return GZ_E_FORMAT;
    return GZ_OK;
}

/* ---------------- entry data ---------------- */

typedef struct {
    gz_src *src;
    u64 pos, end;
    int enc;
    gz_zipcrypto zc;
    gz_aes_ctr *aes;
    gz_hmac_sha1 *hmac;
    gz_out *out;
    u64 written, limit;
} ent_reader;

static int er_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    ent_reader *r = (ent_reader *)ctx;
    u64 left = r->end - r->pos;
    *got = 0;
    if (!left) return GZ_OK;
    u32 n = cap;
    if (n > left) n = (u32)left;
    u32 g = 0;
    int e = r->src->read_at(r->src, r->pos, buf, n, &g);
    if (e) return e;
    if (!g) return GZ_E_TRUNC;
    r->pos += g;
    if (r->enc == GZ_ENC_ZIPCRYPTO) gz_zc_decrypt(&r->zc, buf, g);
    else if (r->enc == GZ_ENC_AES) {
        gz_hmac_update(r->hmac, buf, g);
        gz_aes_ctr_kernel(r->aes, buf, g);
    }
    *got = g;
    return GZ_OK;
}

static int er_write(void *ctx, const u8 *p, size_t n)
{
    ent_reader *r = (ent_reader *)ctx;
    r->written += n;
    if (r->written > r->limit) return GZ_E_DATA;      /* more data than declared */
    return r->out->write(r->out, p, n);
}

typedef struct {
    gz_aes_ctr aes;
    gz_hmac_sha1 hmac;
} aes_ctx;

/* Locate data, verify password. On success fills reader (pos/end/enc). */
static int prepare(gz_archive *a, gz_src *s, gz_entry *e, const u8 *pw, size_t pwn,
                   ent_reader *rd, aes_ctx *ac)
{
    u8 lh[30];
    (void)a;
    int r = read_exact(s, e->off, lh, 30);
    if (r) return r;
    if (rd32(lh) != SIG_LOCAL) return GZ_E_FORMAT;
    u64 data = e->off + 30 + rd16(lh + 26) + rd16(lh + 28);
    rd->src = s;
    rd->pos = data;
    rd->end = data + e->csize;
    rd->enc = GZ_ENC_NONE;
    if (rd->end > s->size) return GZ_E_TRUNC;

    if (e->enc == GZ_ENC_ZIPCRYPTO) {
        if (!pw) return GZ_E_PASSWORD;
        if (e->csize < 12) return GZ_E_DATA;
        u8 h[12];
        r = read_exact(s, data, h, 12);
        if (r) return r;
        gz_zc_init(&rd->zc, pw, pwn);
        gz_zc_decrypt(&rd->zc, h, 12);
        u8 check = (e->flags & 8) ? (u8)(e->dos_time >> 8) : (u8)(e->crc >> 24);
        if (h[11] != check) return GZ_E_PASSWORD;
        rd->pos += 12;
        rd->enc = GZ_ENC_ZIPCRYPTO;
    } else if (e->enc == GZ_ENC_AES) {
        if (e->flags & 0x40) return GZ_E_METHOD;
        if (!pw) return GZ_E_PASSWORD;
        u32 st = e->aes_strength;
        if (st < 1 || st > 3) return GZ_E_METHOD;
        u32 keylen = 8 + 8 * st, saltlen = keylen / 2;
        if (e->csize < saltlen + 2 + 10) return GZ_E_DATA;
        u8 hs[18], dk[66];
        r = read_exact(s, data, hs, saltlen + 2);
        if (r) return r;
        gz_pbkdf2_sha1(pw, pwn, hs, saltlen, 1000, dk, 2 * keylen + 2);
        if (dk[2 * keylen] != hs[saltlen] || dk[2 * keylen + 1] != hs[saltlen + 1])
            return GZ_E_PASSWORD;
        gz_aes_ctr_setup(&ac->aes, dk, (int)keylen);
        gz_hmac_init(&ac->hmac, dk + keylen, keylen);
        rd->aes = &ac->aes;
        rd->hmac = &ac->hmac;
        rd->pos += saltlen + 2;
        rd->end -= 10;
        rd->enc = GZ_ENC_AES;
    }
    return GZ_OK;
}

/* Password byte encodings to try: the system code page (what WinZip/PKZIP/Explorer
 * use for ZipCrypto) and UTF-8 (7-Zip/Bandizip for AES and Unicode passwords). */
typedef struct { u8 b[2][1024]; size_t n[2]; int count; } pw_set;

static void pw_candidates(gz_ctx *c, pw_set *ps)
{
    ps->count = 0;
    if (!c->password) return;
    size_t wn = gz_wcslen(c->password);
    if (wn > 300) wn = 300;
    int an = gz_plat_wc2mb(gz_plat_acp(), c->password, (int)wn, ps->b[0], sizeof ps->b[0]);
    if (an > 0 || wn == 0) { ps->n[ps->count] = (size_t)(an > 0 ? an : 0); ps->count++; }
    int un = gz_utf16_to_utf8(c->password, wn, ps->b[ps->count]);
    if (ps->count == 0 || (size_t)un != ps->n[0] || __builtin_memcmp(ps->b[0], ps->b[ps->count], (size_t)un)) {
        ps->n[ps->count] = (size_t)un;
        ps->count++;
    }
}

static int zip_check_password(gz_archive *a, gz_src *s, u32 idx, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    if (!e->enc || e->is_dir) return GZ_OK;
    pw_set *ps = (pw_set *)gz_alloc(sizeof(pw_set));
    aes_ctx *ac = (aes_ctx *)gz_alloc(sizeof(aes_ctx));
    if (!ps || !ac) { gz_free(ps); gz_free(ac); return GZ_E_NOMEM; }
    pw_candidates(c, ps);
    int r = GZ_E_PASSWORD;
    if (!ps->count) r = prepare(a, s, e, 0, 0, &(ent_reader){0}, ac);
    for (int k = 0; k < ps->count; k++) {
        ent_reader rd;
        __builtin_memset(&rd, 0, sizeof rd);
        r = prepare(a, s, e, ps->b[k], ps->n[k], &rd, ac);
        if (r != GZ_E_PASSWORD) break;
    }
    gz_free(ps);
    gz_free(ac);
    return r;
}

static int extract_once(gz_archive *a, gz_src *s, u32 idx, gz_out *out, const u8 *pw, size_t pwn,
                        gz_ctx *c, int *opened)
{
    gz_entry *e = &a->e[idx];
    u16 m = e->method == 99 ? e->aes_method : e->method;
    if (m != 0 && m != 8 && m != 9) return GZ_E_METHOD;
    gz_inflater *z = gz_ctx_inflater(c);
    if (!z) return GZ_E_NOMEM;

    ent_reader rd;
    __builtin_memset(&rd, 0, sizeof rd);
    aes_ctx *ac = 0;
    if (e->enc == GZ_ENC_AES) {
        ac = (aes_ctx *)gz_alloc(sizeof(aes_ctx));
        if (!ac) return GZ_E_NOMEM;
    }
    int r = prepare(a, s, e, pw, pwn, &rd, ac);
    if (r) { gz_free(ac); return r; }

    r = out->open(out, idx);
    if (r) { gz_free(ac); return r; }
    *opened = 1;
    rd.out = out;
    rd.limit = e->usize;
    gz_stream_io io = { er_read, er_write, &rd };
    int st;
    if (m == 0) st = gz_store_run(z, &io);
    else st = gz_inflate_run(z, &io, m == 9);

    if (!st && z->total_out != e->usize) st = GZ_E_DATA;
    if (!st && e->has_crc && z->crc != e->crc)
        st = (e->enc == GZ_ENC_ZIPCRYPTO) ? GZ_E_PASSWORD : GZ_E_CRC;
    if (!st && e->enc == GZ_ENC_AES) {
        u8 code[10], mac[20];
        int rr = read_exact(s, rd.end, code, 10);
        if (rr) st = rr;
        else {
            /* the reader may stop early when deflate ends: hash the rest */
            u8 tmp[4096];
            while (rd.pos < rd.end) {
                u32 n = (u32)((rd.end - rd.pos) < sizeof tmp ? (rd.end - rd.pos) : sizeof tmp);
                if (read_exact(s, rd.pos, tmp, n)) break;
                gz_hmac_update(&ac->hmac, tmp, n);
                rd.pos += n;
            }
            gz_hmac_final(&ac->hmac, mac);
            if (__builtin_memcmp(code, mac, 10)) st = GZ_E_AUTH;
        }
    }
    gz_free(ac);
    return st;
}

static int null_open(gz_out *o, u32 idx) { (void)o; (void)idx; return GZ_OK; }
static int null_write(gz_out *o, const u8 *p, size_t n) { (void)o; (void)p; (void)n; return GZ_OK; }
static int null_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return GZ_OK; }

static int zip_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir) {
        int r = out->open(out, idx);
        if (r) return r;
        return out->close(out, idx, GZ_OK);
    }
    const u8 *pw = 0;
    size_t pwn = 0;
    pw_set *ps = 0;
    if (e->enc) {
        ps = (pw_set *)gz_alloc(sizeof(pw_set));
        aes_ctx *ac = (aes_ctx *)gz_alloc(sizeof(aes_ctx));
        if (!ps || !ac) { gz_free(ps); gz_free(ac); return GZ_E_NOMEM; }
        pw_candidates(c, ps);
        /* encodings that pass the header check */
        int pass[2], np = 0, err = GZ_E_PASSWORD;
        for (int k = 0; k < ps->count; k++) {
            ent_reader rd;
            __builtin_memset(&rd, 0, sizeof rd);
            int r = prepare(a, s, e, ps->b[k], ps->n[k], &rd, ac);
            if (!r) pass[np++] = k;
            else if (r != GZ_E_PASSWORD) err = r;
        }
        gz_free(ac);
        if (!np) { gz_free(ps); return err; }
        int pick = pass[0];
        if (np > 1) {
            /* both pass the 1-byte ZipCrypto check: find the one with the right CRC */
            gz_out nul = { null_open, null_write, null_close, 0 };
            for (int k = 0; k < np; k++) {
                int op = 0;
                if (!extract_once(a, s, idx, &nul, ps->b[pass[k]], ps->n[pass[k]], c, &op)) { pick = pass[k]; break; }
            }
        }
        pw = ps->b[pick];
        pwn = ps->n[pick];
    }
    int opened = 0;
    int st = extract_once(a, s, idx, out, pw, pwn, c, &opened);
    gz_free(ps);
    if (!opened) return st;
    int cr = out->close(out, idx, st);
    return st ? st : cr;
}

static void zip_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    (void)a;
    u16 m = e->method == 99 ? e->aes_method : e->method;
    const char *n = "?";
    switch (m) {
    case 0: n = "Store"; break;
    case 1: n = "Shrink"; break;
    case 2: case 3: case 4: case 5: n = "Reduce"; break;
    case 6: n = "Implode"; break;
    case 8: n = "Deflate"; break;
    case 9: n = "Deflate64"; break;
    case 12: n = "BZip2"; break;
    case 14: n = "LZMA"; break;
    case 93: n = "Zstd"; break;
    case 95: n = "XZ"; break;
    case 96: n = "JPEG"; break;
    case 97: n = "WavPack"; break;
    case 98: n = "PPMd"; break;
    }
    const char *enc = e->enc == GZ_ENC_AES ? (e->aes_strength == 1 ? " AES-128" : e->aes_strength == 2 ? " AES-192" : " AES-256")
                    : e->enc == GZ_ENC_ZIPCRYPTO ? " ZipCrypto" : "";
    u32 i = 0;
    for (; *n && i + 1 < cap; n++) buf[i++] = *n;
    for (; *enc && i + 1 < cap; enc++) buf[i++] = *enc;
    if (cap) buf[i] = 0;
}

/* stored, unencrypted entries can be read in place */
static gz_src *zip_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    if (e->is_dir || e->enc || e->method != 0) return 0;
    u8 lh[30];
    if (read_exact(s, e->off, lh, 30) || rd32(lh) != SIG_LOCAL) return 0;
    u64 data = e->off + 30 + rd16(lh + 26) + rd16(lh + 28);
    if (data + e->usize > s->size) return 0;
    return gz_src_sub(s, data, e->usize);
}

static int zip_probe(gz_src *s, const u8 *h, u32 n)
{
    if (n >= 4 && h[0] == 'P' && h[1] == 'K' && (h[2] == 3 || h[2] == 5 || h[2] == 7) && h[3] == h[2] + 1)
        return 95;
    if (n >= 8 && rd32(h) == 0x30304b50u && rd32(h + 4) == SIG_LOCAL) return 95;   /* "PK00" spanned marker */
    /* SFX or data before the archive: look for the end record */
    if (s->size < 22) return 0;
    u32 tail = s->size < 65557 ? (u32)s->size : 65557;
    u8 *buf = (u8 *)gz_alloc(tail);
    if (!buf) return 0;
    int score = 0;
    if (!read_exact(s, s->size - tail, buf, tail)) {
        for (i64 p = (i64)tail - 22; p >= 0; p--) {
            if (rd32(buf + p) == SIG_EOCD && (u64)p + 22 + rd16(buf + p + 20) <= tail) { score = 40; break; }
        }
    }
    gz_free(buf);
    return score;
}

GZ_FORMAT(gz_fmt_zip)
const gz_format gz_fmt_zip = {
    "ZIP", "zip zipx jar war ear apk xpi odt ods odp docx xlsx pptx epub ipa appx nupkg whl",
    0, zip_probe, zip_open, 0, zip_extract, 0, zip_check_password, zip_method, zip_view, 0
};
