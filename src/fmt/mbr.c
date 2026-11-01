/*
 * 고깃ZIP - partition maps: MBR (primary + extended/logical EBR chains),
 * GPT (header and entry-array CRCs, backup header fallback, 512 and 4096
 * byte sectors) and the Apple Partition Map.
 *
 * One entry per partition: "<n>[.<label>].<ext>", n = slot number (MBR logical
 * partitions count from 5 like Linux), ext from the file system found inside
 * (ntfs, fat, ext, hfs ...) or else from the partition type. Entries are
 * viewed in place (gz_src_sub), so a single partition is opened automatically
 * by the core. Registered as GZ_FMT_WEAK: 0x55AA at offset 510 is common
 * (boot sectors, hybrid ISOs), so any specific format wins.
 *
 * Entry fields: off = byte offset, usize = csize = byte length,
 * flags = map kind, method = MBR type / GPT type index, aux/aux32 = APM type
 * string in a->raw.
 */
#include "vdisk.h"
#include "crc32.h"

enum { PM_MBR = 1, PM_GPT = 2, PM_APM = 3 };

#define MAX_LOGICAL 128
#define MAX_GPT_BYTES (1u << 20)       /* partition entry array */

/* ---------------- naming ---------------- */

typedef struct { gzch b[160]; u32 n; } wname;

static void wn_ascii(wname *w, const char *s)
{
    for (; *s && w->n < GZ_COUNTOF(w->b); s++) w->b[w->n++] = (u8)*s;
}

static void wn_num(wname *w, u32 v)
{
    char t[12];
    int k = 0;
    do { t[k++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (k && w->n < GZ_COUNTOF(w->b)) w->b[w->n++] = (gzch)t[--k];
}

/* label characters that would split or hide the name are replaced */
static void wn_label(wname *w, const gzch *s, u32 n)
{
    while (n && (s[n - 1] == ' ' || s[n - 1] == 0)) n--;
    u32 i = 0;
    while (i < n && s[i] == ' ') i++;
    if (i >= n) return;
    wn_ascii(w, ".");
    for (; i < n && w->n < 120; i++) {
        gzch c = s[i];
        if (!c) break;
        if (c < 0x20 || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' ||
            c == '<' || c == '>' || c == '|')
            c = '_';
        w->b[w->n++] = c;
    }
}

static int add_part(gz_archive *a, wname *w, const char *ext, u64 off, u64 len, int kind, u16 method)
{
    wn_ascii(w, ".");
    wn_ascii(w, ext);
    gz_entry *e;
    int r = gz_arc_add_named(a, w->b, w->n * 2, GZ_NE_UTF16LE, &e);
    if (r) return r;
    e->off = off;
    e->usize = e->csize = len;
    e->attr = 0x20;
    e->flags = (u16)kind;
    e->method = method;
    return GZ_OK;
}

/* ---------------- file system sniffing (for the extension) ---------------- */

static int fat_bpb(const u8 *b)
{
    u16 bps = rd16(b + 11);
    u8 spc = b[13];
    if ((b[0] != 0xEB && b[0] != 0xE9) || rd16(b + 510) != 0xAA55) return 0;
    if (bps != 512 && bps != 1024 && bps != 2048 && bps != 4096) return 0;
    if (!gz_vd_pow2(spc) || !rd16(b + 14) || b[16] < 1 || b[16] > 2) return 0;
    return 1;
}

static const char *sniff_fs(gz_src *s, u64 off, u64 len)
{
    u8 b[4096];
    u32 n = len < sizeof b ? (u32)len : (u32)sizeof b;
    if (n < 512 || off >= s->size) return 0;
    if (n > s->size - off) n = (u32)(s->size - off);
    if (n < 512 || gz_src_read_exact(s, off, b, n)) return 0;
    if (!__builtin_memcmp(b + 3, "NTFS    ", 8)) return "ntfs";
    if (!__builtin_memcmp(b + 3, "EXFAT   ", 8)) return "exfat";
    if (!__builtin_memcmp(b + 3, "ReFS", 4)) return "refs";
    if (!__builtin_memcmp(b, "XFSB", 4)) return "xfs";
    if (!__builtin_memcmp(b, "hsqs", 4)) return "squashfs";
    if (!__builtin_memcmp(b, "LUKS\xba\xbe", 6)) return "luks";
    if (!__builtin_memcmp(b + 32, "NXSB", 4)) return "apfs";
    if (n >= 2048) {
        if (rd16(b + 1080) == 0xEF53) return "ext";
        if (!__builtin_memcmp(b + 1024, "H+", 2) || !__builtin_memcmp(b + 1024, "HX", 2) ||
            !__builtin_memcmp(b + 1024, "BD", 2))
            return "hfs";
    }
    if (!__builtin_memcmp(b + 512, "LABELONE", 8)) return "lvm";
    if (n == 4096 && (!__builtin_memcmp(b + 4086, "SWAPSPACE2", 10) || !__builtin_memcmp(b + 4086, "SWAP-SPACE", 10)))
        return "swap";
    if (fat_bpb(b)) return "fat";
    if (len > 32774 && off + 32774 <= s->size) {
        u8 t[5];
        if (!gz_src_read_exact(s, off + 32769, t, 5) && !__builtin_memcmp(t, "CD001", 5)) return "iso";
    }
    return 0;
}

/* ---------------- MBR ---------------- */

static int is_ext_type(u8 t) { return t == 0x05 || t == 0x0F || t == 0x85; }

static const char *mbr_ext(u8 t)
{
    switch (t) {
    case 0x01: case 0x04: case 0x06: case 0x0B: case 0x0C: case 0x0E:
    case 0x11: case 0x14: case 0x16: case 0x1B: case 0x1C: case 0x1E: return "fat";
    case 0x07: case 0x17: case 0x27: return "ntfs";
    case 0x82: return "swap";
    case 0x83: return "linux";
    case 0x8E: return "lvm";
    case 0xFD: return "raid";
    case 0xA5: case 0xA6: case 0xA9: return "bsd";
    case 0xAF: return "hfs";
    case 0xEE: return "gpt";
    case 0xEF: return "efi";
    }
    return "img";
}

/* The 4 primary entries look like a partition table: valid status bytes and
 * at least one non-empty entry starting inside the disk. */
static int mbr_table_ok(const u8 *sec, u64 disk_size)
{
    if (rd16(sec + 510) != 0xAA55) return 0;
    if (!__builtin_memcmp(sec + 3, "NTFS    ", 8) || !__builtin_memcmp(sec + 3, "EXFAT   ", 8)) return 0;
    int used = 0;
    for (int i = 0; i < 4; i++) {
        const u8 *p = sec + 446 + 16 * i;
        if (p[0] & 0x7F) return 0;
        if (!p[4]) continue;
        u32 start = rd32(p + 8), cnt = rd32(p + 12);
        if (!start || !cnt) return 0;
        if ((u64)start * 512 < disk_size) used++;
    }
    return used;
}

static int mbr_add(gz_archive *a, gz_src *s, u32 num, u8 type, u64 start, u64 cnt)
{
    u64 off = start * 512, len = cnt * 512;
    if (!cnt || off >= s->size) return GZ_OK;          /* outside the image: not listed */
    wname w = { {0}, 0 };
    wn_num(&w, num);
    const char *ext = sniff_fs(s, off, len);
    return add_part(a, &w, ext ? ext : mbr_ext(type), off, len, PM_MBR, type);
}

static int mbr_open_table(gz_archive *a, gz_src *s, const u8 *sec, gz_ctx *c)
{
    u64 ext_start = 0, ext_cnt = 0;
    for (int i = 0; i < 4; i++) {
        const u8 *p = sec + 446 + 16 * i;
        u8 t = p[4];
        if (!t) continue;
        if (is_ext_type(t)) {
            if (!ext_start) { ext_start = rd32(p + 8); ext_cnt = rd32(p + 12); }
            continue;
        }
        int r = mbr_add(a, s, (u32)i + 1, t, rd32(p + 8), rd32(p + 12));
        if (r) return r;
    }
    /* logical partitions: EBR chain inside the extended partition */
    if (ext_start) {
        u64 ebr = ext_start, seen[MAX_LOGICAL];
        u32 nseen = 0, num = 5;
        u8 b[512];
        while (nseen < MAX_LOGICAL) {
            if (gz_cancelled(c)) return GZ_E_CANCEL;
            for (u32 k = 0; k < nseen; k++) if (seen[k] == ebr) goto done;   /* loop */
            seen[nseen++] = ebr;
            if (ebr * 512 + 512 > s->size || gz_src_read_exact(s, ebr * 512, b, 512)) break;
            if (rd16(b + 510) != 0xAA55) break;
            const u8 *l = b + 446, *nx = b + 462;
            if (l[4] && !is_ext_type(l[4]) && rd32(l + 8) && rd32(l + 12)) {
                int r = mbr_add(a, s, num++, l[4], ebr + rd32(l + 8), rd32(l + 12));
                if (r) return r;
            }
            if (!is_ext_type(nx[4]) || !rd32(nx + 8)) break;
            u64 next = ext_start + rd32(nx + 8);
            if (next >= ext_start + ext_cnt) break;
            ebr = next;
        }
    done:;
    }
    return a->n ? GZ_OK : GZ_E_FORMAT;
}

/* ---------------- GPT ---------------- */

typedef struct { u32 d1; u16 d2, d3; u8 d4[8]; const char *ext, *name; } gpt_type;

static const gpt_type k_gpt[] = {
    { 0xC12A7328, 0xF81F, 0x11D2, {0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B}, "efi",   "EFI System" },
    { 0xE3C9E316, 0x0B5C, 0x4DB8, {0x81,0x7D,0xF9,0x2D,0xF0,0x02,0x15,0xAE}, "img",   "MS Reserved" },
    { 0xEBD0A0A2, 0xB9E5, 0x4433, {0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7}, "img",   "Basic Data" },
    { 0xDE94BBA4, 0x06D1, 0x4D40, {0xA1,0x6A,0xBF,0xD5,0x01,0x79,0xD6,0xAC}, "ntfs",  "Windows Recovery" },
    { 0x5808C8AA, 0x7E8F, 0x42E0, {0x85,0xD2,0xE1,0xE9,0x04,0x34,0xCF,0xB3}, "img",   "LDM Metadata" },
    { 0xAF9B60A0, 0x1431, 0x4F62, {0xBC,0x68,0x33,0x11,0x71,0x4A,0x69,0xAD}, "img",   "LDM Data" },
    { 0x0FC63DAF, 0x8483, 0x4772, {0x8E,0x79,0x3D,0x69,0xD8,0x47,0x7D,0xE4}, "linux", "Linux" },
    { 0x4F68BCE3, 0xE8CD, 0x4DB1, {0x96,0xE7,0xFB,0xCA,0xF9,0x84,0xB7,0x09}, "linux", "Linux Root x86-64" },
    { 0xB921B045, 0x1DF0, 0x41C3, {0xAF,0x44,0x4C,0x6F,0x28,0x0D,0x3F,0xAE}, "linux", "Linux Root ARM64" },
    { 0x933AC7E1, 0x2EB4, 0x4F13, {0xB8,0x44,0x0E,0x14,0xE2,0xAE,0xF9,0x15}, "linux", "Linux Home" },
    { 0xBC13C2FF, 0x59E6, 0x4262, {0xA3,0x52,0xB2,0x75,0xFD,0x6F,0x71,0x72}, "img",   "Linux Boot" },
    { 0x0657FD6D, 0xA4AB, 0x43C4, {0x84,0xE5,0x09,0x33,0xC8,0x4B,0x4F,0x4F}, "swap",  "Linux Swap" },
    { 0xE6D6D379, 0xF507, 0x44C2, {0xA2,0x3C,0x23,0x8F,0x2A,0x3D,0xF9,0x28}, "lvm",   "Linux LVM" },
    { 0xA19D880F, 0x05FC, 0x4D3B, {0xA0,0x06,0x74,0x3F,0x0F,0x84,0x91,0x1E}, "raid",  "Linux RAID" },
    { 0xCA7D7CCB, 0x63ED, 0x4C53, {0x86,0x1C,0x17,0x42,0x53,0x60,0x59,0xCC}, "luks",  "Linux LUKS" },
    { 0x21686148, 0x6449, 0x6E6F, {0x74,0x4E,0x65,0x65,0x64,0x45,0x46,0x49}, "img",   "BIOS Boot" },
    { 0x48465300, 0x0000, 0x11AA, {0xAA,0x11,0x00,0x30,0x65,0x43,0xEC,0xAC}, "hfs",   "Apple HFS+" },
    { 0x7C3457EF, 0x0000, 0x11AA, {0xAA,0x11,0x00,0x30,0x65,0x43,0xEC,0xAC}, "apfs",  "Apple APFS" },
    { 0x426F6F74, 0x0000, 0x11AA, {0xAA,0x11,0x00,0x30,0x65,0x43,0xEC,0xAC}, "img",   "Apple Boot" },
    { 0x516E7CB4, 0x6ECF, 0x11D6, {0x8F,0xF8,0x00,0x02,0x2D,0x09,0x71,0x2B}, "ufs",   "FreeBSD UFS" },
    { 0x516E7CBA, 0x6ECF, 0x11D6, {0x8F,0xF8,0x00,0x02,0x2D,0x09,0x71,0x2B}, "zfs",   "FreeBSD ZFS" },
    { 0x6A898CC3, 0x1DD2, 0x11B2, {0x99,0xA6,0x08,0x00,0x20,0x73,0x66,0x31}, "zfs",   "ZFS" },
};

static int gpt_find_type(const u8 *g)
{
    for (u32 i = 0; i < GZ_COUNTOF(k_gpt); i++) {
        const gpt_type *t = &k_gpt[i];
        if (rd32(g) == t->d1 && rd16(g + 4) == t->d2 && rd16(g + 6) == t->d3 && !__builtin_memcmp(g + 8, t->d4, 8))
            return (int)i;
    }
    return -1;
}

/* Header at lba valid (signature, size, CRC, own LBA, sane array)? */
static int gpt_header_ok(const u8 *h, u32 ss, u64 lba)
{
    if (__builtin_memcmp(h, "EFI PART", 8)) return 0;
    u32 hs = rd32(h + 12);
    if (hs < 92 || hs > ss) return 0;
    u8 tmp[4096];
    __builtin_memcpy(tmp, h, hs);
    wr32(tmp + 16, 0);
    if (gz_crc32(0, tmp, hs) != rd32(h + 16)) return 0;
    if (rd64(h + 24) != lba) return 0;
    u32 cnt = rd32(h + 80), es = rd32(h + 84);
    if (es < 128 || es > 4096 || (es & 7) || !cnt || (u64)cnt * es > MAX_GPT_BYTES) return 0;
    return 1;
}

/* Read the header at lba into h (ss bytes) and its entry array into *arr.
 * GZ_E_CRC when the array checksum fails, GZ_E_FORMAT when there is no valid header. */
static int gpt_read(gz_src *s, u32 ss, u64 lba, u8 *h, u8 **arr)
{
    *arr = 0;
    if (lba > (s->size / ss) || (lba + 1) * ss > s->size) return GZ_E_FORMAT;
    if (gz_src_read_exact(s, lba * ss, h, ss) || !gpt_header_ok(h, ss, lba)) return GZ_E_FORMAT;
    u64 elba = rd64(h + 72);
    u32 bytes = rd32(h + 80) * rd32(h + 84);
    if (elba > s->size / ss || elba * ss + bytes > s->size) return GZ_E_FORMAT;
    u8 *p = (u8 *)gz_alloc(bytes);
    if (!p) return GZ_E_NOMEM;
    int r = gz_src_read_exact(s, elba * ss, p, bytes);
    if (!r && gz_crc32(0, p, bytes) != rd32(h + 88)) r = GZ_E_CRC;
    if (r) { gz_free(p); return r; }
    *arr = p;
    return GZ_OK;
}

static int gpt_open(gz_archive *a, gz_src *s, u32 ss, gz_ctx *c)
{
    u8 h[4096];
    u8 *arr = 0;
    int r = gpt_read(s, ss, 1, h, &arr);
    if (r == GZ_E_NOMEM) return r;
    if (r) {
        /* primary damaged: backup header (where the primary says, else the last sector) */
        int pr = r;
        u64 alt = (pr == GZ_E_CRC) ? rd64(h + 32) : 0;
        u64 last = s->size / ss - 1;
        r = GZ_E_FORMAT;
        if (alt && alt != 1) r = gpt_read(s, ss, alt, h, &arr);
        if (r && r != GZ_E_NOMEM && alt != last) r = gpt_read(s, ss, last, h, &arr);
        if (r == GZ_E_NOMEM) return r;
        if (r) return (pr == GZ_E_CRC || r == GZ_E_CRC) ? GZ_E_CRC : r;
    }
    u32 cnt = rd32(h + 80), es = rd32(h + 84);
    for (u32 i = 0; i < cnt && !r; i++) {
        const u8 *p = arr + (size_t)i * es;
        static const u8 zero[16];
        if (!__builtin_memcmp(p, zero, 16)) continue;
        if ((i & 255) == 0 && gz_cancelled(c)) { r = GZ_E_CANCEL; break; }
        u64 first = rd64(p + 32), lastl = rd64(p + 40);
        if (first > lastl || lastl >= ((u64)1 << 52) / ss) continue;
        u64 off = first * ss, len = (lastl - first + 1) * ss;
        if (off >= s->size) continue;
        int ti = gpt_find_type(p);
        wname w = { {0}, 0 };
        wn_num(&w, i + 1);
        gzch lab[36];
        u32 ln = 0;
        while (ln < 36 && 56 + 2 * ln + 2 <= es && rd16(p + 56 + 2 * ln)) { lab[ln] = rd16(p + 56 + 2 * ln); ln++; }
        wn_label(&w, lab, ln);
        const char *ext = sniff_fs(s, off, len);
        if (!ext) ext = ti >= 0 ? k_gpt[ti].ext : "img";
        r = add_part(a, &w, ext, off, len, PM_GPT, (u16)(ti >= 0 ? ti : 0xFFFF));
        if (!r) {
            /* keep the type GUID for the method column */
            u32 ro;
            if (!(r = gz_arc_raw_append(a, p, 16, &ro))) a->e[a->n - 1].aux = ro;
        }
    }
    gz_free(arr);
    if (r) return r;
    gz_arc_set_type(a, "GPT");
    return a->n ? GZ_OK : GZ_E_FORMAT;
}

/* "EFI PART" at LBA 1 for 512 or 4096 byte sectors: returns the sector size or 0 */
static u32 gpt_sector_size(gz_src *s, const u8 *head, u32 n)
{
    static const u32 sizes[2] = { 512, 4096 };
    for (int i = 0; i < 2; i++) {
        u32 ss = sizes[i];
        u8 sig[8];
        if (n >= ss + 8) { if (!__builtin_memcmp(head + ss, "EFI PART", 8)) return ss; }
        else if (s && s->size >= ss + 92 && !gz_src_read_exact(s, ss, sig, 8) && !__builtin_memcmp(sig, "EFI PART", 8))
            return ss;
    }
    return 0;
}

/* ---------------- Apple Partition Map ---------------- */

/* block size for the map, or 0 when this is not an APM disk */
static u32 apm_block_size(gz_src *s, const u8 *b0)
{
    if (b0[0] != 'E' || b0[1] != 'R') return 0;
    u32 bs = rd16be(b0 + 2);
    u8 pm[2];
    if (bs >= 512 && bs <= 4096 && gz_vd_pow2(bs) && s->size >= 2 * (u64)bs &&
        !gz_src_read_exact(s, bs, pm, 2) && pm[0] == 'P' && pm[1] == 'M')
        return bs;
    if (s->size >= 1024 && !gz_src_read_exact(s, 512, pm, 2) && pm[0] == 'P' && pm[1] == 'M') return 512;
    return 0;
}

static int apm_skip(const u8 *t)
{
    static const char *const skip[] = { "Apple_partition_map", "Apple_Free", "Apple_Void", "Apple_Scratch" };
    for (u32 i = 0; i < GZ_COUNTOF(skip); i++) {
        u32 k = 0;
        while (skip[i][k] && skip[i][k] == (char)t[k]) k++;
        if (!skip[i][k] && (k == 32 || !t[k])) return 1;
    }
    return 0;
}

static const char *apm_ext(const u8 *t)
{
    static const struct { const char *pre, *ext; } m[] = {
        { "Apple_HFS", "hfs" }, { "Apple_APFS", "apfs" }, { "Apple_UFS", "ufs" }, { "Apple_ISO", "iso" },
        { "Linux", "linux" }, { "DOS_FAT", "fat" }, { "Windows_FAT", "fat" }, { "Windows_NTFS", "ntfs" },
    };
    for (u32 i = 0; i < GZ_COUNTOF(m); i++) {
        u32 k = 0;
        while (m[i].pre[k] && m[i].pre[k] == (char)t[k]) k++;
        if (!m[i].pre[k]) return m[i].ext;
    }
    return "img";
}

static int apm_open(gz_archive *a, gz_src *s, u32 bs, gz_ctx *c)
{
    u8 b[512];
    int r = gz_src_read_exact(s, bs, b, 512);
    if (r) return r;
    u32 n = rd32be(b + 4);
    if (!n || n > 1024) return GZ_E_FORMAT;
    for (u32 i = 1; i <= n; i++) {
        if ((u64)i * bs + 512 > s->size || gz_src_read_exact(s, (u64)i * bs, b, 512)) break;
        if (b[0] != 'P' || b[1] != 'M') break;
        if ((i & 63) == 0 && gz_cancelled(c)) return GZ_E_CANCEL;
        const u8 *type = b + 48;
        if (apm_skip(type)) continue;
        u64 off = (u64)rd32be(b + 8) * bs, len = (u64)rd32be(b + 12) * bs;
        if (!len || off >= s->size) continue;
        wname w = { {0}, 0 };
        wn_num(&w, i);
        gzch lab[32];
        u32 ln = 0;
        while (ln < 32 && b[16 + ln]) { lab[ln] = b[16 + ln] < 0x80 ? b[16 + ln] : '_'; ln++; }
        wn_label(&w, lab, ln);
        const char *ext = sniff_fs(s, off, len);
        r = add_part(a, &w, ext ? ext : apm_ext(type), off, len, PM_APM, 0);
        if (r) return r;
        u32 tl = 0, ro;
        while (tl < 32 && type[tl] >= 0x20 && type[tl] < 0x7F) tl++;
        r = gz_arc_raw_append(a, type, tl, &ro);
        if (r) return r;
        a->e[a->n - 1].aux = ro;
        a->e[a->n - 1].aux32 = tl;
    }
    gz_arc_set_type(a, "APM");
    return a->n ? GZ_OK : GZ_E_FORMAT;
}

/* ---------------- format ---------------- */

static int pm_probe(gz_src *s, const u8 *h, u32 n)
{
    if (n < 512) return 0;
    if (gpt_sector_size(s, h, n)) return 60;
    if (h[0] == 'E' && h[1] == 'R' && apm_block_size(s, h)) return 50;
    if (mbr_table_ok(h, s->size)) return 30;
    return 0;
}

static int pm_open(gz_archive *a, gz_src *s, const gz_open_opts *o, gz_ctx *c)
{
    (void)o;
    u8 sec[512];
    if (s->size < 1024) return GZ_E_FORMAT;
    int r = gz_src_read_exact(s, 0, sec, 512);
    if (r) return r;
    u32 ss = gpt_sector_size(s, sec, 512);
    if (ss) return gpt_open(a, s, ss, c);
    u32 bs = apm_block_size(s, sec);
    if (bs) return apm_open(a, s, bs, c);
    if (!mbr_table_ok(sec, s->size)) return GZ_E_FORMAT;
    r = mbr_open_table(a, s, sec, c);
    if (!r) gz_arc_set_type(a, "MBR");
    return r;
}

static int pm_extract(gz_archive *a, gz_src *s, u32 idx, gz_out *out, gz_ctx *c)
{
    return gz_extract_stored(a, s, idx, a->e[idx].off, out, c);
}

static gz_src *pm_view(gz_archive *a, gz_src *s, u32 idx)
{
    gz_entry *e = &a->e[idx];
    return gz_src_sub(s, e->off, e->usize);
}

static void pm_method(const gz_archive *a, const gz_entry *e, char *buf, u32 cap)
{
    char t[64];
    u32 k = 0;
    static const char hx[] = "0123456789ABCDEF";
    if (e->flags == PM_MBR) {
        const char *p = "MBR 0x";
        while (*p) t[k++] = *p++;
        t[k++] = hx[(e->method >> 4) & 15];
        t[k++] = hx[e->method & 15];
    } else if (e->flags == PM_GPT) {
        if (e->method < GZ_COUNTOF(k_gpt)) {
            for (const char *p = k_gpt[e->method].name; *p; p++) t[k++] = *p;
        } else if (e->aux + 16 <= a->raw_len) {
            /* type GUID as text */
            const u8 *g = a->raw + e->aux;
            static const u8 ord[16] = { 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 };
            for (u32 i = 0; i < 16; i++) {
                if (i == 4 || i == 6 || i == 8 || i == 10) t[k++] = '-';
                t[k++] = hx[g[ord[i]] >> 4];
                t[k++] = hx[g[ord[i]] & 15];
            }
        }
    } else if (e->flags == PM_APM) {
        for (u32 i = 0; i < e->aux32 && i < 32 && e->aux + i < a->raw_len; i++) t[k++] = (char)a->raw[e->aux + i];
    }
    t[k] = 0;
    gz_vd_method_str(buf, cap, t);
}

GZ_FORMAT(gz_fmt_mbr)
const gz_format gz_fmt_mbr = {
    "MBR", "mbr gpt img bin raw dsk hdd", GZ_FMT_CONTAINER | GZ_FMT_WEAK,
    pm_probe, pm_open, 0, pm_extract, 0, 0, pm_method, pm_view, 0
};
