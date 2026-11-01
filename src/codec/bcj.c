/*
 * 고깃ZIP - branch converters (BCJ filters) and the Delta filter
 *
 * Ports of the xz 5.8 liblzma "simple" filters (public domain, same output as
 * 7-Zip's Bra*.c). Each converter returns how many leading bytes are final;
 * the caller presents the rest again with more data, exactly like liblzma's
 * simple coder, so results do not depend on how the stream is chunked.
 */
#include "bcj.h"

/* ---- x86 (prev_mask state, as liblzma) ---- */

#define X86_MSB_OK(b) ((b) == 0 || (b) == 0xFF)

static size_t bcj_x86(gz_bcj *f, u8 *buf, size_t size)
{
    static const u8 mask_to_bit[5] = { 0, 1, 2, 2, 3 };
    const u32 now = f->pos;
    const int enc = f->enc;
    u32 prev_mask = f->x86_mask;
    u32 prev_pos = f->x86_prev;

    if (size < 5) return 0;
    if (now - prev_pos > 5) prev_pos = now - 5;

    const size_t limit = size - 5;
    size_t i = 0;
    while (i <= limit) {
        u32 b = buf[i];
        if ((b & 0xFE) != 0xE8) { i++; continue; }

        const u32 off = now + (u32)i - prev_pos;
        prev_pos = now + (u32)i;
        if (off > 5) {
            prev_mask = 0;
        } else {
            for (u32 k = 0; k < off; k++) {
                prev_mask &= 0x77;
                prev_mask <<= 1;
            }
        }

        b = buf[i + 4];
        if (X86_MSB_OK(b) && (prev_mask >> 1) <= 4 && (prev_mask >> 1) != 3) {
            u32 src = b << 24 | (u32)buf[i + 3] << 16 | (u32)buf[i + 2] << 8 | buf[i + 1];
            u32 dest;
            for (;;) {
                if (enc) dest = src + (now + (u32)i + 5);
                else     dest = src - (now + (u32)i + 5);
                if (!prev_mask) break;
                const u32 bi = mask_to_bit[prev_mask >> 1];
                b = (u8)(dest >> (24 - bi * 8));
                if (!X86_MSB_OK(b)) break;
                src = dest ^ ((1u << (32 - bi * 8)) - 1);
            }
            buf[i + 4] = (u8)~(((dest >> 24) & 1) - 1);
            buf[i + 3] = (u8)(dest >> 16);
            buf[i + 2] = (u8)(dest >> 8);
            buf[i + 1] = (u8)dest;
            i += 5;
            prev_mask = 0;
        } else {
            i++;
            prev_mask |= 1;
            if (X86_MSB_OK(b)) prev_mask |= 0x10;
        }
    }
    f->x86_mask = prev_mask;
    f->x86_prev = prev_pos;
    return i;
}

/* ---- PowerPC (big-endian), "bl" with AA=0 LK=1 ---- */

static size_t bcj_ppc(gz_bcj *f, u8 *buf, size_t size)
{
    const u32 now = f->pos;
    size &= ~(size_t)3;
    for (size_t i = 0; i < size; i += 4) {
        if ((buf[i] >> 2) != 0x12 || (buf[i + 3] & 3) != 1) continue;
        const u32 src = ((u32)buf[i] & 3) << 24 | (u32)buf[i + 1] << 16 |
                        (u32)buf[i + 2] << 8 | ((u32)buf[i + 3] & ~3u);
        u32 dest = f->enc ? now + (u32)i + src : src - (now + (u32)i);
        buf[i + 0] = (u8)(0x48 | ((dest >> 24) & 3));
        buf[i + 1] = (u8)(dest >> 16);
        buf[i + 2] = (u8)(dest >> 8);
        buf[i + 3] = (u8)((buf[i + 3] & 3) | dest);
    }
    return size;
}

/* ---- IA-64 bundles ---- */

static size_t bcj_ia64(gz_bcj *f, u8 *buf, size_t size)
{
    static const u8 branch_table[32] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0
    };
    const u32 now = f->pos;
    size &= ~(size_t)15;
    for (size_t i = 0; i < size; i += 16) {
        const u32 mask = branch_table[buf[i] & 0x1F];
        u32 bit_pos = 5;
        for (u32 slot = 0; slot < 3; slot++, bit_pos += 41) {
            if (!((mask >> slot) & 1)) continue;
            const size_t byte_pos = bit_pos >> 3;
            const u32 bit_res = bit_pos & 7;
            u64 instr = 0;
            for (u32 j = 0; j < 6; j++) instr |= (u64)buf[i + j + byte_pos] << (8 * j);
            u64 norm = instr >> bit_res;
            if (((norm >> 37) & 0xF) != 0x5 || ((norm >> 9) & 0x7) != 0) continue;
            u32 src = (u32)((norm >> 13) & 0xFFFFF);
            src |= (u32)((norm >> 36) & 1) << 20;
            src <<= 4;
            u32 dest = f->enc ? now + (u32)i + src : src - (now + (u32)i);
            dest >>= 4;
            norm &= ~((u64)0x8FFFFF << 13);
            norm |= (u64)(dest & 0xFFFFF) << 13;
            norm |= (u64)(dest & 0x100000) << (36 - 20);
            instr &= (1u << bit_res) - 1;
            instr |= norm << bit_res;
            for (u32 j = 0; j < 6; j++) buf[i + j + byte_pos] = (u8)(instr >> (8 * j));
        }
    }
    return size;
}

/* ---- ARM (little-endian), BL ---- */

static size_t bcj_arm(gz_bcj *f, u8 *buf, size_t size)
{
    const u32 now = f->pos;
    size &= ~(size_t)3;
    for (size_t i = 0; i < size; i += 4) {
        if (buf[i + 3] != 0xEB) continue;
        u32 src = ((u32)buf[i + 2] << 16 | (u32)buf[i + 1] << 8 | buf[i]) << 2;
        u32 dest = f->enc ? now + (u32)i + 8 + src : src - (now + (u32)i + 8);
        dest >>= 2;
        buf[i + 2] = (u8)(dest >> 16);
        buf[i + 1] = (u8)(dest >> 8);
        buf[i + 0] = (u8)dest;
    }
    return size;
}

/* ---- ARM Thumb, BL pairs ---- */

static size_t bcj_armt(gz_bcj *f, u8 *buf, size_t size)
{
    const u32 now = f->pos;
    if (size < 4) return 0;
    size -= 4;
    size_t i;
    for (i = 0; i <= size; i += 2) {
        if ((buf[i + 1] & 0xF8) != 0xF0 || (buf[i + 3] & 0xF8) != 0xF8) continue;
        u32 src = ((u32)buf[i + 1] & 7) << 19 | (u32)buf[i] << 11 |
                  ((u32)buf[i + 3] & 7) << 8 | buf[i + 2];
        src <<= 1;
        u32 dest = f->enc ? now + (u32)i + 4 + src : src - (now + (u32)i + 4);
        dest >>= 1;
        buf[i + 1] = (u8)(0xF0 | ((dest >> 19) & 7));
        buf[i + 0] = (u8)(dest >> 11);
        buf[i + 3] = (u8)(0xF8 | ((dest >> 8) & 7));
        buf[i + 2] = (u8)dest;
        i += 2;
    }
    return i;
}

/* ---- SPARC, call ---- */

static size_t bcj_sparc(gz_bcj *f, u8 *buf, size_t size)
{
    const u32 now = f->pos;
    size &= ~(size_t)3;
    for (size_t i = 0; i < size; i += 4) {
        if (!((buf[i] == 0x40 && (buf[i + 1] & 0xC0) == 0x00) ||
              (buf[i] == 0x7F && (buf[i + 1] & 0xC0) == 0xC0))) continue;
        u32 src = rd32be(buf + i) << 2;
        u32 dest = f->enc ? now + (u32)i + src : src - (now + (u32)i);
        dest >>= 2;
        dest = (((0 - ((dest >> 22) & 1)) << 22) & 0x3FFFFFFF) | (dest & 0x3FFFFF) | 0x40000000;
        wr32be(buf + i, dest);
    }
    return size;
}

/* ---- ARM64, BL and ADRP ---- */

static size_t bcj_arm64(gz_bcj *f, u8 *buf, size_t size)
{
    const u32 now = f->pos;
    const int enc = f->enc;
    size &= ~(size_t)3;
    for (size_t i = 0; i < size; i += 4) {
        u32 pc = now + (u32)i;
        u32 ins = rd32(buf + i);
        if ((ins >> 26) == 0x25) {                           /* BL */
            const u32 src = ins;
            pc >>= 2;
            if (!enc) pc = 0u - pc;
            wr32(buf + i, 0x94000000u | ((src + pc) & 0x03FFFFFF));
        } else if ((ins & 0x9F000000u) == 0x90000000u) {     /* ADRP */
            const u32 src = ((ins >> 29) & 3) | ((ins >> 3) & 0x001FFFFC);
            if ((src + 0x00020000) & 0x001C0000) continue;   /* only +-512 MiB */
            ins &= 0x9000001Fu;
            pc >>= 12;
            if (!enc) pc = 0u - pc;
            const u32 dest = src + pc;
            ins |= (dest & 3) << 29;
            ins |= (dest & 0x0003FFFC) << 3;
            ins |= (0u - (dest & 0x00020000)) & 0x00E00000;
            wr32(buf + i, ins);
        }
    }
    return size;
}

/* ---- RISC-V (xz 5.6 / 7-Zip 24): JAL, AUIPC + inst2 pairs ---- */

#define NOT_AUIPC_PAIR(auipc, inst2) ((((auipc) << 8) ^ ((inst2) - 3)) & 0xF8003)
#define NOT_SPECIAL_AUIPC(auipc, inst2_rs1) \
    ((u32)(((auipc) - 0x3117) << 18) >= ((inst2_rs1) & 0x1D))

static size_t bcj_riscv_enc(gz_bcj *f, u8 *buf, size_t size)
{
    const u32 now = f->pos;
    if (size < 8) return 0;
    size -= 8;
    size_t i;
    for (i = 0; i <= size; i += 2) {
        u32 inst = buf[i];
        if (inst == 0xEF) {                                  /* JAL */
            const u32 b1 = buf[i + 1];
            if (b1 & 0x0D) continue;                         /* rd = x1 / x5 only */
            const u32 b2 = buf[i + 2], b3 = buf[i + 3];
            u32 addr = ((b1 & 0xF0) << 8) | ((b2 & 0x0F) << 16) | ((b2 & 0x10) << 7) |
                       ((b2 & 0xE0) >> 4) | ((b3 & 0x7F) << 4) | ((b3 & 0x80) << 13);
            addr += now + (u32)i;
            buf[i + 1] = (u8)((b1 & 0x0F) | ((addr >> 13) & 0xF0));
            buf[i + 2] = (u8)(addr >> 9);
            buf[i + 3] = (u8)(addr >> 1);
            i += 4 - 2;
        } else if ((inst & 0x7F) == 0x17) {                  /* AUIPC */
            inst |= (u32)buf[i + 1] << 8 | (u32)buf[i + 2] << 16 | (u32)buf[i + 3] << 24;
            if (inst & 0xE80) {                              /* rd != x0, x2 */
                const u32 inst2 = rd32(buf + i + 4);
                if (NOT_AUIPC_PAIR(inst, inst2)) { i += 6 - 2; continue; }
                u32 addr = inst & 0xFFFFF000u;
                addr += (inst2 >> 20) - ((inst2 >> 19) & 0x1000);
                addr += now + (u32)i;
                wr32(buf + i, 0x17 | (2 << 7) | (inst2 << 12));
                wr32be(buf + i + 4, addr);
            } else {                                         /* rd == x0 or x2 */
                const u32 fake_rs1 = inst >> 27;
                if (NOT_SPECIAL_AUIPC(inst, fake_rs1)) { i += 4 - 2; continue; }
                const u32 fake_addr = rd32(buf + i + 4);
                const u32 fake_inst2 = (inst >> 12) | (fake_addr << 20);
                wr32(buf + i, 0x17 | (fake_rs1 << 7) | (fake_addr & 0xFFFFF000u));
                wr32(buf + i + 4, fake_inst2);
            }
            i += 8 - 2;
        }
    }
    return i;
}

static size_t bcj_riscv_dec(gz_bcj *f, u8 *buf, size_t size)
{
    const u32 now = f->pos;
    if (size < 8) return 0;
    size -= 8;
    size_t i;
    for (i = 0; i <= size; i += 2) {
        u32 inst = buf[i];
        if (inst == 0xEF) {                                  /* JAL */
            const u32 b1 = buf[i + 1];
            if (b1 & 0x0D) continue;
            const u32 b2 = buf[i + 2], b3 = buf[i + 3];
            u32 addr = ((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1);
            addr -= now + (u32)i;
            buf[i + 1] = (u8)((b1 & 0x0F) | ((addr >> 8) & 0xF0));
            buf[i + 2] = (u8)(((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0));
            buf[i + 3] = (u8)(((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80));
            i += 4 - 2;
        } else if ((inst & 0x7F) == 0x17) {                  /* AUIPC */
            u32 inst2;
            inst |= (u32)buf[i + 1] << 8 | (u32)buf[i + 2] << 16 | (u32)buf[i + 3] << 24;
            if (inst & 0xE80) {
                inst2 = rd32(buf + i + 4);
                if (NOT_AUIPC_PAIR(inst, inst2)) { i += 6 - 2; continue; }
                /* undo the encoder's "fake pair" form */
                u32 addr = (inst & 0xFFFFF000u) + (inst2 >> 20);
                inst = 0x17 | (2 << 7) | (inst2 << 12);
                inst2 = addr;
            } else {
                const u32 inst2_rs1 = inst >> 27;
                if (NOT_SPECIAL_AUIPC(inst, inst2_rs1)) { i += 4 - 2; continue; }
                u32 addr = rd32be(buf + i + 4);
                addr -= now + (u32)i;
                inst2 = (inst >> 12) | (addr << 20);
                inst = 0x17 | (inst2_rs1 << 7) | ((addr + 0x800) & 0xFFFFF000u);
            }
            wr32(buf + i, inst);
            wr32(buf + i + 4, inst2);
            i += 8 - 2;
        }
    }
    return i;
}

/* ---- Delta: byte i -/+ byte i - dist ---- */

static size_t bcj_delta(gz_bcj *f, u8 *buf, size_t n)
{
    const u32 dist = f->dist;
    u8 *h = f->hist;              /* h[(p + j) & 255]: the byte j positions back */
    const u8 p = f->dpos;
    const size_t head = n < dist ? n : dist;
    const size_t k = n < 256 ? n : 256;
    if (f->enc) {
        u8 old[256];
        __builtin_memcpy(old, h, 256);
        for (size_t i = n - k; i < n; i++) h[(u8)(p - i)] = buf[i];
        for (size_t i = n; i-- > head;) buf[i] = (u8)(buf[i] - buf[i - dist]);
        for (size_t i = 0; i < head; i++) buf[i] = (u8)(buf[i] - old[(u8)(p + dist - i)]);
    } else {
        for (size_t i = 0; i < head; i++) buf[i] = (u8)(buf[i] + h[(u8)(p + dist - i)]);
        for (size_t i = head; i < n; i++) buf[i] = (u8)(buf[i] + buf[i - dist]);
        for (size_t i = n - k; i < n; i++) h[(u8)(p - i)] = buf[i];
    }
    f->dpos = (u8)(p - n);
    return n;
}

/* ---- dispatch ---- */

void gz_bcj_init(gz_bcj *f, int type, u32 param, int encoding)
{
    __builtin_memset(f, 0, sizeof *f);
    f->type = (u8)type;
    f->enc = encoding ? 1 : 0;
    if (type == GZ_BCJ_DELTA) {
        f->dist = param < 1 ? 1 : param > 256 ? 256 : param;
    } else {
        f->pos = param;
        f->x86_prev = param - 5;     /* liblzma: prev_pos = -5 relative to the start */
    }
}

size_t gz_bcj_code(gz_bcj *f, u8 *buf, size_t n)
{
    size_t done;
    switch (f->type) {
    case GZ_BCJ_X86:   done = bcj_x86(f, buf, n); break;
    case GZ_BCJ_PPC:   done = bcj_ppc(f, buf, n); break;
    case GZ_BCJ_IA64:  done = bcj_ia64(f, buf, n); break;
    case GZ_BCJ_ARM:   done = bcj_arm(f, buf, n); break;
    case GZ_BCJ_ARMT:  done = bcj_armt(f, buf, n); break;
    case GZ_BCJ_SPARC: done = bcj_sparc(f, buf, n); break;
    case GZ_BCJ_ARM64: done = bcj_arm64(f, buf, n); break;
    case GZ_BCJ_RISCV: done = f->enc ? bcj_riscv_enc(f, buf, n) : bcj_riscv_dec(f, buf, n); break;
    case GZ_BCJ_DELTA: return bcj_delta(f, buf, n);
    default:           return n;          /* unknown type: copy */
    }
    f->pos += (u32)done;
    return done;
}

u32 gz_bcj_align(int type)
{
    switch (type) {
    case GZ_BCJ_ARMT: case GZ_BCJ_RISCV: return 2;
    case GZ_BCJ_PPC: case GZ_BCJ_ARM: case GZ_BCJ_SPARC: case GZ_BCJ_ARM64: return 4;
    case GZ_BCJ_IA64: return 16;
    }
    return 1;
}

int gz_bcj_from_xz_id(u64 id)
{
    switch (id) {
    case 0x03: return GZ_BCJ_DELTA;
    case 0x04: return GZ_BCJ_X86;
    case 0x05: return GZ_BCJ_PPC;
    case 0x06: return GZ_BCJ_IA64;
    case 0x07: return GZ_BCJ_ARM;
    case 0x08: return GZ_BCJ_ARMT;
    case 0x09: return GZ_BCJ_SPARC;
    case 0x0A: return GZ_BCJ_ARM64;
    case 0x0B: return GZ_BCJ_RISCV;
    }
    return GZ_BCJ_NONE;
}

int gz_bcj_from_7z_id(u64 id)
{
    switch (id) {
    case 0x03:       return GZ_BCJ_DELTA;
    case 0x03030103: return GZ_BCJ_X86;
    case 0x03030205: return GZ_BCJ_PPC;
    case 0x03030401: return GZ_BCJ_IA64;
    case 0x03030501: return GZ_BCJ_ARM;
    case 0x03030701: return GZ_BCJ_ARMT;
    case 0x03030805: return GZ_BCJ_SPARC;
    case 0x0A:       return GZ_BCJ_ARM64;
    case 0x0B:       return GZ_BCJ_RISCV;
    }
    return GZ_BCJ_NONE;
}

const char *gz_bcj_name(int type)
{
    static const char *const names[GZ_BCJ_COUNT] = {
        "", "BCJ", "PPC", "IA64", "ARM", "ARMT", "SPARC", "ARM64", "RISCV", "Delta"
    };
    return type > 0 && type < GZ_BCJ_COUNT ? names[type] : "?";
}

/* ---- push adapter ---- */

void gz_filter_push_init(gz_filter_push *p, int type, u32 param, int encoding,
                         int (*next)(void *ctx, const u8 *p, size_t n), void *next_ctx)
{
    gz_bcj_init(&p->f, type, param, encoding);
    p->next = next;
    p->next_ctx = next_ctx;
    p->n = 0;
}

int gz_filter_push_write(void *ctx, const u8 *data, size_t n)
{
    gz_filter_push *p = (gz_filter_push *)ctx;
    while (n) {
        size_t k = GZ_FILTER_PUSH_BUF - p->n;
        if (k > n) k = n;
        __builtin_memcpy(p->buf + p->n, data, k);
        p->n += (u32)k;
        data += k;
        n -= k;
        if (p->n < GZ_FILTER_PUSH_BUF) break;
        size_t done = gz_bcj_code(&p->f, p->buf, p->n);
        int r = done ? p->next(p->next_ctx, p->buf, done) : GZ_OK;
        __builtin_memmove(p->buf, p->buf + done, p->n - done);
        p->n -= (u32)done;
        if (r) return r;
    }
    return GZ_OK;
}

int gz_filter_push_finish(gz_filter_push *p)
{
    u32 n = p->n;
    p->n = 0;
    if (!n) return GZ_OK;
    gz_bcj_code(&p->f, p->buf, n);
    return p->next(p->next_ctx, p->buf, n);
}
