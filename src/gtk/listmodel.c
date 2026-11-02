/*
 * 고깃ZIP GTK - file list model
 *
 * A flat, read-only GtkTreeModel over the rows of one archive folder. Rows are
 * (kind, index) pairs into the archive's folder / entry arrays; every cell is
 * produced on demand, so only the visible rows cost anything and a folder with
 * hundreds of thousands of entries opens instantly (the view runs in
 * fixed-height mode). A new model is made for every folder change and sort.
 */
#include "app.h"
#include <string.h>

struct _GzList {
    GObject parent;
    gint stamp;
    gz_archive *a;
    gz_lrow *rows;
    u32 n;
};

static void gz_list_iface_init(GtkTreeModelIface *iface);
G_DEFINE_TYPE_WITH_CODE(GzList, gz_list, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(GTK_TYPE_TREE_MODEL, gz_list_iface_init))

static void gz_list_finalize(GObject *o)
{
    GzList *m = GZ_LIST(o);
    g_free(m->rows);
    G_OBJECT_CLASS(gz_list_parent_class)->finalize(o);
}

static void gz_list_class_init(GzListClass *k) { G_OBJECT_CLASS(k)->finalize = gz_list_finalize; }
static void gz_list_init(GzList *m) { m->stamp = g_random_int(); }

GzList *gz_list_new(gz_archive *a, gz_lrow *rows, u32 n)
{
    GzList *m = g_object_new(GZ_TYPE_LIST, NULL);
    m->a = a;
    m->rows = rows;
    m->n = n;
    return m;
}

const gz_lrow *gz_list_rows(GzList *m, u32 *n)
{
    *n = m->n;
    return m->rows;
}

/* ---------------- GtkTreeModel ---------------- */

static GtkTreeModelFlags lm_flags(GtkTreeModel *t) { return GTK_TREE_MODEL_LIST_ONLY | GTK_TREE_MODEL_ITERS_PERSIST; }
static gint lm_ncols(GtkTreeModel *t) { return LC_COUNT; }
static GType lm_coltype(GtkTreeModel *t, gint c) { return c == LC_ICON ? G_TYPE_ICON : G_TYPE_STRING; }

static gboolean set_iter(GzList *m, GtkTreeIter *it, guint i)
{
    if (i >= m->n) { it->stamp = 0; return FALSE; }
    it->stamp = m->stamp;
    it->user_data = GUINT_TO_POINTER(i);
    it->user_data2 = it->user_data3 = NULL;
    return TRUE;
}

static gboolean lm_get_iter(GtkTreeModel *t, GtkTreeIter *it, GtkTreePath *p)
{
    GzList *m = GZ_LIST(t);
    if (gtk_tree_path_get_depth(p) != 1) return FALSE;
    gint i = gtk_tree_path_get_indices(p)[0];
    return i >= 0 && set_iter(m, it, (guint)i);
}

static GtkTreePath *lm_get_path(GtkTreeModel *t, GtkTreeIter *it)
{
    return gtk_tree_path_new_from_indices((gint)GPOINTER_TO_UINT(it->user_data), -1);
}

static GIcon *s_folder_icon;

static void lm_get_value(GtkTreeModel *t, GtkTreeIter *it, gint col, GValue *v)
{
    GzList *m = GZ_LIST(t);
    guint i = GPOINTER_TO_UINT(it->user_data);
    g_value_init(v, lm_coltype(t, col));
    if (it->stamp != m->stamp || i >= m->n) return;
    const gz_lrow *r = &m->rows[i];
    gz_archive *a = m->a;
    char b[96];
    b[0] = 0;
    if (r->kind != 2) {
        const gz_folder *f = r->kind == 1 ? &a->f[r->idx] : NULL;
        switch (col) {
        case LC_ICON:
            if (!s_folder_icon) s_folder_icon = g_themed_icon_new_with_default_fallbacks("folder");
            g_value_set_object(v, s_folder_icon);
            return;
        case LC_NAME: if (f) g_value_take_string(v, w2u(f->base)); else g_value_set_string(v, ".."); return;
        case LC_TYPE: g_value_set_string(v, TR(f ? STR_FOLDER : STR_PARENT)); return;
        case LC_MTIME:
            if (f && f->mtime_kind) {
                gz_entry tmp;
                memset(&tmp, 0, sizeof tmp);
                tmp.mtime = f->mtime;
                tmp.mtime_kind = f->mtime_kind;
                fmt_filetime(b, sizeof b, gz_entry_time(&tmp));
            }
            break;
        }
        g_value_set_string(v, b);
        return;
    }
    const gz_entry *e = &a->e[r->idx];
    switch (col) {
    case LC_ICON: {
        GIcon *ic = NULL;
        type_desc(e->base, &ic);
        g_value_set_object(v, ic);
        return;
    }
    case LC_NAME: {
        char *s = w2u(e->base);
        if (e->enc) {
            char *t = g_strconcat(s, " *", NULL);
            g_free(s);
            s = t;
        }
        g_value_take_string(v, s);
        return;
    }
    case LC_SIZE: if (e->usize != GZ_SIZE_UNKNOWN) gz_ui_fmt_kb(b, sizeof b, e->usize); break;
    case LC_PACKED: if (e->csize != GZ_SIZE_UNKNOWN) gz_ui_fmt_kb(b, sizeof b, e->csize); break;
    case LC_TYPE: g_value_set_string(v, e->is_link ? TR(STR_LINK) : type_desc(e->base, NULL)); return;
    case LC_MTIME: fmt_filetime(b, sizeof b, gz_entry_time(e)); break;
    case LC_RATIO:
        if (e->usize != GZ_SIZE_UNKNOWN && e->csize != GZ_SIZE_UNKNOWN) gz_ui_fmt_percent(b, sizeof b, e->csize, e->usize);
        break;
    case LC_METHOD: {
        gzch w[96];
        gz_arc_method(a, e, w, 96);
        char *s = w2u(w);
        g_strlcpy(b, s, sizeof b);
        g_free(s);
        if (e->enc == GZ_ENC_ZIPCRYPTO) g_strlcat(b, " · ZipCrypto", sizeof b);
        else if (e->enc == GZ_ENC_AES && e->aes_strength >= 1 && e->aes_strength <= 3) {
            char t[24];
            g_snprintf(t, sizeof t, " · AES-%d", 64 + 64 * e->aes_strength);
            g_strlcat(b, t, sizeof b);
        } else if (e->enc && !strstr(b, "AES")) {
            g_strlcat(b, " · AES", sizeof b);
        }
        break;
    }
    case LC_CRC: if (e->has_crc && !e->is_dir) gz_ui_fmt_hex32(b, sizeof b, e->crc); break;
    }
    g_value_set_string(v, b);
}

static gboolean lm_next(GtkTreeModel *t, GtkTreeIter *it)
{
    return set_iter(GZ_LIST(t), it, GPOINTER_TO_UINT(it->user_data) + 1);
}

static gboolean lm_prev(GtkTreeModel *t, GtkTreeIter *it)
{
    guint i = GPOINTER_TO_UINT(it->user_data);
    if (!i) { it->stamp = 0; return FALSE; }
    return set_iter(GZ_LIST(t), it, i - 1);
}

static gboolean lm_children(GtkTreeModel *t, GtkTreeIter *it, GtkTreeIter *parent)
{
    if (parent) { it->stamp = 0; return FALSE; }
    return set_iter(GZ_LIST(t), it, 0);
}

static gboolean lm_has_child(GtkTreeModel *t, GtkTreeIter *it) { return FALSE; }
static gint lm_nchildren(GtkTreeModel *t, GtkTreeIter *it) { return it ? 0 : (gint)GZ_LIST(t)->n; }

static gboolean lm_nth(GtkTreeModel *t, GtkTreeIter *it, GtkTreeIter *parent, gint n)
{
    if (parent || n < 0) { it->stamp = 0; return FALSE; }
    return set_iter(GZ_LIST(t), it, (guint)n);
}

static gboolean lm_parent(GtkTreeModel *t, GtkTreeIter *it, GtkTreeIter *child) { it->stamp = 0; return FALSE; }

static void gz_list_iface_init(GtkTreeModelIface *f)
{
    f->get_flags = lm_flags;
    f->get_n_columns = lm_ncols;
    f->get_column_type = lm_coltype;
    f->get_iter = lm_get_iter;
    f->get_path = lm_get_path;
    f->get_value = lm_get_value;
    f->iter_next = lm_next;
    f->iter_previous = lm_prev;
    f->iter_children = lm_children;
    f->iter_has_child = lm_has_child;
    f->iter_n_children = lm_nchildren;
    f->iter_nth_child = lm_nth;
    f->iter_parent = lm_parent;
}

/* ---------------- file types (icon + description per extension) ---------------- */

typedef struct { GIcon *icon; char *desc; } type_info;
static GHashTable *s_types;

static void type_free(gpointer p)
{
    type_info *t = p;
    if (t->icon) g_object_unref(t->icon);
    g_free(t->desc);
    g_free(t);
}

void types_clear(void)
{
    if (s_types) g_hash_table_destroy(s_types);
    s_types = NULL;
}

const char *type_desc(const gzch *name, GIcon **icon)
{
    /* key: lower-case extension (ASCII only; anything else -> generic) */
    const gzch *dot = gz_wcsrchr(name, '.');
    char key[20];
    size_t n = 0;
    if (dot && dot != name) {
        for (const gzch *p = dot + 1; *p && n + 1 < sizeof key; p++) {
            gzch c = *p;
            if (c >= 128) { n = 0; break; }
            key[n++] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
        }
        if (dot[1 + n]) n = 0;
    }
    key[n] = 0;
    if (!s_types) s_types = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, type_free);
    type_info *t = g_hash_table_lookup(s_types, key);
    if (!t) {
        t = g_new0(type_info, 1);
        char probe[32];
        g_snprintf(probe, sizeof probe, "file.%s", key);
        gboolean unsure = FALSE;
        char *ct = n ? g_content_type_guess(probe, NULL, 0, &unsure) : NULL;
        if (ct && !g_content_type_is_unknown(ct)) {
            t->icon = g_content_type_get_icon(ct);
            t->desc = g_content_type_get_description(ct);
        }
        if (!t->icon) t->icon = g_themed_icon_new_with_default_fallbacks("text-x-generic");
        if (!t->desc || !*t->desc) {
            g_free(t->desc);
            if (n) {
                char *up = g_ascii_strup(key, -1);
                t->desc = g_strdup_printf("%s %s", up, TR(STR_FILE));
                g_free(up);
            } else {
                t->desc = g_strdup(TR(STR_FILE));
            }
        }
        g_free(ct);
        g_hash_table_insert(s_types, g_strdup(key), t);
    }
    if (icon) *icon = t->icon;
    return t->desc;
}

/* ---------------- sorting ---------------- */

static gzch fold(gzch c) { return c >= 'A' && c <= 'Z' ? (gzch)(c + 32) : c; }

/* natural order: case-insensitive, digit runs by value ("a2" < "a10") */
int name_cmp_natural(const gzch *a, const gzch *b)
{
    for (;;) {
        gzch x = *a, y = *b;
        if (!x || !y) return (x != 0) - (y != 0);
        if (x >= '0' && x <= '9' && y >= '0' && y <= '9') {
            const gzch *p = a, *q = b;
            while (*p == '0') p++;
            while (*q == '0') q++;
            const gzch *pe = p, *qe = q;
            while (*pe >= '0' && *pe <= '9') pe++;
            while (*qe >= '0' && *qe <= '9') qe++;
            if (pe - p != qe - q) return pe - p < qe - q ? -1 : 1;
            for (; p < pe; p++, q++) if (*p != *q) return *p < *q ? -1 : 1;
            /* equal values: fewer leading zeros first */
            if ((pe - a) != (qe - b)) return (pe - a) < (qe - b) ? -1 : 1;
            a = pe;
            b = qe;
            continue;
        }
        x = fold(x);
        y = fold(y);
        if (x != y) return x < y ? -1 : 1;
        a++;
        b++;
    }
}

typedef struct {
    gz_archive *a;
    int col, desc;
    const char **key;           /* per-row text keys (type, method) or NULL */
} sort_ctx;

static int u64cmp(u64 a, u64 b) { return a < b ? -1 : a > b; }

static u64 ratio_key(const gz_entry *e)
{
    if (e->usize == GZ_SIZE_UNKNOWN || e->csize == GZ_SIZE_UNKNOWN || !e->usize) return 0;
    return e->csize > (~(u64)0) / 1000 ? e->csize / (e->usize / 1000 + 1) : e->csize * 1000 / e->usize;
}

static int row_cmp(const sort_ctx *s, const gz_lrow *x, const gz_lrow *y, u32 ix, u32 iy)
{
    if (x->kind != y->kind) return (int)x->kind - (int)y->kind;     /* "..", folders, files */
    if (x->kind == 0) return 0;
    gz_archive *a = s->a;
    int r = 0;
    const gzch *nx, *ny;
    if (x->kind == 2) {
        const gz_entry *ex = &a->e[x->idx], *ey = &a->e[y->idx];
        nx = ex->base;
        ny = ey->base;
        switch (s->col) {
        case LC_SIZE: r = u64cmp(ex->usize, ey->usize); break;
        case LC_PACKED: r = u64cmp(ex->csize, ey->csize); break;
        case LC_MTIME: r = u64cmp(gz_entry_time(ex), gz_entry_time(ey)); break;
        case LC_RATIO: r = u64cmp(ratio_key(ex), ratio_key(ey)); break;
        case LC_CRC: r = u64cmp(ex->has_crc ? ex->crc : 0, ey->has_crc ? ey->crc : 0); break;
        case LC_TYPE: case LC_METHOD: if (s->key) r = strcmp(s->key[ix], s->key[iy]); break;
        }
    } else {
        nx = a->f[x->idx].base;
        ny = a->f[y->idx].base;
        if (s->col == LC_MTIME) r = u64cmp(a->f[x->idx].mtime, a->f[y->idx].mtime);
    }
    if (!r) r = name_cmp_natural(nx, ny);
    return s->desc ? -r : r;
}

/* stable merge sort of rows (with their keys) */
void gz_list_sort(gz_archive *a, gz_lrow *rows, u32 n, int col, int desc)
{
    if (n < 2) return;
    sort_ctx s = { a, col, desc, NULL };
    GHashTable *keys = NULL;      /* text -> collation key, shared by equal texts */
    if (col == LC_TYPE || col == LC_METHOD) {
        keys = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        s.key = g_new(const char *, n);
        for (u32 i = 0; i < n; i++) {
            const gz_lrow *r = &rows[i];
            if (r->kind != 2) { s.key[i] = ""; continue; }
            const gz_entry *e = &a->e[r->idx];
            char *txt;
            if (col == LC_TYPE) {
                txt = g_strdup(e->is_link ? TR(STR_LINK) : type_desc(e->base, NULL));
            } else {
                gzch w[96];
                gz_arc_method(a, e, w, 96);
                txt = w2u(w);
            }
            char *k = g_hash_table_lookup(keys, txt);
            if (!k) {
                k = g_utf8_collate_key(txt, -1);
                g_hash_table_insert(keys, txt, k);
            } else {
                g_free(txt);
            }
            s.key[i] = k;
        }
    }
    /* sort an index permutation so the keys stay attached */
    u32 *idx = g_new(u32, n), *tmp = g_new(u32, n);
    for (u32 i = 0; i < n; i++) idx[i] = i;
    for (u32 w = 1; w < n; w *= 2) {
        for (u32 i = 0; i < n; i += 2 * w) {
            u32 mid = i + w < n ? i + w : n, hi = i + 2 * w < n ? i + 2 * w : n, p = i, q = mid, k = i;
            while (p < mid && q < hi)
                tmp[k++] = row_cmp(&s, &rows[idx[q]], &rows[idx[p]], idx[q], idx[p]) < 0 ? idx[q++] : idx[p++];
            while (p < mid) tmp[k++] = idx[p++];
            while (q < hi) tmp[k++] = idx[q++];
        }
        u32 *t = idx; idx = tmp; tmp = t;
    }
    gz_lrow *out = g_new(gz_lrow, n);
    for (u32 i = 0; i < n; i++) out[i] = rows[idx[i]];
    memcpy(rows, out, (size_t)n * sizeof *rows);
    g_free(out);
    g_free(idx);
    g_free(tmp);
    if (keys) g_hash_table_destroy(keys);
    g_free(s.key);
}
