/*
 * 고깃ZIP macOS - main window
 *
 *  ┌──────────────────────────────────────────────────────────────┐
 *  │ [열기] [풀기] [새로 압축]  [테스트] [정보]  [코드 페이지]   [설정] │  NSToolbar
 *  │ [↑]  archive.zip › 문서 › inner.tar › 사진                    │  NSPathControl
 *  │ folder tree │ file list (view-based NSTableView over a C row array) │
 *  │ 파일 12개, 폴더 3개 · 원본 …                AVX2 엔진 · 8스레드 │  status bar
 *  └──────────────────────────────────────────────────────────────┘
 * Without an archive the browser is replaced by the welcome view (drop zone,
 * recent archives). Nested archives (double-click on an archive inside the
 * archive) form a stack of levels shown in the path control; "up" at the root
 * of a level goes back to the folder of the outer archive.
 *
 * The list's rows are (kind, index) pairs into the archive's folder / entry
 * arrays; cells are produced on demand for the visible rows only, so folders
 * with 100k+ entries open at once. Sorting is a stable C merge sort.
 */
#import "app.h"
#import <CoreServices/CoreServices.h>

enum { X_DIALOG = 0, X_HERE, X_SMART, X_SELECTED };
#define MAX_NEST 16

typedef struct { u8 kind; u8 pad[3]; i32 idx; } gz_lrow;      /* kind 0 "..", 1 folder, 2 file */

enum { COL_NAME = 0, COL_SIZE, COL_PACKED, COL_TYPE, COL_MTIME, COL_RATIO, COL_METHOD, COL_CRC, COL_COUNT };
static NSString *const k_cols[COL_COUNT] = { @"name", @"size", @"packed", @"type", @"mtime", @"ratio", @"method", @"crc" };

static int colIndex(NSString *ident)
{
    for (int c = 0; c < COL_COUNT; c++)
        if ([k_cols[c] isEqualToString:ident]) return c;
    return -1;
}

static NSColor *accentRed(void) { return [NSColor colorWithSRGBRed:229 / 255.0 green:72 / 255.0 blue:77 / 255.0 alpha:1]; }
static BOOL busy(void) { return [GZRun activeCount] > 0; }

/* the shared tooltips name the Windows / Linux shortcuts: say the Mac ones */
static NSString *macTip(int sid)
{
    NSString *s = TR(sid);
    s = [s stringByReplacingOccurrencesOfString:@"Ctrl+" withString:@"⌘"];
    s = [s stringByReplacingOccurrencesOfString:@"Alt+Enter" withString:@"⌘I"];
    return [s stringByReplacingOccurrencesOfString:@"Backspace" withString:@"⌘↑"];
}

/* ======================================================================
 * sorting (stable merge sort of an index permutation)
 * ====================================================================== */

typedef struct {
    const gz_archive *a;
    int col, desc;
    const u32 *rank;               /* per-row collation rank of the text columns, or NULL */
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
    const gz_archive *a = s->a;
    int r = 0;
    const gzch *nx, *ny;
    if (x->kind == 2) {
        const gz_entry *ex = &a->e[x->idx], *ey = &a->e[y->idx];
        nx = ex->base;
        ny = ey->base;
        switch (s->col) {
        case COL_SIZE: r = u64cmp(ex->usize, ey->usize); break;
        case COL_PACKED: r = u64cmp(ex->csize, ey->csize); break;
        case COL_MTIME: r = u64cmp(gz_entry_time(ex), gz_entry_time(ey)); break;
        case COL_RATIO: r = u64cmp(ratio_key(ex), ratio_key(ey)); break;
        case COL_CRC: r = u64cmp(ex->has_crc ? ex->crc : 0, ey->has_crc ? ey->crc : 0); break;
        case COL_TYPE: case COL_METHOD: if (s->rank) r = u64cmp(s->rank[ix], s->rank[iy]); break;
        }
    } else {
        nx = a->f[x->idx].base;
        ny = a->f[y->idx].base;
        if (s->col == COL_MTIME) r = u64cmp(a->f[x->idx].mtime, a->f[y->idx].mtime);
    }
    if (!r) r = gzNameCmpNatural(nx, ny);
    return s->desc ? -r : r;
}

static void sort_rows(gz_lrow *rows, u32 n, const sort_ctx *s)
{
    if (n < 2) return;
    u32 *idx = (u32 *)malloc((size_t)n * sizeof(u32)), *tmp = (u32 *)malloc((size_t)n * sizeof(u32));
    gz_lrow *out = (gz_lrow *)malloc((size_t)n * sizeof(gz_lrow));
    if (!idx || !tmp || !out) { free(idx); free(tmp); free(out); return; }
    for (u32 i = 0; i < n; i++) idx[i] = i;
    for (u32 w = 1; w < n; w *= 2) {
        for (u32 i = 0; i < n; i += 2 * w) {
            u32 mid = i + w < n ? i + w : n, hi = i + 2 * w < n ? i + 2 * w : n, p = i, q = mid, k = i;
            while (p < mid && q < hi)
                tmp[k++] = row_cmp(s, &rows[idx[q]], &rows[idx[p]], idx[q], idx[p]) < 0 ? idx[q++] : idx[p++];
            while (p < mid) tmp[k++] = idx[p++];
            while (q < hi) tmp[k++] = idx[q++];
        }
        u32 *t = idx;
        idx = tmp;
        tmp = t;
        if (w > n / 2) break;
    }
    for (u32 i = 0; i < n; i++) out[i] = rows[idx[i]];
    memcpy(rows, out, (size_t)n * sizeof *rows);
    free(out);
    free(idx);
    free(tmp);
}

static NSString *methodText(const gz_archive *a, const gz_entry *e)
{
    gzch w[96];
    gz_arc_method(a, e, w, 96);
    NSMutableString *s = [gzNS(w) mutableCopy];
    if (e->enc == GZ_ENC_ZIPCRYPTO) [s appendString:@" · ZipCrypto"];
    else if (e->enc == GZ_ENC_AES && e->aes_strength >= 1 && e->aes_strength <= 3)
        [s appendFormat:@" · AES-%d", 64 + 64 * e->aes_strength];
    else if (e->enc && [s rangeOfString:@"AES"].location == NSNotFound) [s appendString:@" · AES"];
    return s;
}

/* mark every entry under folder f (iterative, bounded) */
static void mark_folder(const gz_archive *a, i32 f, u8 *m)
{
    i32 *st = (i32 *)malloc(((size_t)a->nf + 1) * sizeof(i32));
    if (!st) return;
    u32 n = 0, guard = 0;
    st[n++] = f;
    while (n && guard++ <= a->nf) {
        i32 x = st[--n];
        if (x < 0 || (u32)x >= a->nf) continue;
        if (a->f[x].entry >= 0 && (u32)a->f[x].entry < a->n) m[a->f[x].entry] = 1;
        for (i32 e = a->f[x].first_file; e >= 0 && (u32)e < a->n; e = a->e[e].next) m[e] = 1;
        for (i32 s = a->f[x].first_sub; s >= 0 && (u32)s < a->nf && n <= a->nf; s = a->f[s].next_sib) st[n++] = s;
    }
    free(st);
}

/* ======================================================================
 * small views
 * ====================================================================== */

@interface GZTreeNode : NSObject
@property (nonatomic) i32 folder;
@property (nonatomic, strong) NSArray<GZTreeNode *> *kids;    /* nil until first asked */
@end
@implementation GZTreeNode
@end

/* drag-out of the file list: the rows of one drag, extracted together on first demand */
@interface GZDragBatch : NSObject {
@public
    NSMutableData *rows;           /* gz_lrow */
    unsigned gen;
    i32 folder;                    /* folder shown when the drag started */
    BOOL extracted;
    int result;
    NSString *tmp;
}
@end
@implementation GZDragBatch
@end

@class GZMainWindowController;

@interface GZMainWindowController ()
- (void)activateRow:(NSInteger)row;
- (void)cmdUp:(id)sender;
- (void)dropPaths:(NSArray<NSString *> *)paths;
- (BOOL)isOwnDrag:(id<NSDraggingInfo>)info;
- (void)setDropHighlight:(BOOL)on;
@end

@interface GZListTableView : NSTableView
@property (nonatomic, weak) GZMainWindowController *ctl;
@end

@implementation GZListTableView
- (void)keyDown:(NSEvent *)e
{
    unsigned short k = e.keyCode;
    NSEventModifierFlags m = e.modifierFlags & NSEventModifierFlagDeviceIndependentFlagsMask;
    if (k == 36 || k == 76 || (k == 125 && (m & NSEventModifierFlagCommand))) {      /* Return, Enter, Cmd-Down */
        [_ctl activateRow:self.selectedRow];
        return;
    }
    if (k == 51 || (k == 126 && (m & NSEventModifierFlagCommand))) {                  /* Delete, Cmd-Up */
        [_ctl cmdUp:nil];
        return;
    }
    [super keyDown:e];
}
@end

/* the window's content view: files dropped anywhere open or compress */
@interface GZDropView : NSView
@property (nonatomic, weak) GZMainWindowController *ctl;
@end

@implementation GZDropView

static NSArray<NSString *> *dropPaths(id<NSDraggingInfo> info)
{
    NSArray *urls = [info.draggingPasteboard readObjectsForClasses:@[ [NSURL class] ]
                                                           options:@{ NSPasteboardURLReadingFileURLsOnlyKey : @YES }];
    NSMutableArray *r = [NSMutableArray array];
    for (NSURL *u in urls)
        if (u.path.length) [r addObject:u.path];
    return r;
}

- (NSDragOperation)draggingEntered:(id<NSDraggingInfo>)info
{
    if ([_ctl isOwnDrag:info] || busy() || !dropPaths(info).count) return NSDragOperationNone;
    [_ctl setDropHighlight:YES];
    return NSDragOperationCopy;
}

- (NSDragOperation)draggingUpdated:(id<NSDraggingInfo>)info
{
    if ([_ctl isOwnDrag:info] || busy()) return NSDragOperationNone;
    return NSDragOperationCopy;
}

- (void)draggingExited:(id<NSDraggingInfo>)info { [_ctl setDropHighlight:NO]; }
- (void)draggingEnded:(id<NSDraggingInfo>)info { [_ctl setDropHighlight:NO]; }

- (BOOL)performDragOperation:(id<NSDraggingInfo>)info
{
    [_ctl setDropHighlight:NO];
    if ([_ctl isOwnDrag:info] || busy()) return NO;
    NSArray *paths = dropPaths(info);
    if (!paths.count) return NO;
    GZMainWindowController *c = _ctl;
    /* dialogs must not run inside the drag session */
    dispatch_async(dispatch_get_main_queue(), ^{ [c dropPaths:paths]; });
    return YES;
}

@end

/* rounded drop zone of the welcome view; dashed accent border while dragging */
@interface GZDropZone : NSView
@property (nonatomic) BOOL highlight;
@end

@implementation GZDropZone
- (void)setHighlight:(BOOL)h
{
    _highlight = h;
    self.needsDisplay = YES;
}

- (void)drawRect:(NSRect)dirty
{
    NSBezierPath *p = [NSBezierPath bezierPathWithRoundedRect:NSInsetRect(self.bounds, 1.5, 1.5) xRadius:14 yRadius:14];
    [[NSColor controlBackgroundColor] setFill];
    [p fill];
    if (_highlight) {
        [[accentRed() colorWithAlphaComponent:0.06] setFill];
        [p fill];
        CGFloat dash[2] = { 6, 4 };
        [p setLineDash:dash count:2 phase:0];
        p.lineWidth = 2;
        [accentRed() setStroke];
    } else {
        p.lineWidth = 1;
        [[NSColor gridColor] setStroke];
    }
    [p stroke];
}
@end

/* a bar with a hairline on one edge (path bar: bottom, status bar: top) */
@interface GZBar : NSView
@property (nonatomic) BOOL lineOnTop;
@end

@implementation GZBar
- (void)drawRect:(NSRect)dirty
{
    [[NSColor gridColor] setFill];
    NSRect b = self.bounds;
    NSRectFill(NSMakeRect(0, _lineOnTop ? b.size.height - 1 : 0, b.size.width, 1));
}
@end

/* ======================================================================
 * the controller
 * ====================================================================== */

@interface GZMainWindowController () <NSToolbarDelegate, NSTableViewDataSource, NSTableViewDelegate,
                                      NSOutlineViewDataSource, NSOutlineViewDelegate, NSSplitViewDelegate,
                                      NSMenuDelegate, NSFilePromiseProviderDelegate, NSWindowDelegate>
@end

@implementation GZMainWindowController {
    gz_handle *_h;                     /* archive shown                                */
    gz_handle *_outer[MAX_NEST];       /* archives it is nested in (kept open)         */
    i32 _outerCur[MAX_NEST];           /* folder each outer level showed               */
    int _depth;
    NSString *_path;                   /* file of the outermost archive                */
    i32 _cur;                          /* folder shown                                 */
    unsigned _gen;                     /* bumped whenever _h or its names change       */
    gz_lrow *_rows;
    u32 _nrows;
    int _sortCol;
    BOOL _sortDesc, _syncing, _statusPending;
    GZTreeNode *_root;
    NSMutableDictionary<NSNumber *, GZTreeNode *> *_nodes;
    NSArray<NSArray<NSNumber *> *> *_pathMap;   /* per path item: (level, folder) */
    NSArray<NSString *> *_recentShown;
    GZDragBatch *_pendingBatch;
    NSOperationQueue *_promiseQueue;

    GZDropView *_root_view;
    GZBar *_pathBar, *_status;
    NSButton *_upBtn;
    NSPathControl *_pathCtl;
    NSSplitView *_split;
    NSScrollView *_treeScroll, *_listScroll;
    NSOutlineView *_tree;
    GZListTableView *_list;
    NSTextField *_stLeft, *_stRight;
    NSView *_welcome;
    GZDropZone *_dropZone;
    NSStackView *_recentBox;
    NSTextField *_recentTitle;
    NSMenu *_listMenu, *_recentMenu, *_cpMenu;
}

+ (GZMainWindowController *)shared
{
    static GZMainWindowController *s;
    if (!s) s = [[GZMainWindowController alloc] init];
    return s;
}

- (instancetype)init
{
    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 1100, 680)
                                              styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                        NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
                                                backing:NSBackingStoreBuffered
                                                  defer:YES];
    w.releasedWhenClosed = NO;
    w.title = TR(STR_APP);
    w.minSize = NSMakeSize(640, 400);
    self = [super initWithWindow:w];
    if (!self) return nil;
    w.delegate = self;
    _sortCol = COL_NAME;
    _nodes = [NSMutableDictionary dictionary];
    _promiseQueue = [[NSOperationQueue alloc] init];
    _promiseQueue.maxConcurrentOperationCount = 1;
    _promiseQueue.qualityOfService = NSQualityOfServiceUserInitiated;
    [self buildWindow];
    [w center];
    [w setFrameUsingName:@"GZMainWindow"];     /* last size and place, when saved */
    [w setFrameAutosaveName:@"GZMainWindow"];
    [self showArchive];
    return self;
}

- (void)dealloc { free(_rows); }

- (BOOL)hasArchive { return _h != NULL; }

- (void)showMain
{
    [self showWindow:nil];
    [self.window makeKeyAndOrderFront:nil];
}

/* ======================================================================
 * building the window
 * ====================================================================== */

- (NSTableCellView *)makeCell:(NSString *)ident image:(BOOL)withImage align:(NSTextAlignment)al font:(NSFont *)font
{
    const CGFloat H = 20;
    NSTableCellView *v = [[NSTableCellView alloc] initWithFrame:NSMakeRect(0, 0, 120, H)];
    v.identifier = ident;
    CGFloat x = 3;
    if (withImage) {
        NSImageView *iv = [[NSImageView alloc] initWithFrame:NSMakeRect(3, 2, 16, 16)];
        iv.imageScaling = NSImageScaleProportionallyUpOrDown;
        iv.autoresizingMask = NSViewMaxXMargin | NSViewMinYMargin | NSViewMaxYMargin;
        [v addSubview:iv];
        v.imageView = iv;
        x = 24;
    }
    NSTextField *tf = [NSTextField labelWithString:@""];
    if (font) tf.font = font;
    tf.alignment = al;
    tf.lineBreakMode = withImage ? NSLineBreakByTruncatingMiddle : NSLineBreakByTruncatingTail;
    CGFloat th = ceil(tf.fittingSize.height);
    tf.frame = NSMakeRect(x, floor((H - th) / 2), 120 - x - 3, th);
    tf.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin | NSViewMaxYMargin;
    [v addSubview:tf];
    v.textField = tf;
    return v;
}

- (void)buildList
{
    _list = [[GZListTableView alloc] initWithFrame:NSMakeRect(0, 0, 800, 400)];
    _list.ctl = self;
    static const int titles[COL_COUNT] = { STR_COL_NAME, STR_COL_SIZE, STR_COL_PACKED, STR_COL_TYPE, STR_COL_MTIME,
                                          STR_COL_RATIO, STR_COL_METHOD, STR_COL_CRC };
    static const CGFloat widths[COL_COUNT] = { 280, 84, 84, 150, 128, 56, 120, 80 };
    for (int c = 0; c < COL_COUNT; c++) {
        NSTableColumn *col = [[NSTableColumn alloc] initWithIdentifier:k_cols[c]];
        col.title = TR(titles[c]);
        col.width = widths[c];
        col.minWidth = 36;
        col.resizingMask = NSTableColumnUserResizingMask;
        col.sortDescriptorPrototype = [NSSortDescriptor sortDescriptorWithKey:k_cols[c] ascending:YES];
        if (c == COL_SIZE || c == COL_PACKED || c == COL_RATIO) col.headerCell.alignment = NSTextAlignmentRight;
        [_list addTableColumn:col];
    }
    _list.sortDescriptors = @[ [NSSortDescriptor sortDescriptorWithKey:k_cols[COL_NAME] ascending:YES] ];
    _list.rowHeight = 20;
    _list.intercellSpacing = NSMakeSize(3, 0);
    _list.usesAlternatingRowBackgroundColors = YES;
    _list.allowsMultipleSelection = YES;
    _list.allowsEmptySelection = YES;
    _list.allowsColumnReordering = YES;
    _list.columnAutoresizingStyle = NSTableViewLastColumnOnlyAutoresizingStyle;
    if (@available(macOS 11.0, *)) _list.style = NSTableViewStyleFullWidth;
    _list.dataSource = self;
    _list.delegate = self;
    _list.target = self;
    _list.doubleAction = @selector(listDoubleClick:);
    _list.autosaveName = @"GZFileList";
    _list.autosaveTableColumns = YES;
    [_list setDraggingSourceOperationMask:NSDragOperationCopy forLocal:NO];
    [_list setDraggingSourceOperationMask:NSDragOperationNone forLocal:YES];

    _listMenu = [[NSMenu alloc] initWithTitle:@""];
    _listMenu.delegate = self;
    _listMenu.autoenablesItems = YES;
    [self item:_listMenu title:TRP(STR_M_OPENITEM) action:@selector(cmdView:) key:@""];
    [_listMenu addItem:[NSMenuItem separatorItem]];
    [self item:_listMenu title:TRP(STR_M_EXTRACT_SEL) action:@selector(cmdExtractSelected:) key:@""];
    [self item:_listMenu title:TRP(STR_M_EXTRACT) action:@selector(cmdExtract:) key:@""];
    [self item:_listMenu title:TRP(STR_M_EXTRACT_SMART) action:@selector(cmdExtractSmart:) key:@""];
    [_listMenu addItem:[NSMenuItem separatorItem]];
    [self item:_listMenu title:TRP(STR_M_TEST) action:@selector(cmdTest:) key:@""];
    [self item:_listMenu title:TRP(STR_M_INFO) action:@selector(cmdInfo:) key:@""];
    _list.menu = _listMenu;

    _listScroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(0, 0, 800, 400)];
    _listScroll.documentView = _list;
    _listScroll.hasVerticalScroller = YES;
    _listScroll.hasHorizontalScroller = YES;
    _listScroll.autohidesScrollers = YES;
    _listScroll.borderType = NSNoBorder;
}

- (void)buildTree
{
    _tree = [[NSOutlineView alloc] initWithFrame:NSMakeRect(0, 0, 220, 400)];
    NSTableColumn *col = [[NSTableColumn alloc] initWithIdentifier:@"tree"];
    col.resizingMask = NSTableColumnAutoresizingMask;
    [_tree addTableColumn:col];
    _tree.outlineTableColumn = col;
    _tree.headerView = nil;
    _tree.rowHeight = 20;
    _tree.indentationPerLevel = 12;
    _tree.autoresizesOutlineColumn = NO;
    _tree.columnAutoresizingStyle = NSTableViewUniformColumnAutoresizingStyle;
    if (@available(macOS 11.0, *)) _tree.style = NSTableViewStyleFullWidth;
    _tree.dataSource = self;
    _tree.delegate = self;
    _treeScroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(0, 0, 220, 400)];
    _treeScroll.documentView = _tree;
    _treeScroll.hasVerticalScroller = YES;
    _treeScroll.autohidesScrollers = YES;
    _treeScroll.borderType = NSNoBorder;
}

- (NSView *)buildWelcome:(NSRect)frame
{
    NSView *outer = [[NSView alloc] initWithFrame:frame];
    outer.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

    NSImageView *logo = [NSImageView imageViewWithImage:gzIcon(IC_LOGO, 88)];
    [logo.widthAnchor constraintEqualToConstant:88].active = YES;
    [logo.heightAnchor constraintEqualToConstant:88].active = YES;
    NSTextField *title = [NSTextField labelWithString:TR(STR_APP)];
    title.font = [NSFont systemFontOfSize:28 weight:NSFontWeightSemibold];
    title.textColor = accentRed();
    NSTextField *tag = [NSTextField labelWithString:TR(STR_TAGLINE)];
    tag.textColor = [NSColor secondaryLabelColor];

    /* readable formats: the best known first, then a count of the others */
    static const char *const known[] = { "ZIP", "7z", "RAR", "RAR5", "TAR", "GZIP", "BZIP2", "XZ", "ZSTD", "ISO",
                                         "CAB", "LZ4", "WIM", "DMG", 0 };
    NSMutableArray<NSString *> *names = [NSMutableArray array];
    int nf = 0;
    while (gz_formats[nf]) nf++;
    for (int k = 0; known[k] && names.count < 9; k++)
        for (int i = 0; i < nf; i++)
            if (!strcasecmp(gz_formats[i]->name, known[k])) { [names addObject:gzU8(gz_formats[i]->name)]; break; }
    for (int i = 0; i < nf && names.count < 9; i++) {
        BOOL dup = NO;
        for (int k = 0; known[k]; k++) dup |= !strcasecmp(gz_formats[i]->name, known[k]);
        if (dup || (gz_formats[i]->flags & GZ_FMT_WEAK)) continue;
        [names addObject:gzU8(gz_formats[i]->name)];
    }
    NSString *fl = [names componentsJoinedByString:@" · "];
    if (nf > (int)names.count)
        fl = [NSString stringWithFormat:@"%@  ·  %@", fl,
                                        TRF(STR_W_MORE, @[ [NSString stringWithFormat:@"%d", nf - (int)names.count] ])];

    NSTextField *dt = [NSTextField labelWithString:TR(STR_W_DROP)];
    dt.font = [NSFont systemFontOfSize:17];
    NSTextField *fmts = [NSTextField wrappingLabelWithString:fl];
    fmts.alignment = NSTextAlignmentCenter;
    fmts.textColor = [NSColor tertiaryLabelColor];
    fmts.preferredMaxLayoutWidth = 440;
    NSTextField *d2 = [NSTextField labelWithString:TR(STR_W_DROP2)];
    d2.textColor = [NSColor tertiaryLabelColor];
    NSButton *ob = [NSButton buttonWithTitle:TR(STR_W_OPEN) target:self action:@selector(cmdOpen:)];
    NSButton *nb = [NSButton buttonWithTitle:TRP(STR_W_NEW) target:self action:@selector(cmdNew:)];
    for (NSButton *b in @[ ob, nb ]) [b.widthAnchor constraintGreaterThanOrEqualToConstant:150].active = YES;
    NSStackView *bb = [NSStackView stackViewWithViews:@[ ob, nb ]];
    bb.spacing = 12;
    NSStackView *dzs = [NSStackView stackViewWithViews:@[ dt, fmts, d2, bb ]];
    dzs.orientation = NSUserInterfaceLayoutOrientationVertical;
    dzs.alignment = NSLayoutAttributeCenterX;
    dzs.spacing = 8;
    [dzs setCustomSpacing:14 afterView:d2];
    dzs.translatesAutoresizingMaskIntoConstraints = NO;
    _dropZone = [[GZDropZone alloc] initWithFrame:NSZeroRect];
    _dropZone.translatesAutoresizingMaskIntoConstraints = NO;
    [_dropZone addSubview:dzs];
    [NSLayoutConstraint activateConstraints:@[
        [dzs.leadingAnchor constraintEqualToAnchor:_dropZone.leadingAnchor constant:24],
        [dzs.trailingAnchor constraintEqualToAnchor:_dropZone.trailingAnchor constant:-24],
        [dzs.topAnchor constraintEqualToAnchor:_dropZone.topAnchor constant:18],
        [dzs.bottomAnchor constraintEqualToAnchor:_dropZone.bottomAnchor constant:-20],
        [_dropZone.widthAnchor constraintEqualToConstant:520],
    ]];

    _recentTitle = [NSTextField labelWithString:TR(STR_W_RECENT)];
    _recentTitle.textColor = [NSColor secondaryLabelColor];
    _recentBox = [[NSStackView alloc] initWithFrame:NSZeroRect];
    _recentBox.orientation = NSUserInterfaceLayoutOrientationVertical;
    _recentBox.alignment = NSLayoutAttributeLeading;
    _recentBox.spacing = 2;

    NSStackView *v = [NSStackView stackViewWithViews:@[ logo, title, tag, _dropZone, _recentTitle, _recentBox ]];
    v.orientation = NSUserInterfaceLayoutOrientationVertical;
    v.alignment = NSLayoutAttributeCenterX;
    v.spacing = 6;
    [v setCustomSpacing:18 afterView:tag];
    [v setCustomSpacing:8 afterView:_recentTitle];
    [v setCustomSpacing:22 afterView:_dropZone];
    v.translatesAutoresizingMaskIntoConstraints = NO;
    [outer addSubview:v];

    NSTextField *eng = [NSTextField labelWithString:
        [NSString stringWithFormat:@"%@:  %@  ·  %@", TR(STR_W_ENGINE), engineLine(),
                                   TRF(STR_THREADS, @[ [NSString stringWithFormat:@"%d", gz_os_cpu_count()] ])]];
    eng.textColor = [NSColor tertiaryLabelColor];
    eng.font = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
    eng.translatesAutoresizingMaskIntoConstraints = NO;
    [outer addSubview:eng];
    [NSLayoutConstraint activateConstraints:@[
        [v.centerXAnchor constraintEqualToAnchor:outer.centerXAnchor],
        [v.centerYAnchor constraintEqualToAnchor:outer.centerYAnchor constant:-10],
        [v.topAnchor constraintGreaterThanOrEqualToAnchor:outer.topAnchor constant:12],
        [_recentTitle.leadingAnchor constraintEqualToAnchor:_dropZone.leadingAnchor],
        [_recentBox.leadingAnchor constraintEqualToAnchor:_dropZone.leadingAnchor],
        [_recentBox.trailingAnchor constraintEqualToAnchor:_dropZone.trailingAnchor],
        [eng.centerXAnchor constraintEqualToAnchor:outer.centerXAnchor],
        [eng.bottomAnchor constraintEqualToAnchor:outer.bottomAnchor constant:-10],
        [eng.topAnchor constraintGreaterThanOrEqualToAnchor:v.bottomAnchor constant:8],
    ]];
    return outer;
}

- (void)buildWindow
{
    NSRect b = NSMakeRect(0, 0, 1100, 680);
    const CGFloat SH = 24, PH = 32;
    _root_view = [[GZDropView alloc] initWithFrame:b];
    _root_view.ctl = self;
    [_root_view registerForDraggedTypes:@[ NSPasteboardTypeFileURL ]];
    self.window.contentView = _root_view;

    /* status bar */
    _status = [[GZBar alloc] initWithFrame:NSMakeRect(0, 0, b.size.width, SH)];
    _status.lineOnTop = YES;
    _status.autoresizingMask = NSViewWidthSizable | NSViewMaxYMargin;
    NSFont *sf = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
    _stLeft = [NSTextField labelWithString:TR(STR_ST_READY)];
    _stLeft.font = sf;
    _stLeft.lineBreakMode = NSLineBreakByTruncatingTail;
    _stLeft.frame = NSMakeRect(10, 4, b.size.width - 360, 16);
    _stLeft.autoresizingMask = NSViewWidthSizable;
    [_status addSubview:_stLeft];
    _stRight = [NSTextField labelWithString:TRF(STR_ST_ENGINE, @[ gzU8(gz_dispatch_inflate_name()),
                                                                  [NSString stringWithFormat:@"%d",
                                                                   [[GZSettings shared] effectiveThreads]] ])];
    _stRight.font = sf;
    _stRight.textColor = [NSColor secondaryLabelColor];
    _stRight.alignment = NSTextAlignmentRight;
    _stRight.frame = NSMakeRect(b.size.width - 330, 4, 320, 16);
    _stRight.autoresizingMask = NSViewMinXMargin;
    [_status addSubview:_stRight];
    NSImageView *cpu = [NSImageView imageViewWithImage:gzIcon(IC_CPU, 16)];
    CGFloat tw = ceil(_stRight.fittingSize.width);
    cpu.frame = NSMakeRect(b.size.width - 10 - tw - 20, 4, 16, 16);
    cpu.autoresizingMask = NSViewMinXMargin;
    [_status addSubview:cpu];
    [_root_view addSubview:_status];

    /* path bar */
    _pathBar = [[GZBar alloc] initWithFrame:NSMakeRect(0, b.size.height - PH, b.size.width, PH)];
    _pathBar.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    _upBtn = [NSButton buttonWithImage:gzTemplateIcon(IC_UP, 16) target:self action:@selector(cmdUp:)];
    _upBtn.bordered = NO;
    _upBtn.imagePosition = NSImageOnly;
    _upBtn.toolTip = macTip(STR_TT_UP);
    _upBtn.frame = NSMakeRect(8, 6, 22, 20);
    [_pathBar addSubview:_upBtn];
    _pathCtl = [[NSPathControl alloc] initWithFrame:NSMakeRect(36, 5, b.size.width - 46, 22)];
    _pathCtl.pathStyle = NSPathStyleStandard;
    _pathCtl.autoresizingMask = NSViewWidthSizable;
    _pathCtl.target = self;
    _pathCtl.action = @selector(pathClicked:);
    _pathCtl.focusRingType = NSFocusRingTypeNone;
    [_pathBar addSubview:_pathCtl];
    [_root_view addSubview:_pathBar];

    /* folder tree | file list */
    [self buildTree];
    [self buildList];
    _split = [[NSSplitView alloc] initWithFrame:NSMakeRect(0, SH, b.size.width, b.size.height - SH - PH)];
    _split.vertical = YES;
    _split.dividerStyle = NSSplitViewDividerStyleThin;
    _split.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    _split.delegate = self;
    [_split addSubview:_treeScroll];
    [_split addSubview:_listScroll];
    [_split setPosition:220 ofDividerAtIndex:0];
    _split.autosaveName = @"GZSplit";
    _treeScroll.hidden = ![GZSettings shared].showTree;
    [_root_view addSubview:_split];

    _welcome = [self buildWelcome:NSMakeRect(0, SH, b.size.width, b.size.height - SH)];
    [_root_view addSubview:_welcome];

    /* toolbar */
    NSToolbar *tb = [[NSToolbar alloc] initWithIdentifier:@"GZMainToolbar"];
    tb.delegate = self;
    tb.displayMode = NSToolbarDisplayModeIconAndLabel;
    tb.allowsUserCustomization = YES;
    tb.autosavesConfiguration = YES;
    self.window.toolbar = tb;
    if (@available(macOS 11.0, *)) self.window.toolbarStyle = NSWindowToolbarStyleExpanded;
    [self rebuildRecent];
}

/* ======================================================================
 * toolbar
 * ====================================================================== */

static NSString *const TB_OPEN = @"open", *const TB_EXTRACT = @"extract", *const TB_NEW = @"new",
                       *const TB_TEST = @"test", *const TB_INFO = @"info", *const TB_CP = @"codepage",
                       *const TB_SETTINGS = @"settings";

- (NSArray<NSToolbarItemIdentifier> *)toolbarDefaultItemIdentifiers:(NSToolbar *)toolbar
{
    return @[ TB_OPEN, TB_EXTRACT, TB_NEW, NSToolbarSpaceItemIdentifier, TB_TEST, TB_INFO,
              NSToolbarSpaceItemIdentifier, TB_CP, NSToolbarFlexibleSpaceItemIdentifier, TB_SETTINGS ];
}

- (NSArray<NSToolbarItemIdentifier> *)toolbarAllowedItemIdentifiers:(NSToolbar *)toolbar
{
    return @[ TB_OPEN, TB_EXTRACT, TB_NEW, TB_TEST, TB_INFO, TB_CP, TB_SETTINGS, NSToolbarSpaceItemIdentifier,
              NSToolbarFlexibleSpaceItemIdentifier ];
}

- (NSToolbarItem *)toolbar:(NSToolbar *)toolbar itemForItemIdentifier:(NSToolbarItemIdentifier)ident
    willBeInsertedIntoToolbar:(BOOL)flag
{
    /* automatic storage: @selector() is not a constant initializer */
    const struct { NSString *__unsafe_unretained ident; int icon, label, tip; SEL action; } k[] = {
        { @"open", IC_OPEN, STR_TB_OPEN, STR_TT_OPEN, @selector(cmdOpen:) },
        { @"extract", IC_EXTRACT, STR_TB_EXTRACT, STR_TT_EXTRACT, @selector(cmdExtract:) },
        { @"new", IC_NEW, STR_TB_NEW, STR_TT_NEW, @selector(cmdNew:) },
        { @"test", IC_TEST, STR_TB_TEST, STR_TT_TEST, @selector(cmdTest:) },
        { @"info", IC_INFO, STR_TB_INFO, STR_TT_INFO, @selector(cmdInfo:) },
        { @"codepage", IC_CODEPAGE, STR_TB_CODEPAGE, STR_TT_CODEPAGE, @selector(cmdCodepageMenu:) },
        { @"settings", IC_SETTINGS, STR_TB_SETTINGS, STR_TT_SETTINGS, @selector(cmdSettings:) },
    };
    for (size_t i = 0; i < GZ_COUNTOF(k); i++) {
        if (![k[i].ident isEqualToString:ident]) continue;
        NSToolbarItem *it = [[NSToolbarItem alloc] initWithItemIdentifier:ident];
        it.label = TR(k[i].label);
        it.paletteLabel = TR(k[i].label);
        it.toolTip = macTip(k[i].tip);
        it.image = gzIcon(k[i].icon, 32);
        it.target = self;
        it.action = k[i].action;
        if ([ident isEqualToString:TB_CP]) {
            NSMenuItem *mf = [[NSMenuItem alloc] initWithTitle:TR(k[i].label) action:NULL keyEquivalent:@""];
            mf.submenu = [self codepageMenu];
            it.menuFormRepresentation = mf;
        }
        return it;
    }
    return nil;
}

- (BOOL)validateToolbarItem:(NSToolbarItem *)item
{
    NSString *i = item.itemIdentifier;
    if ([i isEqualToString:TB_SETTINGS]) return YES;
    if (busy()) return NO;
    if ([i isEqualToString:TB_OPEN] || [i isEqualToString:TB_NEW]) return YES;
    return _h != NULL;
}

/* ======================================================================
 * menus (built by main.m, validated here)
 * ====================================================================== */

- (NSMenuItem *)item:(NSMenu *)m title:(NSString *)t action:(SEL)a key:(NSString *)k
{
    NSMenuItem *it = [m addItemWithTitle:t action:a keyEquivalent:k];
    it.target = self;
    return it;
}

- (NSMenu *)recentMenu
{
    if (!_recentMenu) {
        _recentMenu = [[NSMenu alloc] initWithTitle:TRP(STR_M_RECENT)];
        _recentMenu.delegate = self;
    }
    return _recentMenu;
}

- (NSMenu *)codepageMenu
{
    NSMenu *m = [[NSMenu alloc] initWithTitle:TRP(STR_M_CODEPAGE)];
    m.delegate = self;
    if (!_cpMenu) _cpMenu = m;
    return m;
}

- (void)fillCodepageMenu:(NSMenu *)m
{
    [m removeAllItems];
    int cur = _h ? _h->arc->codepage : (int)[GZSettings shared].codepage;
    for (u32 i = 0; i < gz_ui_ncodepages; i++) {
        int cp = gz_ui_codepages[i].cp;
        if (cp && !gz_plat_cp_valid(cp)) continue;
        NSString *t = TR(gz_ui_codepages[i].sid);
        if (_h && !cp && _h->arc->any_legacy && gz_ui_cp_name(_h->arc->used_cp))
            t = [NSString stringWithFormat:@"%@ - %@", TR(STR_CP_AUTO), gzU8(gz_ui_cp_name(_h->arc->used_cp))];
        NSMenuItem *it = [self item:m title:t action:@selector(cmdSetCodepage:) key:@""];
        it.tag = cp;
        it.state = cp == cur ? NSControlStateValueOn : NSControlStateValueOff;
        if (!i) [m addItem:[NSMenuItem separatorItem]];
    }
}

- (void)fillRecentMenu:(NSMenu *)m
{
    [m removeAllItems];
    NSArray<NSString *> *r = [GZSettings shared].recent;
    _recentShown = r;
    for (NSUInteger i = 0; i < r.count; i++) {
        NSMenuItem *it = [self item:m title:r[i].lastPathComponent action:@selector(openRecent:) key:@""];
        it.tag = (NSInteger)i;
        it.toolTip = displayPath(r[i]);
        NSImage *ic = [[[NSWorkspace sharedWorkspace] iconForFile:r[i]] copy];
        ic.size = NSMakeSize(16, 16);
        it.image = ic;
    }
    if (!r.count) {
        NSMenuItem *it = [m addItemWithTitle:TRP(STR_M_NORECENT) action:NULL keyEquivalent:@""];
        it.enabled = NO;
    }
    [m addItem:[NSMenuItem separatorItem]];
    [self item:m title:MS(MS_CLEAR_RECENT) action:@selector(clearRecent:) key:@""];
}

- (void)menuNeedsUpdate:(NSMenu *)menu
{
    if (menu == _recentMenu) {
        [self fillRecentMenu:menu];
    } else if (menu == _listMenu) {
        NSInteger r = _list.clickedRow;
        if (r >= 0 && ![_list isRowSelected:r])
            [_list selectRowIndexes:[NSIndexSet indexSetWithIndex:(NSUInteger)r] byExtendingSelection:NO];
    } else {
        [self fillCodepageMenu:menu];
    }
}

- (BOOL)validateMenuItem:(NSMenuItem *)mi
{
    SEL a = mi.action;
    if (a == @selector(cmdSettings:) || a == @selector(clearRecent:)) return YES;
    if (a == @selector(cmdToggleTree:)) {
        mi.state = [GZSettings shared].showTree ? NSControlStateValueOn : NSControlStateValueOff;
        return YES;
    }
    if (busy()) return NO;
    if (a == @selector(cmdOpen:) || a == @selector(cmdNew:) || a == @selector(openRecent:)) return YES;
    if (a == @selector(cmdSetCodepage:)) return YES;
    if (a == @selector(cmdBack:)) return _depth > 0;
    if (a == @selector(cmdView:) || a == @selector(cmdExtractSelected:)) return _h && _list.numberOfSelectedRows > 0;
    if (a == @selector(cmdUp:)) return _h && (_cur > 0 || _depth > 0);
    return _h != NULL;
}

/* ======================================================================
 * title, status, path control
 * ====================================================================== */

- (void)updateTitle
{
    if (!_h) {
        self.window.title = TR(STR_APP);
        self.window.representedURL = nil;
        return;
    }
    self.window.title = [NSString stringWithFormat:@"%@ - %@", gzNS(_h->name), TR(STR_APP)];
    self.window.representedURL = _path ? [NSURL fileURLWithPath:_path] : nil;
}

- (void)statusNow
{
    _statusPending = NO;
    if (!_h) {
        _stLeft.stringValue = TR(STR_ST_READY);
        return;
    }
    gz_archive *a = _h->arc;
    __block u32 n = 0;
    __block u64 bytes = 0;
    [_list.selectedRowIndexes enumerateIndexesUsingBlock:^(NSUInteger i, BOOL *stop) {
        if (i >= self->_nrows || self->_rows[i].kind == 0) return;
        n++;
        if (self->_rows[i].kind == 2) {
            u64 us = a->e[self->_rows[i].idx].usize;
            if (us != GZ_SIZE_UNKNOWN) bytes += us;
        }
    }];
    if (n) {
        _stLeft.stringValue = TRF(STR_ST_SELECTED, @[ fmtThousands(n), fmtSize(bytes) ]);
    } else {
        char pc[16];
        gz_ui_fmt_percent(pc, sizeof pc, a->total_csize, a->total_usize);
        _stLeft.stringValue = TRF(STR_ST_SUMMARY, @[ fmtThousands(a->nfiles), fmtThousands(a->ndirs),
                                                     fmtSize(a->total_usize), fmtSize(a->total_csize),
                                                     pc[0] ? gzU8(pc) : @"-" ]);
    }
}

- (void)updateStatus
{
    if (_statusPending) return;
    _statusPending = YES;
    dispatch_async(dispatch_get_main_queue(), ^{ [self statusNow]; });
}

static NSString *baseOfName(const gzch *name)
{
    const gzch *s = gz_wcsrchr(name, '/');
    return gzNS(s ? s + 1 : name);
}

- (void)pathBuild
{
    NSMutableArray<NSPathControlItem *> *items = [NSMutableArray array];
    NSMutableArray *map = [NSMutableArray array];
    if (_h) {
        for (int L = 0; L <= _depth; L++) {
            gz_handle *h = L < _depth ? _outer[L] : _h;
            i32 cur = L < _depth ? _outerCur[L] : _cur;
            gz_archive *a = h->arc;
            i32 chain[48];
            int n = 0;
            for (i32 f = cur; f > 0 && (u32)f < a->nf && n < 48; f = a->f[f].parent) chain[n++] = f;
            NSPathControlItem *it = [[NSPathControlItem alloc] init];
            NSString *rootName = L == 0 && _path ? _path.lastPathComponent : baseOfName(h->name);
            it.title = rootName;
            it.image = L == 0 && _path ? [[NSWorkspace sharedWorkspace] iconForFile:_path] : typeIcon(h->name);
            [items addObject:it];
            [map addObject:@[ @(L), @0 ]];
            for (int k = n - 1; k >= 0; k--) {
                NSPathControlItem *fi = [[NSPathControlItem alloc] init];
                fi.title = gzNS(a->f[chain[k]].base);
                fi.image = folderIcon();
                [items addObject:fi];
                [map addObject:@[ @(L), @(chain[k]) ]];
            }
        }
    }
    _pathMap = map;
    _pathCtl.pathItems = items;
    _upBtn.enabled = _h && (_cur != 0 || _depth > 0);
}

- (void)pathClicked:(id)sender
{
    NSPathControlItem *ci = _pathCtl.clickedPathItem;
    NSUInteger i = ci ? [_pathCtl.pathItems indexOfObject:ci] : NSNotFound;
    if (i == NSNotFound || i >= _pathMap.count || busy()) return;
    int level = _pathMap[i][0].intValue;
    i32 f = _pathMap[i][1].intValue;
    if (level < _depth) {
        [self popTo:level];
        [self showArchiveAt:f];
    } else if (f != _cur) {
        [self navigate:f focus:-1];
    }
}

/* ======================================================================
 * folder tree (lazy)
 * ====================================================================== */

- (GZTreeNode *)nodeFor:(i32)f
{
    NSNumber *k = @(f);
    GZTreeNode *n = _nodes[k];
    if (!n) {
        n = [[GZTreeNode alloc] init];
        n.folder = f;
        _nodes[k] = n;
    }
    return n;
}

- (NSArray<GZTreeNode *> *)kidsOf:(GZTreeNode *)node
{
    if (node.kids) return node.kids;
    gz_archive *a = _h->arc;
    NSMutableArray<GZTreeNode *> *kids = [NSMutableArray array];
    u32 guard = 0;
    for (i32 s = a->f[node.folder].first_sub; s >= 0 && (u32)s < a->nf && guard++ < a->nf; s = a->f[s].next_sib)
        [kids addObject:[self nodeFor:s]];
    [kids sortUsingComparator:^NSComparisonResult(GZTreeNode *x, GZTreeNode *y) {
        int r = gzNameCmpNatural(a->f[x.folder].base, a->f[y.folder].base);
        return r < 0 ? NSOrderedAscending : r > 0 ? NSOrderedDescending : NSOrderedSame;
    }];
    node.kids = kids;
    return kids;
}

- (NSInteger)outlineView:(NSOutlineView *)ov numberOfChildrenOfItem:(id)item
{
    if (!_h) return 0;
    if (!item) return 1;
    return (NSInteger)[self kidsOf:item].count;
}

- (id)outlineView:(NSOutlineView *)ov child:(NSInteger)index ofItem:(id)item
{
    if (!item) return _root;
    NSArray *k = [self kidsOf:item];
    return index >= 0 && index < (NSInteger)k.count ? k[(NSUInteger)index] : _root;
}

- (BOOL)outlineView:(NSOutlineView *)ov isItemExpandable:(id)item
{
    if (!_h) return NO;
    GZTreeNode *n = item;
    return _h->arc->f[n.folder].first_sub >= 0;
}

- (NSView *)outlineView:(NSOutlineView *)ov viewForTableColumn:(NSTableColumn *)col item:(id)item
{
    NSTableCellView *v = [ov makeViewWithIdentifier:@"treecell" owner:self];
    if (!v) v = [self makeCell:@"treecell" image:YES align:NSTextAlignmentLeft font:nil];
    if (!_h) return v;
    GZTreeNode *n = item;
    if (n.folder == 0) {
        v.textField.stringValue = baseOfName(_h->name);
        v.imageView.image = _depth == 0 && _path ? [[NSWorkspace sharedWorkspace] iconForFile:_path] : typeIcon(_h->name);
    } else {
        v.textField.stringValue = gzNS(_h->arc->f[n.folder].base);
        v.imageView.image = folderIcon();
    }
    return v;
}

- (void)outlineViewSelectionDidChange:(NSNotification *)note
{
    if (_syncing || !_h) return;
    GZTreeNode *n = [_tree itemAtRow:_tree.selectedRow];
    if (n && n.folder != _cur && (u32)n.folder < _h->arc->nf) [self navigate:n.folder focus:-1];
}

- (void)treeBuild
{
    [_nodes removeAllObjects];
    _root = _h ? [self nodeFor:0] : nil;
    [_tree reloadData];
    if (_root) [_tree expandItem:_root];
}

/* select folder f in the tree, expanding its ancestors */
- (void)treeSync:(i32)f
{
    if (!_h || !_root) return;
    gz_archive *a = _h->arc;
    i32 chain[256];
    int n = 0;
    for (i32 x = f; x > 0 && (u32)x < a->nf && n < 256; x = a->f[x].parent) chain[n++] = x;
    _syncing = YES;
    GZTreeNode *node = _root;
    while (n--) {
        [_tree expandItem:node];               /* loads its children: the next node is among them */
        node = [self nodeFor:chain[n]];
    }
    [_tree expandItem:node];                   /* show the subfolders too */
    NSInteger row = [_tree rowForItem:node];
    if (row >= 0) {
        [_tree selectRowIndexes:[NSIndexSet indexSetWithIndex:(NSUInteger)row] byExtendingSelection:NO];
        [_tree scrollRowToVisible:row];
    }
    _syncing = NO;
}

/* ======================================================================
 * file list
 * ====================================================================== */

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tv { return _h ? (NSInteger)_nrows : 0; }

- (NSView *)tableView:(NSTableView *)tv viewForTableColumn:(NSTableColumn *)col row:(NSInteger)row
{
    NSString *ident = col.identifier;
    int c = colIndex(ident);
    NSTableCellView *v = [tv makeViewWithIdentifier:ident owner:self];
    if (!v) {
        NSFont *f = nil;
        NSTextAlignment al = NSTextAlignmentLeft;
        if (c == COL_SIZE || c == COL_PACKED || c == COL_RATIO) {
            al = NSTextAlignmentRight;
            f = [NSFont monospacedDigitSystemFontOfSize:[NSFont systemFontSize] weight:NSFontWeightRegular];
        } else if (c == COL_CRC) {
            f = [NSFont userFixedPitchFontOfSize:[NSFont smallSystemFontSize]];
        }
        v = [self makeCell:ident image:c == COL_NAME align:al font:f];
    }
    if (!_h || row < 0 || (u32)row >= _nrows) return v;
    const gz_lrow *r = &_rows[row];
    gz_archive *a = _h->arc;
    NSString *s = @"";
    if (r->kind != 2) {
        const gz_folder *fo = r->kind == 1 ? &a->f[r->idx] : NULL;
        switch (c) {
        case COL_NAME:
            s = fo ? gzNS(fo->base) : @"..";
            v.imageView.image = folderIcon();
            break;
        case COL_TYPE: s = TR(fo ? STR_FOLDER : STR_PARENT); break;
        case COL_MTIME:
            if (fo && fo->mtime_kind) {
                gz_entry tmp;
                memset(&tmp, 0, sizeof tmp);
                tmp.mtime = fo->mtime;
                tmp.mtime_kind = fo->mtime_kind;
                s = fmtFiletime(gz_entry_time(&tmp));
            }
            break;
        }
        v.textField.stringValue = s;
        return v;
    }
    const gz_entry *e = &a->e[r->idx];
    char b[64];
    switch (c) {
    case COL_NAME:
        s = e->enc ? [gzNS(e->base) stringByAppendingString:@" *"] : gzNS(e->base);
        v.imageView.image = typeIcon(e->base);
        break;
    case COL_SIZE:
        if (e->usize != GZ_SIZE_UNKNOWN) { gz_ui_fmt_kb(b, sizeof b, e->usize); s = gzU8(b); }
        break;
    case COL_PACKED:
        if (e->csize != GZ_SIZE_UNKNOWN) { gz_ui_fmt_kb(b, sizeof b, e->csize); s = gzU8(b); }
        break;
    case COL_TYPE: s = e->is_link ? TR(STR_LINK) : typeDescription(e->base); break;
    case COL_MTIME: s = fmtFiletime(gz_entry_time(e)); break;
    case COL_RATIO:
        if (e->usize != GZ_SIZE_UNKNOWN && e->csize != GZ_SIZE_UNKNOWN) {
            gz_ui_fmt_percent(b, sizeof b, e->csize, e->usize);
            s = gzU8(b);
        }
        break;
    case COL_METHOD: s = methodText(a, e); break;
    case COL_CRC:
        if (e->has_crc && !e->is_dir) { gz_ui_fmt_hex32(b, sizeof b, e->crc); s = gzU8(b); }
        break;
    }
    v.textField.stringValue = s;
    return v;
}

- (NSString *)tableView:(NSTableView *)tv typeSelectStringForTableColumn:(NSTableColumn *)col row:(NSInteger)row
{
    if (!_h || row < 0 || (u32)row >= _nrows || ![col.identifier isEqualToString:k_cols[COL_NAME]]) return nil;
    const gz_lrow *r = &_rows[row];
    return r->kind == 2 ? gzNS(_h->arc->e[r->idx].base) : r->kind == 1 ? gzNS(_h->arc->f[r->idx].base) : nil;
}

- (void)tableViewSelectionDidChange:(NSNotification *)note { [self updateStatus]; }

- (void)tableView:(NSTableView *)tv sortDescriptorsDidChange:(NSArray<NSSortDescriptor *> *)old
{
    NSSortDescriptor *sd = tv.sortDescriptors.firstObject;
    int c = sd.key ? colIndex(sd.key) : -1;
    _sortCol = c < 0 ? COL_NAME : c;
    _sortDesc = sd ? !sd.ascending : NO;
    if (!_h) return;
    [self sortAndReload:-1];
}

- (void)sortAndReload:(i32)focusFolder
{
    gz_archive *a = _h->arc;
    u32 *rank = NULL;
    if ((_sortCol == COL_TYPE || _sortCol == COL_METHOD) && _nrows > 1) {
        @autoreleasepool {
            NSMutableArray<NSString *> *txt = [NSMutableArray arrayWithCapacity:_nrows];
            NSMutableSet<NSString *> *uniq = [NSMutableSet set];
            for (u32 i = 0; i < _nrows; i++) {
                NSString *t = @"";
                if (_rows[i].kind == 2) {
                    const gz_entry *e = &a->e[_rows[i].idx];
                    t = _sortCol == COL_TYPE ? (e->is_link ? TR(STR_LINK) : typeDescription(e->base)) : methodText(a, e);
                }
                [txt addObject:t];
                [uniq addObject:t];
            }
            NSArray<NSString *> *sorted = [uniq.allObjects sortedArrayUsingSelector:@selector(localizedStandardCompare:)];
            NSMutableDictionary<NSString *, NSNumber *> *pos = [NSMutableDictionary dictionaryWithCapacity:sorted.count];
            for (NSUInteger k = 0; k < sorted.count; k++) pos[sorted[k]] = @(k);
            rank = (u32 *)malloc((size_t)_nrows * sizeof(u32));
            if (rank)
                for (u32 i = 0; i < _nrows; i++) rank[i] = pos[txt[i]].unsignedIntValue;
        }
    }
    sort_ctx s = { a, _sortCol, _sortDesc, rank };
    sort_rows(_rows, _nrows, &s);
    free(rank);
    [_list reloadData];
    [_list deselectAll:nil];
    if (!_nrows) return;
    NSInteger sel = -1;
    if (focusFolder >= 0)
        for (u32 i = 0; i < _nrows; i++)
            if (_rows[i].kind == 1 && _rows[i].idx == focusFolder) { sel = (NSInteger)i; break; }
    if (sel >= 0) {
        [_list selectRowIndexes:[NSIndexSet indexSetWithIndex:(NSUInteger)sel] byExtendingSelection:NO];
        [_list scrollRowToVisible:sel];
    } else {
        [_list scrollRowToVisible:0];
    }
}

- (void)navigate:(i32)f focus:(i32)focus
{
    if (!_h) return;
    gz_archive *a = _h->arc;
    if (f < 0 || (u32)f >= a->nf) f = 0;
    _cur = f;
    u32 cnt = (f != 0) + a->f[f].nsub + a->f[f].nfiles, n = 0;
    free(_rows);
    _rows = (gz_lrow *)calloc((size_t)cnt + 1, sizeof(gz_lrow));
    if (!_rows) { _nrows = 0; [_list reloadData]; return; }
    if (f != 0) { _rows[n].kind = 0; _rows[n++].idx = a->f[f].parent; }
    for (i32 s = a->f[f].first_sub; s >= 0 && (u32)s < a->nf && n < cnt; s = a->f[s].next_sib) {
        _rows[n].kind = 1;
        _rows[n++].idx = s;
    }
    for (i32 e = a->f[f].first_file; e >= 0 && (u32)e < a->n && n < cnt; e = a->e[e].next) {
        _rows[n].kind = 2;
        _rows[n++].idx = e;
    }
    _nrows = n;
    [self sortAndReload:focus];
    [self pathBuild];
    [self treeSync:f];
    [self updateStatus];
}

/* selection -> entry mask (malloc'ed), NULL when nothing is selected */
- (u8 *)selectionMask:(u32 *)nrows names:(NSMutableArray<NSString *> *)names
{
    *nrows = 0;
    if (!_h) return NULL;
    gz_archive *a = _h->arc;
    u8 *m = (u8 *)calloc(a->n + 1, 1);
    if (!m) return NULL;
    __block u32 k = 0;
    [_list.selectedRowIndexes enumerateIndexesUsingBlock:^(NSUInteger i, BOOL *stop) {
        if (i >= self->_nrows || self->_rows[i].kind == 0) return;
        const gz_lrow *r = &self->_rows[i];
        k++;
        if (r->kind == 2) m[r->idx] = 1;
        else mark_folder(a, r->idx, m);
        if (names) [names addObject:gzNS(r->kind == 2 ? a->e[r->idx].base : a->f[r->idx].base)];
    }];
    *nrows = k;
    if (!k) { free(m); return NULL; }
    return m;
}

- (void)listDoubleClick:(id)sender
{
    NSInteger r = _list.clickedRow;
    if (r >= 0) [self activateRow:r];
}

- (void)activateRow:(NSInteger)i
{
    if (!_h || busy() || i < 0 || (u32)i >= _nrows) return;
    gz_lrow row = _rows[i];
    if (row.kind == 0) [self navigate:_h->arc->f[_cur].parent focus:_cur];
    else if (row.kind == 1) [self navigate:row.idx focus:-1];
    else [self viewEntry:(u32)row.idx];
}

/* ======================================================================
 * archives: open, nest, close
 * ====================================================================== */

- (void)detachViews
{
    _nrows = 0;
    [_list reloadData];
    _root = nil;
    [_nodes removeAllObjects];
    [_tree reloadData];
    _gen++;
}

- (void)closeAll
{
    [self detachViews];
    if (_h) gz_handle_close(_h);
    while (_depth) gz_handle_close(_outer[--_depth]);
    _h = NULL;
    _path = nil;
}

- (void)showArchiveAt:(i32)folder
{
    _gen++;
    _cur = 0;
    [self updateTitle];
    [self treeBuild];
    BOOL has = _h != NULL;
    _welcome.hidden = has;
    _split.hidden = !has;
    _pathBar.hidden = !has;
    if (has) {
        [self navigate:folder focus:-1];
        [self.window makeFirstResponder:_list];
    } else {
        [self pathBuild];
        [self rebuildRecent];
    }
    [self updateStatus];
}

- (void)showArchive { [self showArchiveAt:0]; }

- (void)openArchivePath:(NSString *)path
{
    if (busy() || !path.length) return;
    NSString *ab = absPath(path);
    [self showMain];
    GZRun *run = [GZRun openPath:ab codepage:(int)[GZSettings shared].codepage parent:self.window
                            done:^(GZRun *r, int res) {
        gz_handle *h = [r takeHandle];
        if (!h) {
            if (res != GZ_E_CANCEL)
                msgBox(self.window, NSAlertStyleWarning, TR(STR_OPEN_FAIL),
                       [NSString stringWithFormat:@"%@\n%@", displayPath(ab),
                                                  gzU8(gz_ui_code_text(res ? res : GZ_E_FORMAT))]);
            return;
        }
        [self closeAll];
        self->_h = h;
        self->_path = ab;
        [[GZSettings shared] addRecent:ab];
        [self showArchive];
    }];
    if (!run) msgBox(self.window, NSAlertStyleWarning, TR(STR_OPEN_FAIL), displayPath(ab));
}

- (void)popTo:(int)level
{
    if (level < 0 || level >= _depth) return;
    [self detachViews];
    while (_depth > level) {
        gz_handle_close(_h);
        _depth--;
        _h = _outer[_depth];
    }
}

- (void)openChild:(u32)idx
{
    [GZRun openChildOf:_h index:idx codepage:(int)[GZSettings shared].codepage parent:self.window
                  done:^(GZRun *r, int res) {
                      gz_handle *h = [r takeHandle];
                      if (!h) {
                          if (res != GZ_E_CANCEL)
                              msgBox(self.window, NSAlertStyleWarning, TR(STR_OPEN_FAIL),
                                     gzU8(gz_ui_code_text(res ? res : GZ_E_FORMAT)));
                          return;
                      }
                      if (self->_depth >= MAX_NEST) {
                          gz_handle_close(h);
                          return;
                      }
                      [self detachViews];
                      self->_outer[self->_depth] = self->_h;
                      self->_outerCur[self->_depth] = self->_cur;
                      self->_depth++;
                      self->_h = h;
                      [self showArchive];
                  }];
}

- (void)cmdBack:(id)sender
{
    if (busy() || !_depth) return;
    i32 f = _outerCur[_depth - 1];
    [self popTo:_depth - 1];
    [self showArchiveAt:f];
}

- (void)cmdClose:(id)sender
{
    if (busy()) return;
    [self closeAll];
    [self showArchive];
}

- (void)cmdUp:(id)sender
{
    if (!_h || busy()) return;
    if (_cur > 0) [self navigate:_h->arc->f[_cur].parent focus:_cur];
    else [self cmdBack:nil];
}

- (void)cmdOpen:(id)sender
{
    if (busy()) return;
    NSOpenPanel *p = [NSOpenPanel openPanel];
    p.canChooseFiles = YES;
    p.canChooseDirectories = NO;
    p.allowsMultipleSelection = NO;
    p.title = TR(STR_W_OPEN);
    p.prompt = TR(STR_TB_OPEN);
    if (_path) p.directoryURL = [NSURL fileURLWithPath:_path.stringByDeletingLastPathComponent isDirectory:YES];
    void (^fin)(NSModalResponse) = ^(NSModalResponse r) {
        if (r == NSModalResponseOK && p.URL.path) [self openArchivePath:p.URL.path];
    };
    if (self.window.visible) [p beginSheetModalForWindow:self.window completionHandler:fin];
    else fin([p runModal]);
}

- (void)openRecent:(NSMenuItem *)sender
{
    NSInteger i = sender.tag;
    if (i >= 0 && i < (NSInteger)_recentShown.count) [self openArchivePath:_recentShown[(NSUInteger)i]];
}

- (void)clearRecent:(id)sender
{
    [[GZSettings shared] clearRecent];
    [self rebuildRecent];
}

/* ======================================================================
 * extraction, test, view
 * ====================================================================== */

- (NSString *)arcDir
{
    return _path ? _path.stringByDeletingLastPathComponent : NSHomeDirectory();
}

- (void)startExtract:(NSString *)dest smart:(BOOL)smart pathMode:(int)pm overwrite:(int)ow sel:(const u8 *)sel
               strip:(BOOL)useStrip test:(BOOL)test flags:(int)flags
{
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    gzch *wd = gzPathW(dest);
    if (!wd) return;
    xo.dest = wd;
    xo.smart = smart;
    xo.path_mode = pm;
    if (useStrip && _cur > 0 && pm == GZ_PATH_FULL) {
        xo.path_mode = GZ_PATH_STRIP;
        xo.strip = _h->arc->f[_cur].name;
    }
    xo.overwrite = ow;
    xo.sel = sel;
    xo.test = test;
    xo.threads = (int)[GZSettings shared].threads;
    [GZRun extractHandle:_h options:&xo parent:self.window flags:flags done:nil];
    gz_free(wd);
}

- (void)extractMode:(int)mode
{
    if (!_h || busy()) return;
    GZSettings *set = [GZSettings shared];
    u32 nsel = 0;
    u8 *mask = [self selectionMask:&nsel names:nil];
    NSString *dir = [self arcDir];
    if (mode == X_HERE || mode == X_SMART) {         /* next to the archive, as Finder's Archive Utility */
        [self startExtract:dir smart:mode == X_SMART pathMode:GZ_PATH_FULL overwrite:(int)set.overwrite sel:NULL
                     strip:NO test:NO flags:RUN_QUIET_OK];
        free(mask);
        return;
    }
    u32 offer = mode == X_SELECTED || nsel ? nsel : 0;
    /* the sheet does not block: Finder (application:openFiles:), Open Recent or a drop can
     * replace the archive meanwhile. The mask (h->arc->n + 1 bytes) and the folder to strip
     * belong to h as it is now: extract nothing when it changed */
    gz_handle *h = _h;
    unsigned gen = _gen;
    dlgExtract(self.window, _h, _path ? _path : [dir stringByAppendingPathComponent:@"-"], offer,
               ^(GZExtractChoice *c) {
                   if (c && self->_h && self->_h == h && self->_gen == gen && !busy()) {
                       BOOL sel = c.onlySelected && mask;
                       [self startExtract:c.dest smart:c.smart pathMode:c.pathMode overwrite:c.overwrite
                                      sel:sel ? mask : NULL strip:sel test:NO
                                    flags:RUN_QUIET_OK | (c.openFolder ? RUN_OPEN_DEST : 0)];
                   }
                   free(mask);
               });
}

- (void)cmdExtract:(id)sender { [self extractMode:X_DIALOG]; }
- (void)cmdExtractHere:(id)sender { [self extractMode:X_HERE]; }
- (void)cmdExtractSmart:(id)sender { [self extractMode:X_SMART]; }
- (void)cmdExtractSelected:(id)sender { [self extractMode:X_SELECTED]; }

- (void)cmdTest:(id)sender
{
    if (!_h || busy()) return;
    [self startExtract:@"/" smart:NO pathMode:GZ_PATH_FULL overwrite:GZ_OW_ALL sel:NULL strip:NO test:YES flags:0];
}

- (void)cmdInfo:(id)sender
{
    if (!_h) return;
    dlgInfo(self.window, _h, _path ? _path : @"");
}

- (void)viewEntry:(u32)idx
{
    gz_archive *a = _h->arc;
    const gz_entry *e = &a->e[idx];
    NSString *name = gzPathNS(e->base);
    if (isArchiveName(name)) {
        [self openChild:idx];
        return;
    }
    NSString *dir = tempNewDir(@"v");
    if (!dir) return;
    u8 *m = (u8 *)calloc(a->n + 1, 1);
    if (!m) return;
    m[idx] = 1;
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    gzch *wd = gzPathW(dir);
    xo.dest = wd;
    xo.path_mode = GZ_PATH_NONE;
    xo.overwrite = GZ_OW_ALL;
    xo.sel = m;
    xo.threads = 1;
    if (wd)
        [GZRun extractHandle:_h options:&xo parent:self.window flags:RUN_DELAY | RUN_QUIET_OK
                        done:^(GZRun *r, int res) {
                            if (res != GZ_OK) return;
                            NSString *p = [dir stringByAppendingPathComponent:name];
                            if (!pathExists(p)) {   /* renamed by the engine (unsafe name...): take what is there */
                                NSString *f = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:NULL]
                                                  .firstObject;
                                if (f) p = [dir stringByAppendingPathComponent:f];
                            }
                            openWithDefault(p, self.window);
                        }];
    gz_free(wd);
    free(m);
}

- (void)cmdView:(id)sender
{
    NSInteger r = _list.clickedRow >= 0 && [_list isRowSelected:_list.clickedRow] ? _list.clickedRow : _list.selectedRow;
    [self activateRow:r];
}

- (void)cmdSetCodepage:(NSMenuItem *)sender
{
    int cp = (int)sender.tag;
    if (!_h) {
        [GZSettings shared].codepage = cp;
        [[GZSettings shared] save];
        return;
    }
    if (busy()) return;
    [self detachViews];
    gz_handle_set_codepage(_h, cp);
    typesClear();
    [self showArchive];
}

- (void)cmdCodepageMenu:(id)sender
{
    if (!_h) return;
    NSMenu *m = [[NSMenu alloc] initWithTitle:@""];
    [self fillCodepageMenu:m];
    [m popUpMenuPositioningItem:nil atLocation:[NSEvent mouseLocation] inView:nil];
}

- (void)cmdSettings:(id)sender { prefsShow(); }

- (void)cmdToggleTree:(id)sender
{
    GZSettings *s = [GZSettings shared];
    s.showTree = !s.showTree;
    [s save];
    _treeScroll.hidden = !s.showTree;
    [_split adjustSubviews];
    if (s.showTree && _treeScroll.frame.size.width < 80) [_split setPosition:220 ofDividerAtIndex:0];
}

/* ======================================================================
 * new archive
 * ====================================================================== */

- (void)compressPaths:(NSArray<NSString *> *)paths
{
    if (!paths.count || busy()) return;
    NSWindow *par = self.window.visible ? self.window : nil;
    dlgCreate(par, paths, nil, 0, ^(GZCreateChoice *c) {
        if (c) startCompress(paths, c, par, GZ_OW_ASK, RUN_QUIET_OK, nil);
    });
}

- (void)cmdNew:(id)sender
{
    if (busy()) return;
    NSOpenPanel *p = [NSOpenPanel openPanel];
    p.canChooseFiles = YES;
    p.canChooseDirectories = YES;
    p.allowsMultipleSelection = YES;
    p.title = TR(STR_C_PICK_FILES);
    p.prompt = TR(STR_SELECT);
    void (^fin)(NSModalResponse) = ^(NSModalResponse r) {
        if (r != NSModalResponseOK) return;
        NSMutableArray *v = [NSMutableArray array];
        for (NSURL *u in p.URLs)
            if (u.path) [v addObject:u.path];
        /* the create dialog is a sheet too: start it after this panel is gone */
        dispatch_async(dispatch_get_main_queue(), ^{ [self compressPaths:v]; });
    };
    if (self.window.visible) [p beginSheetModalForWindow:self.window completionHandler:fin];
    else fin([p runModal]);
}

- (void)openOrCompressPaths:(NSArray<NSString *> *)paths
{
    if (!paths.count) return;
    BOOL allArchives = YES;
    for (NSString *p in paths) allArchives = allArchives && !pathIsDir(p) && isArchiveName(p.lastPathComponent);
    if (allArchives) [self openArchivePath:paths[0]];
    else {
        [self showMain];
        [self compressPaths:paths];
    }
}

/* ======================================================================
 * drag and drop
 * ====================================================================== */

- (BOOL)isOwnDrag:(id<NSDraggingInfo>)info
{
    id src = info.draggingSource;
    return src == _list || src == _tree;
}

- (void)setDropHighlight:(BOOL)on { _dropZone.highlight = on && !_h; }

- (void)dropPaths:(NSArray<NSString *> *)paths
{
    if (busy()) return;
    if (paths.count == 1 && !pathIsDir(paths[0]) && isArchiveName(paths[0].lastPathComponent))
        [self openArchivePath:paths[0]];
    else
        [self compressPaths:paths];
}

/* drag out: one file promise per row; the rows of a drag are extracted together into a
 * private temporary folder when the first promise is asked for, then moved into place */
- (id<NSPasteboardWriting>)tableView:(NSTableView *)tv pasteboardWriterForRow:(NSInteger)row
{
    if (!_h || busy() || row < 0 || (u32)row >= _nrows || _rows[row].kind == 0) return nil;
    gz_lrow r = _rows[row];
    gz_archive *a = _h->arc;
    NSString *name = gzPathNS(r.kind == 2 ? a->e[r.idx].base : a->f[r.idx].base);
    NSString *type = @"public.folder";
    if (r.kind == 2) {
        type = @"public.data";
        NSString *ext = name.pathExtension;
        if (ext.length) {
            CFStringRef u = UTTypeCreatePreferredIdentifierForTag(kUTTagClassFilenameExtension,
                                                                  (__bridge CFStringRef)ext, NULL);
            if (u) type = CFBridgingRelease(u);
        }
    }
    if (!_pendingBatch || _pendingBatch->gen != _gen) {
        _pendingBatch = [[GZDragBatch alloc] init];
        _pendingBatch->rows = [NSMutableData data];
        _pendingBatch->gen = _gen;
        _pendingBatch->folder = _cur;
    }
    [_pendingBatch->rows appendBytes:&r length:sizeof r];
    NSFilePromiseProvider *p = [[NSFilePromiseProvider alloc] initWithFileType:type delegate:self];
    p.userInfo = @{ @"name" : name, @"batch" : _pendingBatch };
    return p;
}

- (void)tableView:(NSTableView *)tv draggingSession:(NSDraggingSession *)session
    willBeginAtPoint:(NSPoint)screenPoint forRowIndexes:(NSIndexSet *)rowIndexes
{
    _pendingBatch = nil;          /* the next drag collects a new batch */
}

- (void)tableView:(NSTableView *)tv draggingSession:(NSDraggingSession *)session
     endedAtPoint:(NSPoint)screenPoint operation:(NSDragOperation)operation
{
    _pendingBatch = nil;
}

- (NSString *)filePromiseProvider:(NSFilePromiseProvider *)fp fileNameForType:(NSString *)fileType
{
    NSDictionary *ui = fp.userInfo;
    return ui[@"name"];
}

- (NSOperationQueue *)operationQueueForFilePromiseProvider:(NSFilePromiseProvider *)fp { return _promiseQueue; }

/* main thread: extract the batch; done gets the result (also when nothing started) */
- (void)extractBatch:(GZDragBatch *)b done:(void (^)(int))done
{
    if (!_h || b->gen != _gen || busy()) { done(GZ_E_CANCEL); return; }
    gz_archive *a = _h->arc;
    NSString *dir = tempNewDir(@"d");
    u8 *mask = (u8 *)calloc(a->n + 1, 1);
    if (!dir || !mask) { free(mask); done(GZ_E_NOMEM); return; }
    const gz_lrow *rows = (const gz_lrow *)b->rows.bytes;
    NSUInteger n = b->rows.length / sizeof(gz_lrow);
    for (NSUInteger i = 0; i < n; i++) {
        if (rows[i].kind == 2 && (u32)rows[i].idx < a->n) mask[rows[i].idx] = 1;
        else if (rows[i].kind == 1 && (u32)rows[i].idx < a->nf) mark_folder(a, rows[i].idx, mask);
    }
    b->tmp = dir;
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    gzch *wd = gzPathW(dir);
    xo.dest = wd;
    xo.path_mode = b->folder > 0 && (u32)b->folder < a->nf ? GZ_PATH_STRIP : GZ_PATH_FULL;
    xo.strip = xo.path_mode == GZ_PATH_STRIP ? a->f[b->folder].name : NULL;
    xo.overwrite = GZ_OW_ALL;
    xo.sel = mask;
    xo.threads = (int)[GZSettings shared].threads;
    GZRun *r = wd ? [GZRun extractHandle:_h options:&xo parent:self.window flags:RUN_DELAY | RUN_QUIET_OK
                                    done:^(GZRun *run, int res) { done(res); }]
                  : nil;
    gz_free(wd);
    free(mask);
    if (!r) done(GZ_E_NOMEM);
}

- (void)filePromiseProvider:(NSFilePromiseProvider *)fp writePromiseToURL:(NSURL *)url
          completionHandler:(void (^)(NSError *errorOrNil))completionHandler
{
    /* runs on _promiseQueue (serial, background) */
    NSDictionary *ui = fp.userInfo;
    GZDragBatch *b = ui[@"batch"];
    NSString *name = ui[@"name"];
    if (!b->extracted) {
        b->extracted = YES;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block int res = GZ_E_IO;
        dispatch_async(dispatch_get_main_queue(), ^{
            [self extractBatch:b done:^(int r) {
                res = r;
                dispatch_semaphore_signal(sem);
            }];
        });
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        b->result = res;
    }
    NSError *err = nil;
    NSString *src = b->tmp ? [b->tmp stringByAppendingPathComponent:name] : nil;
    if ((b->result == GZ_OK || b->result == GZ_E_SKIP) && src && pathExists(src)) {
        [[NSFileManager defaultManager] moveItemAtURL:[NSURL fileURLWithPath:src] toURL:url error:&err];
    } else {
        err = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileWriteUnknownError
                              userInfo:@{ NSLocalizedDescriptionKey : MS(MS_DRAG_FAIL) }];
    }
    completionHandler(err);
}

/* ======================================================================
 * welcome view: recent archives
 * ====================================================================== */

- (void)recentClicked:(NSButton *)b
{
    NSInteger i = b.tag;
    if (i >= 0 && i < (NSInteger)_recentShown.count) [self openArchivePath:_recentShown[(NSUInteger)i]];
}

- (void)rebuildRecent
{
    if (!_recentBox) return;
    for (NSView *v in [_recentBox.arrangedSubviews copy]) {
        [_recentBox removeArrangedSubview:v];
        [v removeFromSuperview];
    }
    NSArray<NSString *> *r = [GZSettings shared].recent;
    _recentShown = r;
    int shown = 0;
    for (NSUInteger i = 0; i < r.count && shown < 6; i++) {
        NSString *p = r[i];
        if (!pathExists(p)) continue;
        shown++;
        NSMutableAttributedString *t = [[NSMutableAttributedString alloc]
            initWithString:p.lastPathComponent
                attributes:@{ NSForegroundColorAttributeName : [NSColor labelColor],
                              NSFontAttributeName : [NSFont systemFontOfSize:[NSFont systemFontSize]] }];
        [t appendAttributedString:[[NSAttributedString alloc]
                                      initWithString:[@"   " stringByAppendingString:
                                                                  displayPath(p.stringByDeletingLastPathComponent)]
                                          attributes:@{ NSForegroundColorAttributeName : [NSColor tertiaryLabelColor],
                                                        NSFontAttributeName : [NSFont systemFontOfSize:
                                                                                   [NSFont smallSystemFontSize]] }]];
        NSImage *ic = [[[NSWorkspace sharedWorkspace] iconForFile:p] copy];
        ic.size = NSMakeSize(16, 16);
        NSButton *b = [NSButton buttonWithImage:ic target:self action:@selector(recentClicked:)];
        b.attributedTitle = t;
        b.imagePosition = NSImageLeft;
        b.bordered = NO;
        b.alignment = NSTextAlignmentLeft;
        b.tag = (NSInteger)i;
        b.toolTip = displayPath(p);
        [b.cell setLineBreakMode:NSLineBreakByTruncatingMiddle];
        [_recentBox addArrangedSubview:b];
        [b.widthAnchor constraintLessThanOrEqualToConstant:520].active = YES;
    }
    _recentTitle.hidden = shown == 0;
}

/* ======================================================================
 * split view, window
 * ====================================================================== */

- (BOOL)splitView:(NSSplitView *)sv canCollapseSubview:(NSView *)v { return v == _treeScroll; }

- (CGFloat)splitView:(NSSplitView *)sv constrainMinCoordinate:(CGFloat)p ofSubviewAt:(NSInteger)i
{
    return 120;
}

- (CGFloat)splitView:(NSSplitView *)sv constrainMaxCoordinate:(CGFloat)p ofSubviewAt:(NSInteger)i
{
    return MAX(160, sv.bounds.size.width - 260);
}

- (BOOL)splitView:(NSSplitView *)sv shouldAdjustSizeOfSubview:(NSView *)v { return v != _treeScroll; }

- (BOOL)windowShouldClose:(NSWindow *)sender { return !busy(); }

- (void)windowWillClose:(NSNotification *)note
{
    [self closeAll];
    [self showArchive];
}

@end
