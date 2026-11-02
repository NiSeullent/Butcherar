/*
 * 고깃ZIP macOS - dialogs
 *
 * Same content as the Windows / GTK dialogs: a header (icon, title, subtitle), the
 * options, and the buttons with the main action as the default button (Return;
 * Escape cancels). A dialog is a sheet on its parent window when that is visible,
 * else an app-modal window (Finder services, command line modes). Questions asked
 * by a running job are NSAlerts answering through a completion block (run.m).
 */
#import "app.h"

/* ======================================================================
 * dialog window plumbing
 * ====================================================================== */

static NSMutableSet *s_dialogs;          /* dialogs on screen keep themselves alive */

@implementation GZDialog {
    void (^_done)(NSModalResponse);
    BOOL _modal;
}

- (void)beginOn:(NSWindow *)parent completion:(void (^)(NSModalResponse))done
{
    _done = [done copy];
    if (!s_dialogs) s_dialogs = [NSMutableSet set];
    [s_dialogs addObject:self];
    self.window.delegate = self;
    if (parent.visible && !parent.attachedSheet) {
        [parent beginSheet:self.window completionHandler:^(NSModalResponse r) { [self completed:r]; }];
    } else {
        _modal = YES;
        [NSApp activateIgnoringOtherApps:YES];
        [self.window center];
        NSModalResponse r = [NSApp runModalForWindow:self.window];
        [self.window orderOut:nil];
        [self completed:r];
    }
}

- (void)end:(NSModalResponse)r
{
    NSWindow *sp = self.window.sheetParent;
    if (sp) [sp endSheet:self.window returnCode:r];
    else if (_modal) [NSApp stopModalWithCode:r];
}

- (void)completed:(NSModalResponse)r
{
    void (^d)(NSModalResponse) = _done;
    _done = nil;
    [s_dialogs removeObject:self];
    if (d) d(r);
}

- (BOOL)windowShouldClose:(NSWindow *)sender
{
    [self end:NSModalResponseCancel];
    return NO;
}

- (void)ok:(id)sender { [self end:NSModalResponseOK]; }
- (void)cancel:(id)sender { [self end:NSModalResponseCancel]; }

@end

static NSWindow *dialogWindow(NSString *title)
{
    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 480, 300)
                                              styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                                                backing:NSBackingStoreBuffered
                                                  defer:YES];
    w.title = title;
    w.releasedWhenClosed = NO;
    return w;
}

static NSTextField *label(NSString *s) { return [NSTextField labelWithString:s ? s : @""]; }

static NSTextField *dimLabel(NSString *s)
{
    NSTextField *l = label(s);
    l.textColor = [NSColor secondaryLabelColor];
    l.lineBreakMode = NSLineBreakByTruncatingMiddle;
    [l setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow
                                forOrientation:NSLayoutConstraintOrientationHorizontal];
    return l;
}

static NSTextField *boldLabel(NSString *s)
{
    NSTextField *l = label(s);
    l.font = [NSFont boldSystemFontOfSize:[NSFont systemFontSize]];
    return l;
}

static NSView *header(int icon, NSString *title, NSString *sub)
{
    NSImageView *iv = [NSImageView imageViewWithImage:gzIcon(icon, 32)];
    [iv.widthAnchor constraintEqualToConstant:32].active = YES;
    [iv.heightAnchor constraintEqualToConstant:32].active = YES;
    NSTextField *t = label(title);
    t.font = [NSFont boldSystemFontOfSize:15];
    NSMutableArray *col = [NSMutableArray arrayWithObject:t];
    if (sub.length) [col addObject:dimLabel(sub)];
    NSStackView *tv = [NSStackView stackViewWithViews:col];
    tv.orientation = NSUserInterfaceLayoutOrientationVertical;
    tv.alignment = NSLayoutAttributeLeading;
    tv.spacing = 2;
    NSStackView *h = [NSStackView stackViewWithViews:@[ iv, tv ]];
    h.spacing = 12;
    h.alignment = NSLayoutAttributeCenterY;
    return h;
}

static NSButton *pushButton(NSString *title, id target, SEL action, NSString *key)
{
    NSButton *b = [NSButton buttonWithTitle:title target:target action:action];
    if (key) b.keyEquivalent = key;
    [b.widthAnchor constraintGreaterThanOrEqualToConstant:96].active = YES;
    return b;
}

static NSView *buttonRow(NSArray<NSView *> *left, NSArray<NSButton *> *right)
{
    NSStackView *s = [[NSStackView alloc] initWithFrame:NSZeroRect];
    s.spacing = 10;
    for (NSView *v in left) [s addView:v inGravity:NSStackViewGravityLeading];
    for (NSButton *b in right) [s addView:b inGravity:NSStackViewGravityTrailing];
    return s;
}

/* rows stacked vertically; views in `fill` stretch to the full width */
static void installContent(NSWindow *w, NSArray<NSView *> *rows, NSArray<NSView *> *fill, CGFloat minWidth)
{
    NSStackView *st = [NSStackView stackViewWithViews:rows];
    st.orientation = NSUserInterfaceLayoutOrientationVertical;
    st.alignment = NSLayoutAttributeLeading;
    st.spacing = 10;
    st.translatesAutoresizingMaskIntoConstraints = NO;
    NSView *cv = [[NSView alloc] initWithFrame:NSZeroRect];
    [cv addSubview:st];
    [NSLayoutConstraint activateConstraints:@[
        [st.leadingAnchor constraintEqualToAnchor:cv.leadingAnchor constant:20],
        [st.trailingAnchor constraintEqualToAnchor:cv.trailingAnchor constant:-20],
        [st.topAnchor constraintEqualToAnchor:cv.topAnchor constant:18],
        [st.bottomAnchor constraintEqualToAnchor:cv.bottomAnchor constant:-18],
        [st.widthAnchor constraintGreaterThanOrEqualToConstant:minWidth],
    ]];
    for (NSView *v in fill) [v.widthAnchor constraintEqualToAnchor:st.widthAnchor].active = YES;
    w.contentView = cv;
    [w setContentSize:cv.fittingSize];
}

static void runAlert(NSAlert *a, NSWindow *parent, void (^done)(NSModalResponse))
{
    if (parent.visible && !parent.attachedSheet) {
        [a beginSheetModalForWindow:parent completionHandler:done];
    } else {
        [NSApp activateIgnoringOtherApps:YES];
        done([a runModal]);
    }
}

static NSPopUpButton *popup(NSArray<NSString *> *items, NSInteger sel)
{
    NSPopUpButton *p = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    [p addItemsWithTitles:items];
    if (sel >= 0 && sel < (NSInteger)items.count) [p selectItemAtIndex:sel];
    return p;
}

static NSControlStateValue onOff(BOOL b) { return b ? NSControlStateValueOn : NSControlStateValueOff; }
static BOOL isOn(NSButton *b) { return b.state == NSControlStateValueOn; }

/* ======================================================================
 * password field with "show password"
 * ====================================================================== */

@interface GZPasswordField : NSView
@property (nonatomic, readonly) NSSecureTextField *secure;
@property (nonatomic, readonly) NSTextField *plain;
@property (nonatomic, copy) NSString *stringValue;
- (void)setShowsPlain:(BOOL)show;
- (NSTextField *)activeField;
@end

@implementation GZPasswordField

- (instancetype)initWithFrame:(NSRect)r
{
    self = [super initWithFrame:r];
    if (!self) return nil;
    _secure = [[NSSecureTextField alloc] initWithFrame:self.bounds];
    _plain = [[NSTextField alloc] initWithFrame:self.bounds];
    for (NSTextField *f in @[ _secure, _plain ]) {
        f.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
        [self addSubview:f];
    }
    _plain.hidden = YES;
    return self;
}

- (NSSize)intrinsicContentSize { return NSMakeSize(260, 22); }
- (NSTextField *)activeField { return _plain.hidden ? _secure : _plain; }
- (NSString *)stringValue { return [self activeField].stringValue; }

- (void)setStringValue:(NSString *)s
{
    _secure.stringValue = s ? s : @"";
    _plain.stringValue = s ? s : @"";
}

- (void)setShowsPlain:(BOOL)show
{
    NSString *v = self.stringValue;
    _secure.stringValue = v;
    _plain.stringValue = v;
    _plain.hidden = !show;
    _secure.hidden = show;
    [self.window makeFirstResponder:[self activeField]];
}

- (void)clear { self.stringValue = @""; }

@end

/* toggles every password field it knows (a checkbox target) */
@interface GZShowToggle : NSObject
@property (nonatomic, strong) NSArray<GZPasswordField *> *fields;
- (void)toggle:(NSButton *)b;
@end
@implementation GZShowToggle
- (void)toggle:(NSButton *)b
{
    for (GZPasswordField *f in _fields) [f setShowsPlain:isOn(b)];
}
@end

/* ======================================================================
 * questions from running jobs (non-blocking, answer through done)
 * ====================================================================== */

static void askPassword(NSWindow *parent, gz_ask *q, void (^done)(int))
{
    NSAlert *a = [[NSAlert alloc] init];
    a.messageText = TR(STR_PW_TITLE);
    NSString *what = q->archive && q->path && gz_wcscmp(q->archive, q->path)
                         ? [NSString stringWithFormat:@"%@\n%@", gzNS(q->archive), gzNS(q->path)]
                         : gzNS(q->path ? q->path : q->archive);
    a.informativeText = [NSString stringWithFormat:@"%@\n\n%@", TR(q->retry ? STR_PW_WRONG : STR_PW_PROMPT), what];
    a.icon = gzIcon(IC_LOCK, 64);
    a.alertStyle = q->retry ? NSAlertStyleWarning : NSAlertStyleInformational;
    NSView *acc = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 300, 50)];
    GZPasswordField *pw = [[GZPasswordField alloc] initWithFrame:NSMakeRect(0, 28, 300, 22)];
    [acc addSubview:pw];
    GZShowToggle *tg = [[GZShowToggle alloc] init];
    tg.fields = @[ pw ];
    NSButton *show = [NSButton checkboxWithTitle:TR(STR_PW_SHOW) target:tg action:@selector(toggle:)];
    show.frame = NSMakeRect(0, 0, 300, 20);
    [acc addSubview:show];
    a.accessoryView = acc;
    [a addButtonWithTitle:TR(STR_OK)];
    NSButton *cancel = [a addButtonWithTitle:TR(STR_CANCEL)];
    cancel.keyEquivalent = @"\e";
    [a addButtonWithTitle:TR(STR_OWQ_SKIP)];
    [a layout];
    a.window.initialFirstResponder = pw.secure;
    runAlert(a, parent, ^(NSModalResponse r) {
        (void)tg;                                  /* keep the checkbox target alive */
        int ans = GZ_ANS_CANCEL;
        if (r == NSAlertFirstButtonReturn) {
            NSString *s = pw.stringValue;
            gzCopyAnswer(q->answer, s);
            ans = s.length ? GZ_ANS_YES : GZ_ANS_NO;
        } else if (r == NSAlertThirdButtonReturn) {
            ans = GZ_ANS_NO;
        }
        [pw clear];
        done(ans);
    });
    if (a.window.sheetParent) [a.window makeFirstResponder:pw.secure];
}

static NSView *fileBlock(NSString *title, NSImage *icon, NSString *name, NSString *info)
{
    NSImageView *iv = [NSImageView imageViewWithImage:icon];
    [iv.widthAnchor constraintEqualToConstant:32].active = YES;
    [iv.heightAnchor constraintEqualToConstant:32].active = YES;
    NSTextField *n = label(name);
    n.lineBreakMode = NSLineBreakByTruncatingMiddle;
    [n.widthAnchor constraintLessThanOrEqualToConstant:360].active = YES;
    NSStackView *t = [NSStackView stackViewWithViews:@[ n, dimLabel(info) ]];
    t.orientation = NSUserInterfaceLayoutOrientationVertical;
    t.alignment = NSLayoutAttributeLeading;
    t.spacing = 2;
    NSStackView *row = [NSStackView stackViewWithViews:@[ iv, t ]];
    row.spacing = 8;
    NSStackView *b = [NSStackView stackViewWithViews:@[ boldLabel(title), row ]];
    b.orientation = NSUserInterfaceLayoutOrientationVertical;
    b.alignment = NSLayoutAttributeLeading;
    b.spacing = 4;
    return b;
}

static void askOverwrite(NSWindow *parent, gz_ask *q, void (^done)(int))
{
    NSAlert *a = [[NSAlert alloc] init];
    a.alertStyle = NSAlertStyleWarning;
    a.messageText = TR(STR_OWQ_TITLE);
    a.icon = gzIcon(IC_WARN, 64);
    BOOL archive = q->entry == q->path;        /* the archive being created exists */
    if (archive) {
        a.informativeText = [NSString stringWithFormat:@"%@\n\n%@\n%@", TR(STR_OWQ_ARC_PROMPT), gzNS(q->path),
                                                       fmtSizeDate(q->old_size, q->old_mtime)];
        [a addButtonWithTitle:TR(STR_OWQ_OVERWRITE)];
        NSButton *no = [a addButtonWithTitle:TR(STR_NO)];
        no.keyEquivalent = @"\e";
        runAlert(a, parent, ^(NSModalResponse r) { done(r == NSAlertFirstButtonReturn ? GZ_ANS_YES : GZ_ANS_NO); });
        return;
    }
    a.informativeText = TR(STR_OWQ_PROMPT);
    NSStackView *acc = [NSStackView stackViewWithViews:@[
        fileBlock(TR(STR_OWQ_EXISTING), typeIcon(q->entry ? q->entry : q->path), gzNS(q->path),
                  fmtSizeDate(q->old_size, q->old_mtime)),
        fileBlock(TR(STR_OWQ_NEW), gzIcon(IC_EXTRACT, 32), gzNS(q->entry), fmtSizeDate(q->new_size, q->new_mtime)),
    ]];
    acc.orientation = NSUserInterfaceLayoutOrientationVertical;
    acc.alignment = NSLayoutAttributeLeading;
    acc.spacing = 12;
    NSSize fit = acc.fittingSize;
    acc.frame = NSMakeRect(0, 0, MAX(fit.width, 360), fit.height);
    a.accessoryView = acc;
    a.showsSuppressionButton = YES;
    a.suppressionButton.title = TR(STR_OWQ_APPLYALL);
    a.suppressionButton.state = NSControlStateValueOff;
    [a addButtonWithTitle:TR(STR_OWQ_OVERWRITE)];
    [a addButtonWithTitle:TR(STR_OWQ_SKIP)];
    [a addButtonWithTitle:TR(STR_OWQ_RENAME)];
    NSButton *cancel = [a addButtonWithTitle:TR(STR_CANCEL)];
    cancel.keyEquivalent = @"\e";
    runAlert(a, parent, ^(NSModalResponse r) {
        BOOL all = a.suppressionButton.state == NSControlStateValueOn;
        int ans = GZ_ANS_CANCEL;
        if (r == NSAlertFirstButtonReturn) ans = all ? GZ_ANS_YES_ALL : GZ_ANS_YES;
        else if (r == NSAlertSecondButtonReturn) ans = all ? GZ_ANS_NO_ALL : GZ_ANS_NO;
        else if (r == NSAlertThirdButtonReturn) ans = all ? GZ_ANS_RENAME_ALL : GZ_ANS_RENAME;
        done(ans);
    });
}

static void askVolume(NSWindow *parent, gz_ask *q, void (^done)(int))
{
    NSOpenPanel *p = [NSOpenPanel openPanel];
    p.canChooseFiles = YES;
    p.canChooseDirectories = NO;
    p.allowsMultipleSelection = NO;
    NSString *want = gzPathNS(q->path);
    p.message = [NSString stringWithFormat:@"%@\n%@", TR(STR_VOL_PROMPT), want.lastPathComponent];
    p.title = TR(STR_VOL_TITLE);
    NSString *dir = want.stringByDeletingLastPathComponent;
    if (pathIsDir(dir)) p.directoryURL = [NSURL fileURLWithPath:dir isDirectory:YES];
    void (^fin)(NSModalResponse) = ^(NSModalResponse r) {
        if (r == NSModalResponseOK && p.URL.path) {
            gzch *w = gzPathW(p.URL.path);
            gz_ask *qq = q;
            size_t i = 0;
            for (; w && w[i] && i + 1 < GZ_ASK_CAP; i++) qq->answer[i] = w[i];
            qq->answer[i] = 0;
            gz_free(w);
            done(GZ_ANS_YES);
        } else {
            done(GZ_ANS_CANCEL);
        }
    };
    if (parent.visible && !parent.attachedSheet) [p beginSheetModalForWindow:parent completionHandler:fin];
    else fin([p runModal]);
}

void askDialog(NSWindow *parent, gz_ask *q, void (^done)(int))
{
    switch (q->kind) {
    case GZ_ASK_PASSWORD: askPassword(parent, q, done); break;
    case GZ_ASK_OVERWRITE: askOverwrite(parent, q, done); break;
    case GZ_ASK_VOLUME: askVolume(parent, q, done); break;
    default: done(GZ_ANS_CANCEL); break;
    }
}

/* ======================================================================
 * extract options
 * ====================================================================== */

@implementation GZExtractChoice
@end

@interface GZExtractDialog : GZDialog <NSComboBoxDelegate>
@end

@implementation GZExtractDialog {
@public
    NSComboBox *_dest;
    NSMutableDictionary<NSString *, NSString *> *_shown;     /* text shown -> real path */
    NSString *_arcDir;
    NSButton *_smart, *_openf, *_only;
    NSPopUpButton *_paths, *_ow;
}

- (void)setDest:(NSString *)p
{
    NSString *t = displayPath(p);
    _shown[t] = p;
    _dest.stringValue = t;
}

- (NSString *)destPath
{
    NSString *t = [_dest.stringValue stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (!t.length) return nil;
    NSString *p = _shown[t];
    if (p) return p;
    p = t.stringByExpandingTildeInPath;
    if (!p.absolutePath) p = [_arcDir stringByAppendingPathComponent:p];
    return p.stringByStandardizingPath;
}

- (void)browse:(id)sender
{
    NSOpenPanel *p = [NSOpenPanel openPanel];
    p.canChooseDirectories = YES;
    p.canChooseFiles = NO;
    p.canCreateDirectories = YES;
    p.allowsMultipleSelection = NO;
    p.message = TR(STR_X_PICK);
    p.prompt = TR(STR_SELECT);
    NSString *cur = [self destPath];
    p.directoryURL = [NSURL fileURLWithPath:pathIsDir(cur) ? cur : _arcDir isDirectory:YES];
    if ([p runModal] == NSModalResponseOK && p.URL.path) [self setDest:p.URL.path];
}

- (void)quick:(NSButton *)b
{
    NSString *p = b.identifier;
    if (p) [self setDest:p];
}

@end

void dlgExtract(NSWindow *parent, gz_handle *h, NSString *arcPath, u32 nsel, void (^done)(GZExtractChoice *c))
{
    GZSettings *set = [GZSettings shared];
    gz_archive *a = h->arc;
    GZExtractDialog *x = [[GZExtractDialog alloc] init];
    x->_arcDir = arcPath.stringByDeletingLastPathComponent;
    if (!x->_arcDir.length) x->_arcDir = NSHomeDirectory();
    x->_shown = [NSMutableDictionary dictionary];
    x.window = dialogWindow(TR(STR_X_TITLE));
    NSString *sub = [NSString stringWithFormat:@"%@  ·  %@", gzNS(h->name),
                                               TRF(STR_X_SUMMARY, @[ fmtThousands(a->nfiles), fmtSize(a->total_usize) ])];

    x->_dest = [[NSComboBox alloc] initWithFrame:NSMakeRect(0, 0, 360, 26)];
    x->_dest.completes = NO;
    x->_dest.numberOfVisibleItems = 8;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *desk = [fm URLsForDirectory:NSDesktopDirectory inDomains:NSUserDomainMask].firstObject.path;
    NSString *docs = [fm URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].firstObject.path;
    NSString *down = [fm URLsForDirectory:NSDownloadsDirectory inDomains:NSUserDomainMask].firstObject.path;
    NSMutableArray<NSString *> *hist = [NSMutableArray array];
    if (set.dest && ![set.dest isEqual:x->_arcDir]) [hist addObject:set.dest];
    for (NSString *p in @[ x->_arcDir, desk ? desk : @"", docs ? docs : @"", down ? down : @"" ])
        if (p.length && pathIsDir(p) && ![hist containsObject:p]) [hist addObject:p];
    if (![hist containsObject:x->_arcDir]) [hist insertObject:x->_arcDir atIndex:0];
    for (NSString *p in hist) {
        NSString *t = displayPath(p);
        x->_shown[t] = p;
        [x->_dest addItemWithObjectValue:t];
    }
    [x setDest:set.destMode == 1 && set.dest ? set.dest : x->_arcDir];
    NSButton *br = [NSButton buttonWithTitle:TR(STR_BROWSE) target:x action:@selector(browse:)];
    NSStackView *row = [NSStackView stackViewWithViews:@[ x->_dest, br ]];
    row.spacing = 8;
    [x->_dest setContentHuggingPriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];

    NSStackView *qrow = [[NSStackView alloc] initWithFrame:NSZeroRect];
    qrow.spacing = 6;
    NSString *quick[4] = { x->_arcDir, desk, docs, down };
    static const int qs[4] = { STR_X_HERE, STR_X_DESKTOP, STR_X_DOCS, STR_X_DOWNLOADS };
    for (int i = 0; i < 4; i++) {
        if (!quick[i].length || !pathIsDir(quick[i])) continue;
        NSButton *b = [NSButton buttonWithTitle:TR(qs[i]) target:x action:@selector(quick:)];
        b.bezelStyle = NSBezelStyleRecessed;
        b.controlSize = NSControlSizeSmall;
        b.font = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
        b.identifier = quick[i];
        [qrow addView:b inGravity:NSStackViewGravityLeading];
    }

    x->_smart = [NSButton checkboxWithTitle:TR(STR_X_MAKEFOLDER) target:nil action:NULL];
    x->_smart.state = onOff(set.smart);
    x->_paths = popup(@[ TR(STR_X_PATH_FULL), TR(STR_X_PATH_NONE) ], set.pathMode == GZ_PATH_NONE);
    x->_ow = popup(@[ TR(STR_OW_ASK), TR(STR_OW_ALL), TR(STR_OW_SKIP), TR(STR_OW_RENAME), TR(STR_OW_NEWER) ],
                   set.overwrite);
    NSGridView *g = [NSGridView gridViewWithViews:@[
        @[ label(TR(STR_X_PATHS)), x->_paths ],
        @[ label(TR(STR_X_OVERWRITE)), x->_ow ],
    ]];
    g.rowSpacing = 8;
    g.columnSpacing = 12;
    for (NSInteger r = 0; r < g.numberOfRows; r++) [g rowAtIndex:r].yPlacement = NSGridCellPlacementCenter;
    x->_openf = [NSButton checkboxWithTitle:TR(STR_X_OPENFOLDER) target:nil action:NULL];
    x->_openf.state = onOff(set.openFolder);
    NSMutableArray *rows = [NSMutableArray arrayWithObjects:header(IC_EXTRACT, TR(STR_X_TITLE), sub),
                                                            boldLabel(TR(STR_X_DEST)), row, qrow, x->_smart, g,
                                                            x->_openf, nil];
    if (nsel) {
        x->_only = [NSButton checkboxWithTitle:TRF(STR_X_SELECTED, @[ fmtThousands(nsel) ]) target:nil action:NULL];
        x->_only.state = NSControlStateValueOn;
        [rows addObject:x->_only];
    }
    NSButton *cancel = pushButton(TR(STR_CANCEL), x, @selector(cancel:), @"\e");
    NSButton *ok = pushButton(TR(STR_X_START), x, @selector(ok:), @"\r");
    NSView *buttons = buttonRow(@[], @[ cancel, ok ]);
    [rows addObject:buttons];
    installContent(x.window, rows, @[ row, buttons ], 460);
    x.window.initialFirstResponder = ok;

    [x beginOn:parent completion:^(NSModalResponse r) {
        GZExtractChoice *c = nil;
        NSString *dest = r == NSModalResponseOK ? [x destPath] : nil;
        if (dest) {
            c = [[GZExtractChoice alloc] init];
            c.dest = dest;
            c.smart = isOn(x->_smart);
            c.pathMode = x->_paths.indexOfSelectedItem == 1 ? GZ_PATH_NONE : GZ_PATH_FULL;
            c.overwrite = x->_ow.indexOfSelectedItem < 0 ? GZ_OW_ASK : (int)x->_ow.indexOfSelectedItem;
            c.openFolder = isOn(x->_openf);
            c.onlySelected = x->_only && isOn(x->_only);
            set.smart = c.smart;
            set.pathMode = c.pathMode;
            set.overwrite = c.overwrite;
            set.openFolder = c.openFolder;
            if (![dest isEqual:x->_arcDir]) set.dest = dest;
            [set save];
        }
        done(c);
    }];
}

/* ======================================================================
 * create archive
 * ====================================================================== */

@implementation GZCreateChoice
@end

static BOOL singleStream(int f) { return f == GZ_WF_GZ || f == GZ_WF_BZ2 || f == GZ_WF_XZ || f == GZ_WF_ZST; }

static BOOL writerUsable(const gz_writer *w, NSUInteger ninputs, BOOL singleFile)
{
    return !singleStream(w->format) || (ninputs == 1 && singleFile);
}

const gz_writer *writerDefault(NSUInteger ninputs, BOOL singleFile)
{
    const gz_writer *w = gz_writer_find((int)[GZSettings shared].cFormat);
    if (w && writerUsable(w, ninputs, singleFile)) return w;
    static const int pref[] = { GZ_WF_ZIP, GZ_WF_7Z, GZ_WF_TGZ, GZ_WF_TXZ, GZ_WF_TAR };
    for (u32 i = 0; i < GZ_COUNTOF(pref); i++)
        if ((w = gz_writer_find(pref[i]))) return w;
    for (int i = 0; gz_writers[i]; i++)
        if (writerUsable(gz_writers[i], ninputs, singleFile)) return gz_writers[i];
    return NULL;
}

NSString *defaultArchiveName(NSArray<NSString *> *inputs, const gz_writer *w)
{
    NSString *first = inputs.firstObject;
    NSString *dir = first.stringByDeletingLastPathComponent;
    NSString *base;
    if (inputs.count == 1) {
        base = first.lastPathComponent;
        if (!pathIsDir(first) && !(w && singleStream(w->format)) && base.pathExtension.length &&
            base.stringByDeletingPathExtension.length)
            base = base.stringByDeletingPathExtension;       /* "report.txt" -> "report.zip" */
    } else {
        base = dir.lastPathComponent;
        if (!base.length || [base isEqual:@"/"]) base = @"archive";
    }
    NSString *file = [NSString stringWithFormat:@"%@.%s", base, w ? w->ext : "zip"];
    return [dir stringByAppendingPathComponent:file];
}

@interface GZCreateDialog : GZDialog
@end

@implementation GZCreateDialog {
@public
    NSTextField *_out, *_err;
    NSPopUpButton *_fmt, *_level, *_method, *_encm;
    NSButton *_solid, *_encn, *_show;
    GZPasswordField *_pw1, *_pw2;
    NSView *_encbox;
    const gz_writer *_wl[GZ_WF_COUNT + 8];
    int _nw;
    const gz_writer *_cur;
    int _methods[GZ_WM_COUNT], _nmethods;
    NSString *_base;
    GZShowToggle *_toggle;
}

- (const gz_writer *)writer
{
    NSInteger i = _fmt.indexOfSelectedItem;
    return i >= 0 && i < _nw ? _wl[i] : NULL;
}

/* "a.tar.gz" with the old extension "tar.gz" -> "a.zip" */
- (void)swapExtFrom:(const gz_writer *)old to:(const gz_writer *)nw
{
    NSString *t = _out.stringValue;
    NSString *base = nil;
    const gz_writer *cands[GZ_WF_COUNT + 9];
    int k = 0;
    if (old) cands[k++] = old;
    for (int i = 0; gz_writers[i] && k < (int)GZ_COUNTOF(cands); i++) cands[k++] = gz_writers[i];
    for (int i = 0; i < k && !base; i++) {
        NSString *e = [@"." stringByAppendingString:gzU8(cands[i]->ext)];
        if (t.length > e.length && [t.lowercaseString hasSuffix:e]) base = [t substringToIndex:t.length - e.length];
    }
    if (!base) base = t;
    _out.stringValue = [NSString stringWithFormat:@"%@.%s", base, nw->ext];
}

- (void)update:(id)sender
{
    const gz_writer *w = [self writer];
    if (!w) return;
    GZSettings *set = [GZSettings shared];
    if (_cur != w) {
        if (_cur) [self swapExtFrom:_cur to:w];
        _cur = w;
        [_method removeAllItems];
        _nmethods = 0;
        _methods[_nmethods++] = GZ_WM_DEFAULT;
        [_method addItemWithTitle:gzU8(gz_ui_method_name(GZ_WM_DEFAULT))];
        for (int m = 1; m < GZ_WM_COUNT; m++) {
            if (!(w->methods & (1u << m))) continue;
            _methods[_nmethods++] = m;
            [_method addItemWithTitle:gzU8(gz_ui_method_name(m))];
        }
        [_method selectItemAtIndex:0];
        [_encm removeAllItems];
        if (w->encryptions & (1u << GZ_WE_AES256)) {
            [_encm addItemWithTitle:@"AES-256"];
            _encm.lastItem.tag = GZ_WE_AES256;
        }
        if (w->encryptions & (1u << GZ_WE_ZIPCRYPTO)) {
            [_encm addItemWithTitle:@"ZipCrypto"];
            _encm.lastItem.tag = GZ_WE_ZIPCRYPTO;
        }
        if (_encm.numberOfItems && ![_encm selectItemWithTag:set.cEnc]) [_encm selectItemAtIndex:0];
    }
    BOOL enc = w->encryptions != 0;
    for (NSControl *c in @[ _pw1.secure, _pw1.plain, _pw2.secure, _pw2.plain, _encm, _show ]) c.enabled = enc;
    _encbox.toolTip = enc ? nil : TR(STR_C_NO_ENC);
    _solid.enabled = w->format == GZ_WF_7Z;
    _encn.enabled = enc && w->format == GZ_WF_7Z;
    _method.enabled = _level.indexOfSelectedItem != 0 && _nmethods > 1;
}

- (void)browse:(id)sender
{
    NSSavePanel *p = [NSSavePanel savePanel];
    p.title = TR(STR_C_SAVE_AS);
    p.canCreateDirectories = YES;
    NSString *cur = [self outputPath];
    if (cur.length) {
        NSString *dir = cur.stringByDeletingLastPathComponent;
        if (pathIsDir(dir)) p.directoryURL = [NSURL fileURLWithPath:dir isDirectory:YES];
        p.nameFieldStringValue = cur.lastPathComponent;
    }
    if ([p runModal] != NSModalResponseOK || !p.URL.path) return;
    _out.stringValue = displayPath(p.URL.path);
    gzch *w = gzPathW(p.URL.path);
    int fmt = w ? gz_format_from_name(w) : 0;
    gz_free(w);
    for (int i = 0; i < _nw; i++)
        if (_wl[i]->format == fmt) {
            _cur = _wl[i];
            [_fmt selectItemAtIndex:i];
            [self update:nil];
        }
}

- (NSString *)outputPath
{
    NSString *t = [_out.stringValue stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (!t.length) return nil;
    NSString *p = t.stringByExpandingTildeInPath;
    if (!p.absolutePath) p = [_base stringByAppendingPathComponent:p];
    return p.stringByStandardizingPath;
}

- (void)ok:(id)sender
{
    const gz_writer *w = [self writer];
    if (!w || ![self outputPath]) {
        _err.stringValue = TR(STR_C_NEED_NAME);
        return;
    }
    if (w->encryptions && ![_pw1.stringValue isEqual:_pw2.stringValue]) {
        _err.stringValue = TR(STR_C_PW_MISMATCH);
        return;
    }
    [self end:NSModalResponseOK];
}

@end

void dlgCreate(NSWindow *parent, NSArray<NSString *> *inputs, void (^done)(GZCreateChoice *c))
{
    if (!inputs.count) { done(nil); return; }
    GZSettings *set = [GZSettings shared];
    GZCreateDialog *c = [[GZCreateDialog alloc] init];
    NSUInteger n = inputs.count;
    BOOL single = n == 1 && !pathIsDir(inputs[0]);
    c->_base = [inputs[0] stringByDeletingLastPathComponent];
    for (int i = 0; gz_writers[i] && c->_nw < (int)GZ_COUNTOF(c->_wl); i++)
        if (writerUsable(gz_writers[i], n, single)) c->_wl[c->_nw++] = gz_writers[i];
    if (!c->_nw) {
        msgBox(parent, NSAlertStyleCritical, TR(STR_C_NO_WRITERS), nil);
        done(nil);
        return;
    }
    NSString *first = [inputs[0] lastPathComponent];
    NSString *sub = n > 1 ? TRF(STR_C_SOURCE_MANY, @[ first, [NSString stringWithFormat:@"%lu", (unsigned long)n - 1] ])
                          : first;
    c.window = dialogWindow(TR(STR_C_TITLE));

    c->_out = [NSTextField textFieldWithString:@""];
    c->_out.lineBreakMode = NSLineBreakByTruncatingHead;
    [c->_out.widthAnchor constraintGreaterThanOrEqualToConstant:300].active = YES;
    NSButton *br = [NSButton buttonWithTitle:TR(STR_BROWSE) target:c action:@selector(browse:)];
    NSStackView *orow = [NSStackView stackViewWithViews:@[ c->_out, br ]];
    orow.spacing = 8;

    c->_fmt = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    const gz_writer *dw = writerDefault(n, single);
    int act = 0;
    for (int i = 0; i < c->_nw; i++) {
        [c->_fmt addItemWithTitle:[NSString stringWithFormat:@"%s  (.%s)", c->_wl[i]->name, c->_wl[i]->ext]];
        if (c->_wl[i] == dw) act = i;
    }
    [c->_fmt selectItemAtIndex:act];
    c->_out.stringValue = displayPath(defaultArchiveName(inputs, c->_wl[act]));
    c->_level = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    int lact = 3;
    for (int i = 0; i < 6; i++) {
        [c->_level addItemWithTitle:[NSString stringWithFormat:@"%d - %@", gz_ui_levels[i],
                                                               gzU8(gz_ui_level_name(gz_ui_levels[i]))]];
        if (gz_ui_levels[i] <= set.cLevel) lact = i;
    }
    [c->_level selectItemAtIndex:lact];
    c->_method = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    for (NSPopUpButton *p in @[ c->_fmt, c->_level ]) {
        p.target = c;
        p.action = @selector(update:);
    }
    NSGridView *g = [NSGridView gridViewWithViews:@[
        @[ label(TR(STR_C_OUT)), orow ],
        @[ label(TR(STR_C_FORMAT)), c->_fmt ],
        @[ label(TR(STR_C_LEVEL)), c->_level ],
        @[ label(TR(STR_C_METHOD)), c->_method ],
    ]];
    g.rowSpacing = 8;
    g.columnSpacing = 12;
    [g columnAtIndex:0].xPlacement = NSGridCellPlacementTrailing;
    for (NSInteger r = 0; r < g.numberOfRows; r++) [g rowAtIndex:r].yPlacement = NSGridCellPlacementCenter;
    c->_solid = [NSButton checkboxWithTitle:TR(STR_C_SOLID) target:nil action:NULL];
    c->_solid.state = NSControlStateValueOn;

    c->_pw1 = [[GZPasswordField alloc] initWithFrame:NSMakeRect(0, 0, 260, 22)];
    c->_pw2 = [[GZPasswordField alloc] initWithFrame:NSMakeRect(0, 0, 260, 22)];
    c->_encm = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    c->_encn = [NSButton checkboxWithTitle:TR(STR_C_ENC_NAMES) target:nil action:NULL];
    c->_toggle = [[GZShowToggle alloc] init];
    c->_toggle.fields = @[ c->_pw1, c->_pw2 ];
    c->_show = [NSButton checkboxWithTitle:TR(STR_PW_SHOW) target:c->_toggle action:@selector(toggle:)];
    NSView *e = [NSGridCell emptyContentView];
    NSGridView *eg = [NSGridView gridViewWithViews:@[
        @[ label(TR(STR_C_PASSWORD)), c->_pw1 ],
        @[ label(TR(STR_C_PASSWORD2)), c->_pw2 ],
        @[ label(TR(STR_C_ENC_METHOD)), c->_encm ],
        @[ e, c->_encn ],
        @[ e, c->_show ],
    ]];
    eg.rowSpacing = 6;
    eg.columnSpacing = 12;
    [eg columnAtIndex:0].xPlacement = NSGridCellPlacementTrailing;
    for (NSInteger r = 0; r < eg.numberOfRows; r++) [eg rowAtIndex:r].yPlacement = NSGridCellPlacementCenter;
    c->_encbox = eg;                       /* "Encryption" section: a bold title over the grid */
    c->_err = label(@"");
    c->_err.textColor = [NSColor systemRedColor];

    NSButton *cancel = pushButton(TR(STR_CANCEL), c, @selector(cancel:), @"\e");
    NSButton *ok = pushButton(TR(STR_C_START), c, @selector(ok:), @"\r");
    NSView *buttons = buttonRow(@[], @[ cancel, ok ]);
    installContent(c.window, @[ header(IC_NEW, TR(STR_C_TITLE), sub), g, c->_solid, boldLabel(TR(STR_C_ENCRYPTION)),
                                eg, c->_err, buttons ],
                   @[ buttons ], 480);
    [c update:nil];
    c.window.initialFirstResponder = c->_out;

    [c beginOn:parent completion:^(NSModalResponse r) {
        GZCreateChoice *o = nil;
        const gz_writer *w = [c writer];
        NSString *out = [c outputPath];
        if (r == NSModalResponseOK && w && out) {
            o = [[GZCreateChoice alloc] init];
            o.output = out;
            o.format = w->format;
            NSInteger lv = c->_level.indexOfSelectedItem;
            o.level = lv >= 0 && lv < 6 ? gz_ui_levels[lv] : 5;
            NSInteger mi = c->_method.indexOfSelectedItem;
            o.method = o.level == 0 ? ((w->methods & (1u << GZ_WM_STORE)) ? GZ_WM_STORE : GZ_WM_DEFAULT)
                                    : (mi > 0 && mi < c->_nmethods ? c->_methods[mi] : GZ_WM_DEFAULT);
            o.solid = w->format == GZ_WF_7Z && isOn(c->_solid);
            NSString *pw = c->_pw1.stringValue;
            if (w->encryptions && pw.length) {
                o.password = pw;
                o.encryption = c->_encm.selectedItem ? (int)c->_encm.selectedItem.tag : GZ_WE_AES256;
                o.encryptNames = w->format == GZ_WF_7Z && isOn(c->_encn);
                set.cEnc = o.encryption;
            }
            set.cFormat = o.format;
            set.cLevel = o.level;
            [set save];
        }
        [c->_pw1 setStringValue:@""];
        [c->_pw2 setStringValue:@""];
        done(o);
    }];
}

GZRun *startCompress(NSArray<NSString *> *inputs, GZCreateChoice *c, NSWindow *parent, int overwrite, int flags,
                     GZRunDone done)
{
    u32 n = (u32)inputs.count;
    gzch **in = (gzch **)calloc(n + 1, sizeof(gzch *));
    if (!in) return nil;
    for (u32 i = 0; i < n; i++) in[i] = gzPathW(inputs[i]);
    gzch *wout = gzPathW(c.output), *wpw = c.password.length ? gzW(c.password) : NULL;
    gz_compress_opts co;
    memset(&co, 0, sizeof co);
    co.out = wout;
    co.inputs = (const gzch *const *)in;
    co.ninputs = n;
    co.format = c.format;
    co.method = c.method;
    co.level = c.level;
    co.solid = c.solid;
    co.encryption = wpw ? c.encryption : GZ_WE_NONE;
    co.password = wpw;
    co.encrypt_names = c.encryptNames;
    co.threads = (int)[GZSettings shared].threads;
    co.overwrite = overwrite;
    BOOL ok = wout != NULL;
    for (u32 i = 0; i < n; i++) ok = ok && in[i];
    GZRun *r = ok ? [GZRun compressWithOptions:&co parent:parent flags:flags done:done] : nil;
    for (u32 i = 0; i < n; i++) gz_free(in[i]);
    free(in);
    gz_free(wout);
    gzWipeFree(wpw);
    return r;
}

/* ======================================================================
 * archive information
 * ====================================================================== */

@interface GZInfoDialog : GZDialog
@end
@implementation GZInfoDialog
@end

void dlgInfo(NSWindow *parent, gz_handle *h, NSString *arcPath)
{
    gz_archive *a = h->arc;
    NSMutableArray<NSArray *> *rows = [NSMutableArray array];
    void (^add)(int, NSString *) = ^(int key, NSString *val) {
        NSTextField *k = label(TR(key));
        k.textColor = [NSColor secondaryLabelColor];
        NSTextField *v = [NSTextField wrappingLabelWithString:val ? val : @""];
        v.selectable = YES;
        v.preferredMaxLayoutWidth = 380;
        [rows addObject:@[ k, v ]];
    };
    add(STR_I_PATH, displayPath(arcPath));
    add(STR_I_FORMAT, gzU8(gz_arc_type_name(a)));
    u64 fsz = a->src_size ? a->src_size : (h->src ? h->src->size : 0);
    add(STR_I_FILESIZE, [NSString stringWithFormat:@"%@ (%@ B)", fmtSize(fsz), fmtThousands(fsz)]);
    add(STR_I_CONTENTS, TRF(STR_I_CONTENTS_FMT, @[ fmtThousands(a->nfiles), fmtThousands(a->ndirs) ]));
    add(STR_I_USIZE, [NSString stringWithFormat:@"%@ (%@ B)", fmtSize(a->total_usize), fmtThousands(a->total_usize)]);
    if (a->total_usize) {
        char pc[16];
        gz_ui_fmt_percent(pc, sizeof pc, a->total_csize, a->total_usize);
        add(STR_I_RATIO, [NSString stringWithFormat:@"%s  (%@)", pc, fmtSize(a->total_csize)]);
    }
    /* methods, most frequent first */
    NSCountedSet *ms = [[NSCountedSet alloc] init];
    for (u32 i = 0; i < a->n; i++) {
        if (a->e[i].is_dir) continue;
        gzch w[96];
        gz_arc_method(a, &a->e[i], w, 96);
        if (w[0]) [ms addObject:gzNS(w)];
    }
    if (ms.count) {
        NSArray *sorted = [ms.allObjects sortedArrayUsingComparator:^NSComparisonResult(id x, id y) {
            NSUInteger cx = [ms countForObject:x], cy = [ms countForObject:y];
            return cx > cy ? NSOrderedAscending : cx < cy ? NSOrderedDescending : [x compare:y];
        }];
        NSArray *top = sorted.count > 4 ? [sorted subarrayWithRange:NSMakeRange(0, 4)] : sorted;
        NSString *s = [top componentsJoinedByString:@", "];
        if (sorted.count > 4) s = [s stringByAppendingString:@", …"];
        add(STR_I_METHOD, s);
    }
    add(STR_I_ENC, TR(a->headers_enc ? STR_I_HDR_ENC : a->has_enc ? STR_I_YES : STR_I_NO));
    if (a->solid) add(STR_I_SOLID, TR(STR_I_YES));
    if (a->any_legacy || a->any_utf8) {
        const char *cn = a->any_legacy ? gz_ui_cp_name(a->used_cp) : NULL;
        NSString *cps = cn ? gzU8(cn) : [NSString stringWithFormat:@"CP%d", a->used_cp];
        add(STR_I_CP, a->any_legacy && a->any_utf8 ? [@"UTF-8 + " stringByAppendingString:cps]
                                                   : (a->any_legacy ? cps : @"UTF-8"));
    }
    if (a->nvols) add(STR_I_VOLUMES, [NSString stringWithFormat:@"%u", a->nvols + 1]);
    if (a->sfx_shift) add(STR_I_FORMAT, TRF(STR_I_SFX, @[ fmtSize(a->sfx_shift) ]));
    NSGridView *g = [NSGridView gridViewWithViews:rows];
    g.rowSpacing = 6;
    g.columnSpacing = 16;
    [g columnAtIndex:0].xPlacement = NSGridCellPlacementTrailing;

    GZInfoDialog *d = [[GZInfoDialog alloc] init];
    d.window = dialogWindow(TR(STR_I_TITLE));
    NSMutableArray *content = [NSMutableArray arrayWithObjects:header(IC_INFO, TR(STR_I_TITLE), gzNS(h->name)), g, nil];
    NSMutableArray *fill = [NSMutableArray array];
    if (a->comment && a->comment[0]) {
        [content addObject:boldLabel(TR(STR_I_COMMENT))];
        NSScrollView *sv = [[NSScrollView alloc] initWithFrame:NSMakeRect(0, 0, 460, 110)];
        sv.hasVerticalScroller = YES;
        sv.borderType = NSBezelBorder;
        NSTextView *tv = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, sv.contentSize.width, sv.contentSize.height)];
        tv.editable = NO;
        tv.verticallyResizable = YES;
        tv.autoresizingMask = NSViewWidthSizable;
        tv.textContainer.widthTracksTextView = YES;
        tv.string = gzNS(a->comment);
        sv.documentView = tv;
        [sv.heightAnchor constraintEqualToConstant:110].active = YES;
        [content addObject:sv];
        [fill addObject:sv];
    }
    NSButton *close = pushButton(TR(STR_CLOSE), d, @selector(ok:), @"\r");
    NSView *buttons = buttonRow(@[], @[ close ]);
    [content addObject:buttons];
    [fill addObject:buttons];
    installContent(d.window, content, fill, 440);
    [d beginOn:parent completion:^(NSModalResponse r) {}];
}

/* ======================================================================
 * job results
 * ====================================================================== */

void dlgResult(NSWindow *parent, gz_job *j, int kind, int result, BOOL quietOk, void (^done)(void))
{
    gz_progress p;
    gz_job_progress(j, &p);
    u32 nlog = gz_job_log_count(j), shown = 0;
    for (u32 i = 0; i < nlog; i++) {
        const gz_log *l = gz_job_log_at(j, i);
        if (l && l->level >= GZ_LOG_WARN) shown++;
    }
    NSAlert *a = [[NSAlert alloc] init];
    [a addButtonWithTitle:TR(STR_OK)];
    if (result == GZ_E_CANCEL) {
        if (quietOk) { done(); return; }
        a.messageText = TR(STR_R_CANCELED);
        runAlert(a, parent, ^(NSModalResponse r) { done(); });
        return;
    }
    if (!result && !p.errors && !shown) {
        if (kind != RK_TEST || quietOk) { done(); return; }
        char sp[48];
        gz_ui_fmt_speed(sp, sizeof sp, p.elapsed_ms ? p.done_bytes * 1000 / p.elapsed_ms : p.done_bytes);
        char dur[32];
        gz_ui_fmt_duration(dur, sizeof dur, (p.elapsed_ms + 500) / 1000);
        a.messageText = TR(STR_R_TEST_OK);
        a.informativeText = TRF(STR_R_STATS, @[ fmtThousands(p.done_files), fmtSize(p.done_bytes), gzU8(dur), gzU8(sp) ]);
        a.icon = gzIcon(IC_CHECK, 64);
        runAlert(a, parent, ^(NSModalResponse r) { done(); });
        return;
    }
    if (p.errors) a.messageText = TRF(STR_R_ERRORS, @[ [NSString stringWithFormat:@"%u", p.errors] ]);
    else if (result) a.messageText = TR(STR_R_FAILED);
    else a.messageText = TRF(STR_R_WARNINGS, @[ [NSString stringWithFormat:@"%u", p.warnings] ]);
    a.alertStyle = p.errors || result ? NSAlertStyleCritical : NSAlertStyleWarning;
    a.icon = gzIcon(p.errors || result ? IC_ERROR : IC_WARN, 64);
    NSMutableString *txt = [NSMutableString string];
    u32 lines = 0;
    for (u32 i = 0; i < nlog && lines < 5000; i++) {
        const gz_log *l = gz_job_log_at(j, i);
        if (!l || l->level < GZ_LOG_WARN) continue;
        NSString *msg = gzU8(gz_ui_code_text(l->code));
        if (l->detail) msg = [NSString stringWithFormat:@"%@: %@", msg, gzNS(l->detail)];
        [txt appendFormat:@"%@\t%@\n\t%@\n", TR(l->level == GZ_LOG_ERROR ? STR_L_ERROR : STR_L_WARN), gzNS(l->name),
                          msg];
        lines++;
    }
    if (!shown && result) [txt appendFormat:@"%@\t%s\n", TR(STR_L_ERROR), gz_ui_code_text(result)];
    NSScrollView *sv = [[NSScrollView alloc] initWithFrame:NSMakeRect(0, 0, 520, 180)];
    sv.hasVerticalScroller = YES;
    sv.borderType = NSBezelBorder;
    NSTextView *tv = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, sv.contentSize.width, sv.contentSize.height)];
    tv.editable = NO;
    tv.verticallyResizable = YES;
    tv.autoresizingMask = NSViewWidthSizable;
    tv.textContainer.widthTracksTextView = YES;
    tv.font = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
    tv.string = txt;
    sv.documentView = tv;
    a.accessoryView = sv;
    runAlert(a, parent, ^(NSModalResponse r) { done(); });
}

/* ======================================================================
 * about
 * ====================================================================== */

void dlgAbout(void)
{
    int nr = 0, nw = 0;
    while (gz_formats[nr]) nr++;
    while (gz_writers[nw]) nw++;
    NSString *fm = TRF(STR_A_FORMATS, @[ [NSString stringWithFormat:@"%d", nr], [NSString stringWithFormat:@"%d", nw] ]);
    NSString *cpu = g_cpu.brand[0] ? gzU8(g_cpu.brand) : gzU8(g_cpu.vendor);
    NSString *body = [NSString stringWithFormat:@"%@\n\n%@\n%@: %@\n%@: %@\n\n", TR(STR_TAGLINE), fm, TR(STR_A_CPU), cpu,
                                                TR(STR_A_ENGINE), engineLine()];
    NSMutableParagraphStyle *ps = [[NSMutableParagraphStyle alloc] init];
    ps.alignment = NSTextAlignmentCenter;
    NSDictionary *at = @{
        NSFontAttributeName : [NSFont systemFontOfSize:[NSFont smallSystemFontSize]],
        NSForegroundColorAttributeName : [NSColor labelColor],
        NSParagraphStyleAttributeName : ps
    };
    NSMutableAttributedString *cr = [[NSMutableAttributedString alloc] initWithString:body attributes:at];
    NSMutableDictionary *link = [at mutableCopy];
    link[NSLinkAttributeName] = [NSURL URLWithString:GZ_HOMEPAGE];
    [cr appendAttributedString:[[NSAttributedString alloc] initWithString:TR(STR_A_HOME) attributes:link]];
    [NSApp activateIgnoringOtherApps:YES];
    [NSApp orderFrontStandardAboutPanelWithOptions:@{
        NSAboutPanelOptionApplicationName : TR(STR_APP),
        NSAboutPanelOptionApplicationVersion : @GZ_APP_VERSION,
        NSAboutPanelOptionVersion : @"",
        NSAboutPanelOptionCredits : cr,
        NSAboutPanelOptionApplicationIcon : gzIcon(IC_LOGO, 96),
    }];
}
