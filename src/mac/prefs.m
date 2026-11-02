/*
 * 고깃ZIP macOS - settings (NSUserDefaults), recent archives, preferences window
 *
 * The preferences window applies every change at once, as Mac preference
 * windows do. The language takes effect at the next start.
 */
#import "app.h"
#import <CoreServices/CoreServices.h>

static NSInteger clampi(NSInteger v, NSInteger lo, NSInteger hi, NSInteger def) { return v < lo || v > hi ? def : v; }

@implementation GZSettings {
    NSMutableArray<NSString *> *_recentList;
}

+ (GZSettings *)shared
{
    static GZSettings *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [[GZSettings alloc] init];
        [s load];
    });
    return s;
}

- (void)load
{
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d registerDefaults:@{
        @"language" : @0, @"codepage" : @0, @"threads" : @0, @"overwrite" : @(GZ_OW_ASK), @"smart" : @YES,
        @"openFolder" : @YES, @"paths" : @(GZ_PATH_FULL), @"destMode" : @0, @"showTree" : @YES,
        @"createFormat" : @(GZ_WF_ZIP), @"createLevel" : @5, @"createEncryption" : @(GZ_WE_AES256)
    }];
    _lang = clampi([d integerForKey:@"language"], 0, 2, 0);
    _codepage = clampi([d integerForKey:@"codepage"], 0, 65535, 0);
    if (_codepage && !gz_plat_cp_valid((int)_codepage)) _codepage = 0;
    _threads = clampi([d integerForKey:@"threads"], 0, 256, 0);
    _overwrite = clampi([d integerForKey:@"overwrite"], GZ_OW_ASK, GZ_OW_NEWER, GZ_OW_ASK);
    _pathMode = clampi([d integerForKey:@"paths"], GZ_PATH_FULL, GZ_PATH_NONE, GZ_PATH_FULL);
    _destMode = clampi([d integerForKey:@"destMode"], 0, 1, 0);
    _smart = [d boolForKey:@"smart"];
    _openFolder = [d boolForKey:@"openFolder"];
    _showTree = [d boolForKey:@"showTree"];
    _cFormat = clampi([d integerForKey:@"createFormat"], 1, GZ_WF_COUNT - 1, GZ_WF_ZIP);
    _cLevel = clampi([d integerForKey:@"createLevel"], 0, 9, 5);
    _cEnc = clampi([d integerForKey:@"createEncryption"], GZ_WE_ZIPCRYPTO, GZ_WE_AES256, GZ_WE_AES256);
    NSString *dest = [d stringForKey:@"dest"];
    _dest = dest.absolutePath ? dest : nil;
    _recentList = [NSMutableArray array];
    for (id p in [d arrayForKey:@"recent"]) {
        if ([p isKindOfClass:[NSString class]] && [p isAbsolutePath] && _recentList.count < GZ_RECENT_MAX)
            [_recentList addObject:p];
    }
}

- (void)save
{
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setInteger:_lang forKey:@"language"];
    [d setInteger:_codepage forKey:@"codepage"];
    [d setInteger:_threads forKey:@"threads"];
    [d setInteger:_overwrite forKey:@"overwrite"];
    [d setInteger:_pathMode forKey:@"paths"];
    [d setInteger:_destMode forKey:@"destMode"];
    [d setBool:_smart forKey:@"smart"];
    [d setBool:_openFolder forKey:@"openFolder"];
    [d setBool:_showTree forKey:@"showTree"];
    [d setInteger:_cFormat forKey:@"createFormat"];
    [d setInteger:_cLevel forKey:@"createLevel"];
    [d setInteger:_cEnc forKey:@"createEncryption"];
    if (_dest) [d setObject:_dest forKey:@"dest"];
    else [d removeObjectForKey:@"dest"];
    [d setObject:[_recentList copy] forKey:@"recent"];
}

- (NSArray<NSString *> *)recent { return [_recentList copy]; }

- (void)addRecent:(NSString *)path
{
    if (!path.absolutePath) return;
    [_recentList removeObject:path];
    [_recentList insertObject:path atIndex:0];
    while (_recentList.count > GZ_RECENT_MAX) [_recentList removeLastObject];
    [self save];
    /* the Dock menu and the system's recent items */
    [[NSDocumentController sharedDocumentController] noteNewRecentDocumentURL:[NSURL fileURLWithPath:path]];
}

- (void)clearRecent
{
    [_recentList removeAllObjects];
    [self save];
    [[NSDocumentController sharedDocumentController] clearRecentDocuments:nil];
}

- (int)effectiveThreads { return _threads > 0 ? (int)_threads : gz_os_cpu_count(); }

@end

BOOL uiKorean(NSString *forced)
{
    if (forced.length) return gz_ui_locale_korean(forced.UTF8String) != 0;
    NSInteger l = [GZSettings shared].lang;
    if (l) return l == 1;
    /* the localization the system picks for this app (the same one its standard panels use) */
    NSArray<NSString *> *loc = [NSBundle preferredLocalizationsFromArray:@[ @"en", @"ko" ]];
    NSString *first = loc.firstObject;
    return first && gz_ui_locale_korean(first.UTF8String);
}

/* ======================================================================
 * file associations: LaunchServices default handler for our archive types
 * ====================================================================== */

int assocSetDefault(int *failed)
{
    int ok = 0, bad = 0;
    NSString *bid = [NSBundle mainBundle].bundleIdentifier;
    NSArray *types = [NSBundle mainBundle].infoDictionary[@"CFBundleDocumentTypes"];
    NSMutableSet<NSString *> *done = [NSMutableSet set];
    for (NSDictionary *t in types) {
        if (![t isKindOfClass:[NSDictionary class]]) continue;
        if (![t[@"LSHandlerRank"] isEqual:@"Default"]) continue;       /* archives, not disk images */
        for (NSString *uti in t[@"LSItemContentTypes"]) {
            if (![uti isKindOfClass:[NSString class]] || [done containsObject:uti]) continue;
            [done addObject:uti];
            if (!bid) { bad++; continue; }
            OSStatus st = LSSetDefaultRoleHandlerForContentType((__bridge CFStringRef)uti, kLSRolesAll,
                                                                (__bridge CFStringRef)bid);
            if (st == noErr) ok++;
            else bad++;
        }
    }
    if (failed) *failed = bad;
    return ok;
}

/* ======================================================================
 * preferences window
 * ====================================================================== */

static const int k_threads[] = { 0, 1, 2, 4, 6, 8, 12, 16, 24, 32, 64 };

@interface GZPrefsController : NSWindowController <NSWindowDelegate>
@end

@implementation GZPrefsController {
    NSPopUpButton *_lang, *_cp, *_threads, *_ow;
    NSButton *_destArc, *_destCustom, *_choose, *_smart, *_openFolder;
    NSTextField *_destLabel;
    NSInteger _langAtStart;
}

static NSTextField *boldLabel(NSString *s)
{
    NSTextField *l = [NSTextField labelWithString:s];
    l.font = [NSFont boldSystemFontOfSize:[NSFont systemFontSize]];
    return l;
}

static NSTextField *dimWrap(NSString *s, CGFloat w)
{
    NSTextField *l = [NSTextField wrappingLabelWithString:s];
    l.textColor = [NSColor secondaryLabelColor];
    l.font = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
    l.preferredMaxLayoutWidth = w;
    return l;
}

- (instancetype)init
{
    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 520, 400)
                                              styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                                                backing:NSBackingStoreBuffered
                                                  defer:YES];
    w.title = TRP(STR_S_TITLE);
    w.releasedWhenClosed = NO;
    self = [super initWithWindow:w];
    if (!self) return nil;
    w.delegate = self;
    [self build];
    return self;
}

- (NSPopUpButton *)popup:(NSArray<NSString *> *)items selected:(NSInteger)sel
{
    NSPopUpButton *p = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    [p addItemsWithTitles:items];
    if (sel >= 0 && sel < (NSInteger)items.count) [p selectItemAtIndex:sel];
    p.target = self;
    p.action = @selector(changed:);
    return p;
}

- (void)build
{
    GZSettings *s = [GZSettings shared];
    _langAtStart = s.lang;
    _lang = [self popup:@[ TR(STR_S_LANG_AUTO), TR(STR_S_LANG_KO), TR(STR_S_LANG_EN) ] selected:s.lang];

    _cp = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    for (u32 i = 0; i < gz_ui_ncodepages; i++) {
        int cp = gz_ui_codepages[i].cp;
        if (cp && !gz_plat_cp_valid(cp)) continue;
        [_cp addItemWithTitle:TR(gz_ui_codepages[i].sid)];
        _cp.lastItem.tag = cp;
    }
    if (![_cp selectItemWithTag:s.codepage]) [_cp selectItemAtIndex:0];
    _cp.target = self;
    _cp.action = @selector(changed:);

    _threads = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    for (u32 i = 0; i < GZ_COUNTOF(k_threads); i++) {
        NSString *t = i ? [NSString stringWithFormat:@"%d", k_threads[i]]
                        : TRF(STR_S_AUTO_N, @[ [NSString stringWithFormat:@"%d", gz_os_cpu_count()] ]);
        [_threads addItemWithTitle:t];
        _threads.lastItem.tag = k_threads[i];
    }
    if (![_threads selectItemWithTag:s.threads]) [_threads selectItemAtIndex:0];
    _threads.target = self;
    _threads.action = @selector(changed:);

    _destArc = [NSButton radioButtonWithTitle:TR(STR_S_DEST_ARC) target:self action:@selector(destMode:)];
    _destCustom = [NSButton radioButtonWithTitle:TR(STR_S_DEST_CUSTOM) target:self action:@selector(destMode:)];
    _destLabel = [NSTextField labelWithString:@""];
    _destLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
    _destLabel.textColor = [NSColor secondaryLabelColor];
    [_destLabel setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow
                                         forOrientation:NSLayoutConstraintOrientationHorizontal];
    _choose = [NSButton buttonWithTitle:MS(MS_DEST_CHOOSE) target:self action:@selector(chooseDest:)];
    NSStackView *custom = [NSStackView stackViewWithViews:@[ _destCustom, _destLabel, _choose ]];
    custom.spacing = 8;

    _smart = [NSButton checkboxWithTitle:TR(STR_S_SMART) target:self action:@selector(changed:)];
    _ow = [self popup:@[ TR(STR_OW_ASK), TR(STR_OW_ALL), TR(STR_OW_SKIP), TR(STR_OW_RENAME), TR(STR_OW_NEWER) ]
             selected:s.overwrite];
    _openFolder = [NSButton checkboxWithTitle:TR(STR_X_OPENFOLDER) target:self action:@selector(changed:)];

    NSButton *assoc = [NSButton buttonWithTitle:TR(STR_S_ASSOC_BTN) target:self action:@selector(makeDefault:)];

    NSView *e = [NSGridCell emptyContentView];
    NSGridView *g = [NSGridView gridViewWithViews:@[
        @[ boldLabel(TR(STR_S_GENERAL)), e ],
        @[ [NSTextField labelWithString:TR(STR_S_LANG)], _lang ],
        @[ [NSTextField labelWithString:TR(STR_S_CODEPAGE)], _cp ],
        @[ [NSTextField labelWithString:TR(STR_S_THREADS)], _threads ],
        @[ boldLabel(TR(STR_S_EXTRACT)), e ],
        @[ [NSTextField labelWithString:TR(STR_S_DEST)], _destArc ],
        @[ e, custom ],
        @[ e, _smart ],
        @[ [NSTextField labelWithString:TR(STR_S_OVERWRITE)], _ow ],
        @[ e, _openFolder ],
        @[ boldLabel(TR(STR_S_ASSOC)), e ],
        @[ e, dimWrap(MS(MS_ASSOC_DESC), 330) ],
        @[ e, assoc ],
        @[ e, dimWrap(MS(MS_SERVICES_NOTE), 330) ],
    ]];
    g.rowSpacing = 8;
    g.columnSpacing = 12;
    [g columnAtIndex:0].xPlacement = NSGridCellPlacementTrailing;
    for (NSInteger r = 0; r < g.numberOfRows; r++) [g rowAtIndex:r].yPlacement = NSGridCellPlacementCenter;
    /* section titles start at the left edge */
    for (NSNumber *r in @[ @0, @4, @10 ]) {
        NSGridCell *c = [g cellAtColumnIndex:0 rowIndex:r.integerValue];
        c.xPlacement = NSGridCellPlacementLeading;
        [g rowAtIndex:r.integerValue].topPadding = r.integerValue ? 10 : 0;
    }
    g.translatesAutoresizingMaskIntoConstraints = NO;
    NSView *cv = [[NSView alloc] initWithFrame:NSZeroRect];
    [cv addSubview:g];
    [NSLayoutConstraint activateConstraints:@[
        [g.leadingAnchor constraintEqualToAnchor:cv.leadingAnchor constant:20],
        [g.trailingAnchor constraintEqualToAnchor:cv.trailingAnchor constant:-20],
        [g.topAnchor constraintEqualToAnchor:cv.topAnchor constant:20],
        [g.bottomAnchor constraintEqualToAnchor:cv.bottomAnchor constant:-20],
        [_destLabel.widthAnchor constraintLessThanOrEqualToConstant:200],
    ]];
    self.window.contentView = cv;
    [self.window setContentSize:cv.fittingSize];
    [self refresh];
}

- (void)refresh
{
    GZSettings *s = [GZSettings shared];
    _destArc.state = s.destMode == 0 ? NSControlStateValueOn : NSControlStateValueOff;
    _destCustom.state = s.destMode == 1 ? NSControlStateValueOn : NSControlStateValueOff;
    _destLabel.stringValue = s.dest ? displayPath(s.dest) : @"";
    _destLabel.toolTip = s.dest;
    _smart.state = s.smart ? NSControlStateValueOn : NSControlStateValueOff;
    _openFolder.state = s.openFolder ? NSControlStateValueOn : NSControlStateValueOff;
}

- (void)changed:(id)sender
{
    GZSettings *s = [GZSettings shared];
    s.lang = _lang.indexOfSelectedItem < 0 ? 0 : _lang.indexOfSelectedItem;
    s.codepage = _cp.selectedItem ? _cp.selectedItem.tag : 0;
    s.threads = _threads.selectedItem ? _threads.selectedItem.tag : 0;
    s.overwrite = _ow.indexOfSelectedItem < 0 ? GZ_OW_ASK : _ow.indexOfSelectedItem;
    s.smart = _smart.state == NSControlStateValueOn;
    s.openFolder = _openFolder.state == NSControlStateValueOn;
    [s save];
    if (sender == _lang && s.lang != _langAtStart) {
        _langAtStart = s.lang;
        msgBox(self.window, NSAlertStyleInformational, TR(STR_S_RESTART), nil);
    }
}

- (void)destMode:(id)sender
{
    GZSettings *s = [GZSettings shared];
    s.destMode = sender == _destCustom ? 1 : 0;
    if (s.destMode == 1 && !s.dest) {
        [self chooseDest:nil];
        if (!s.dest) s.destMode = 0;
    }
    [s save];
    [self refresh];
}

- (void)chooseDest:(id)sender
{
    GZSettings *s = [GZSettings shared];
    NSOpenPanel *p = [NSOpenPanel openPanel];
    p.canChooseDirectories = YES;
    p.canChooseFiles = NO;
    p.canCreateDirectories = YES;
    p.allowsMultipleSelection = NO;
    p.message = TR(STR_X_PICK);
    p.prompt = TR(STR_SELECT);
    if (s.dest && pathIsDir(s.dest)) p.directoryURL = [NSURL fileURLWithPath:s.dest isDirectory:YES];
    if ([p runModal] == NSModalResponseOK && p.URL.path) {
        s.dest = p.URL.path;
        s.destMode = 1;
        [s save];
    }
    [self refresh];
}

- (void)makeDefault:(id)sender
{
    int failed = 0, n = assocSetDefault(&failed);
    NSString *msg = TRF(STR_S_ASSOC_DONE, @[ [NSString stringWithFormat:@"%d", n] ]);
    if (failed || !n) msgBox(self.window, NSAlertStyleWarning, MS(MS_ASSOC_FAIL), msg);
    else msgBox(self.window, NSAlertStyleInformational, msg, nil);
}

@end

void prefsShow(void)
{
    static GZPrefsController *c;
    if (!c) {
        c = [[GZPrefsController alloc] init];
        [c.window center];
    }
    [c showWindow:nil];
    [c.window makeKeyAndOrderFront:nil];
}
