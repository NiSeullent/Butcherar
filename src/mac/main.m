/*
 * 고깃ZIP macOS - start-up, menus, Finder integration and command line modes
 *
 *   GogitZIP [archive]                    main window
 *   GogitZIP --extract-here  ARCHIVE...   into each archive's folder
 *   GogitZIP --extract-smart ARCHIVE...   into a folder named after the archive when needed
 *   GogitZIP --extract-to DIR ARCHIVE...  into DIR
 *   GogitZIP --extract ARCHIVE...         ask with the extract window
 *   GogitZIP --test ARCHIVE...            test
 *   GogitZIP --compress FILE...           create window (no files: pick them first)
 *        [--output ARCHIVE] [--format zip|7z|tar|tgz|...] [--level 0-9] [--yes]
 *   options: --yes  answer questions automatically (overwrite, no windows but progress;
 *                   problems on stderr), --lang ko|en
 * (run the binary inside the bundle, or: open -a GogitZIP --args --extract-to ...)
 * The command line modes show only progress windows and exit with 0 ok, 1 warnings,
 * 2 errors, 7 usage, 255 canceled.
 *
 * Finder: double-clicked / dropped documents arrive through application:openFiles:;
 * the Services (Info.plist NSServices) "Compress with GogitZIP", "Extract Here" and
 * "Extract to Folder" call compressFiles: / extractHere: / extractSmart: below.
 */
#import "app.h"

enum { MODE_GUI = 0, MODE_HERE, MODE_SMART, MODE_TO, MODE_DIALOG, MODE_TEST, MODE_COMPRESS };

/* ======================================================================
 * batches: extract / test archives one after another
 * ====================================================================== */

static NSMutableSet *s_batches;

@implementation GZBatch {
    NSArray<NSString *> *_files;
    int _mode, _exit;
    NSString *_dest;
    BOOL _yes, _stopped;
    void (^_done)(int);
    NSUInteger _idx;
    gz_handle *_h;
}

- (instancetype)initWithFiles:(NSArray<NSString *> *)files mode:(int)mode dest:(NSString *)dest yes:(BOOL)yes
                         done:(void (^)(int))done
{
    self = [super init];
    if (!self) return nil;
    _files = [files copy];
    _mode = mode;
    _dest = [dest copy];
    _yes = yes;
    _done = [done copy];
    return self;
}

- (void)worst:(int)code
{
    if (code == EXIT_BREAK || _exit == EXIT_BREAK) _exit = EXIT_BREAK;
    else if (code > _exit) _exit = code;
}

- (void)start
{
    if (!s_batches) s_batches = [NSMutableSet set];
    [s_batches addObject:self];
    [self next];
}

- (void)finish
{
    if (_h) gz_handle_close(_h);
    _h = NULL;
    void (^d)(int) = _done;
    _done = nil;
    [s_batches removeObject:self];
    if (d) d(_exit);
}

- (void)next
{
    if (_stopped || _idx >= _files.count) { [self finish]; return; }
    NSString *p = _files[_idx++];
    GZRun *r = [GZRun openPath:p codepage:(int)[GZSettings shared].codepage parent:nil
                          done:^(GZRun *run, int res) { [self opened:run path:p result:res]; }];
    if (!r) {
        [self worst:EXIT_FATAL];
        [self next];
    }
}

- (void)extracted:(GZRun *)run result:(int)res
{
    [self worst:[run exitCode]];
    gz_handle_close(_h);
    _h = NULL;
    if (res == GZ_E_CANCEL) _stopped = YES;
    [self next];
}

- (void)extractWith:(gz_extract_opts *)xo dest:(NSString *)dest flags:(int)flags
{
    gzch *wd = gzPathW(dest);
    xo->dest = wd;
    xo->threads = (int)[GZSettings shared].threads;
    GZRun *x = wd ? [GZRun extractHandle:_h options:xo parent:nil flags:flags
                                    done:^(GZRun *run, int res) { [self extracted:run result:res]; }]
                  : nil;
    gz_free(wd);
    if (!x) {
        [self worst:EXIT_FATAL];
        gz_handle_close(_h);
        _h = NULL;
        [self next];
    }
}

- (void)opened:(GZRun *)run path:(NSString *)p result:(int)res
{
    _h = [run takeHandle];
    if (!_h) {
        const char *why = gz_ui_code_text(res ? res : GZ_E_FORMAT);
        fprintf(stderr, "%s: %s : %s\n", gz_ui_str(STR_L_ERROR), displayPath(p).UTF8String, why);
        if (res != GZ_E_CANCEL && !_yes)
            msgBox(nil, NSAlertStyleWarning, TR(STR_OPEN_FAIL), [NSString stringWithFormat:@"%@\n%s", displayPath(p), why]);
        [self worst:res == GZ_E_CANCEL ? EXIT_BREAK : EXIT_FATAL];
        if (res == GZ_E_CANCEL) _stopped = YES;
        [self next];
        return;
    }
    GZSettings *set = [GZSettings shared];
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    NSString *dest = _mode == BATCH_TO && _dest ? _dest : p.stringByDeletingLastPathComponent;
    int flags = RUN_QUIET_OK | (_yes ? RUN_QUIET | RUN_LOG_STDERR | RUN_DELAY : 0);   /* --yes: no window for quick jobs */
    xo.overwrite = _yes ? GZ_OW_ALL : (int)set.overwrite;
    xo.smart = _mode == BATCH_SMART;
    xo.path_mode = GZ_PATH_FULL;
    if (_mode == BATCH_TEST) {
        xo.test = 1;
        if (!_yes) flags &= ~RUN_QUIET_OK;
        [self extractWith:&xo dest:dest flags:flags];
    } else if (_mode == BATCH_DIALOG) {
        dlgExtract(nil, _h, p, 0, ^(GZExtractChoice *c) {
            if (!c) {
                gz_handle_close(self->_h);
                self->_h = NULL;
                [self next];
                return;
            }
            gz_extract_opts o2 = xo;
            o2.smart = c.smart;
            o2.overwrite = c.overwrite;
            o2.path_mode = c.pathMode;
            [self extractWith:&o2 dest:c.dest flags:flags | (c.openFolder ? RUN_OPEN_DEST : 0)];
        });
    } else {
        [self extractWith:&xo dest:dest flags:flags];
    }
}

@end

/* ======================================================================
 * application delegate
 * ====================================================================== */

@interface GZAppDelegate : NSObject <NSApplicationDelegate>
@property (nonatomic) int mode, yes, level, format, exitCode;
@property (nonatomic, copy) NSString *to, *output;
@property (nonatomic, strong) NSMutableArray<NSString *> *files;      /* absolute paths from argv */
@end

@implementation GZAppDelegate {
    BOOL _launched, _mainShown, _serviceLaunch;
    NSMutableArray<NSString *> *_pendingOpen;       /* documents that arrived before launch ended */
}

/* ---------------- menus ---------------- */

static NSMenuItem *mi(NSMenu *m, NSString *title, SEL action, NSString *key, id target)
{
    NSMenuItem *it = [m addItemWithTitle:title action:action keyEquivalent:key ? key : @""];
    it.target = target;
    return it;
}

static NSMenu *submenu(NSMenu *bar, NSString *title)
{
    NSMenuItem *top = [bar addItemWithTitle:title action:NULL keyEquivalent:@""];
    NSMenu *m = [[NSMenu alloc] initWithTitle:title];
    top.submenu = m;
    return m;
}

static NSString *key(unichar c) { return [NSString stringWithCharacters:&c length:1]; }

- (void)buildMenus
{
    GZMainWindowController *w = [GZMainWindowController shared];
    NSMenu *bar = [[NSMenu alloc] initWithTitle:@""];

    NSMenu *app = submenu(bar, TR(STR_APP));
    mi(app, MS(MS_ABOUT), @selector(about:), nil, self);
    [app addItem:[NSMenuItem separatorItem]];
    mi(app, MS(MS_PREFS), @selector(preferences:), @",", self);
    [app addItem:[NSMenuItem separatorItem]];
    NSMenu *services = [[NSMenu alloc] initWithTitle:MS(MS_SERVICES)];
    [app addItemWithTitle:MS(MS_SERVICES) action:NULL keyEquivalent:@""].submenu = services;
    NSApp.servicesMenu = services;
    [app addItem:[NSMenuItem separatorItem]];
    mi(app, MS(MS_HIDE), @selector(hide:), @"h", NSApp);
    mi(app, MS(MS_HIDE_OTHERS), @selector(hideOtherApplications:), @"h", NSApp).keyEquivalentModifierMask =
        NSEventModifierFlagOption | NSEventModifierFlagCommand;
    mi(app, MS(MS_SHOW_ALL), @selector(unhideAllApplications:), nil, NSApp);
    [app addItem:[NSMenuItem separatorItem]];
    mi(app, MS(MS_QUIT), @selector(terminate:), @"q", NSApp);

    NSMenu *file = submenu(bar, MS(MS_FILE));
    mi(file, TRP(STR_M_OPEN), @selector(cmdOpen:), @"o", w);
    mi(file, TRP(STR_M_NEW), @selector(cmdNew:), @"n", w);
    [file addItemWithTitle:TRP(STR_M_RECENT) action:NULL keyEquivalent:@""].submenu = [w recentMenu];
    [file addItem:[NSMenuItem separatorItem]];
    mi(file, TRP(STR_M_BACK), @selector(cmdBack:), @"[", w);
    mi(file, MS(MS_CLOSE_ARCHIVE), @selector(cmdClose:), @"W", w);
    mi(file, MS(MS_CLOSE_WINDOW), @selector(performClose:), @"w", nil);
    [file addItem:[NSMenuItem separatorItem]];
    mi(file, TRP(STR_M_INFO), @selector(cmdInfo:), @"i", w);

    NSMenu *edit = submenu(bar, MS(MS_EDIT));
    mi(edit, MS(MS_UNDO), @selector(undo:), @"z", nil);
    mi(edit, MS(MS_REDO), @selector(redo:), @"Z", nil);
    [edit addItem:[NSMenuItem separatorItem]];
    mi(edit, MS(MS_CUT), @selector(cut:), @"x", nil);
    mi(edit, MS(MS_COPY), @selector(copy:), @"c", nil);
    mi(edit, MS(MS_PASTE), @selector(paste:), @"v", nil);
    mi(edit, MS(MS_SELECT_ALL), @selector(selectAll:), @"a", nil);

    NSMenu *act = submenu(bar, MS(MS_ACTIONS));
    mi(act, TRP(STR_M_EXTRACT), @selector(cmdExtract:), @"e", w);
    mi(act, TRP(STR_M_EXTRACT_HERE), @selector(cmdExtractHere:), nil, w);
    mi(act, TRP(STR_M_EXTRACT_SMART), @selector(cmdExtractSmart:), @"E", w);
    mi(act, TRP(STR_M_EXTRACT_SEL), @selector(cmdExtractSelected:), nil, w);
    [act addItem:[NSMenuItem separatorItem]];
    mi(act, TRP(STR_M_TEST), @selector(cmdTest:), @"t", w);

    NSMenu *view = submenu(bar, MS(MS_VIEW));
    mi(view, TRP(STR_M_OPENITEM), @selector(cmdView:), key(NSDownArrowFunctionKey), w);
    mi(view, TRP(STR_M_UP), @selector(cmdUp:), key(NSUpArrowFunctionKey), w);
    [view addItem:[NSMenuItem separatorItem]];
    mi(view, TRP(STR_M_TREE), @selector(cmdToggleTree:), @"s", w).keyEquivalentModifierMask =
        NSEventModifierFlagOption | NSEventModifierFlagCommand;
    [view addItemWithTitle:TRP(STR_M_CODEPAGE) action:NULL keyEquivalent:@""].submenu = [w codepageMenu];
    [view addItem:[NSMenuItem separatorItem]];
    mi(view, MS(MS_TOOLBAR_SHOW), @selector(toggleToolbarShown:), @"t", nil).keyEquivalentModifierMask =
        NSEventModifierFlagOption | NSEventModifierFlagCommand;
    mi(view, MS(MS_TOOLBAR_CUSTOM), @selector(runToolbarCustomizationPalette:), nil, nil);
    [view addItem:[NSMenuItem separatorItem]];
    mi(view, MS(MS_FULLSCREEN), @selector(toggleFullScreen:), @"f", nil).keyEquivalentModifierMask =
        NSEventModifierFlagControl | NSEventModifierFlagCommand;

    NSMenu *win = submenu(bar, MS(MS_WINDOW));
    mi(win, MS(MS_MINIMIZE), @selector(performMiniaturize:), @"m", nil);
    mi(win, MS(MS_ZOOM), @selector(performZoom:), nil, nil);
    [win addItem:[NSMenuItem separatorItem]];
    mi(win, MS(MS_FRONT), @selector(arrangeInFront:), nil, NSApp);
    NSApp.windowsMenu = win;

    NSMenu *help = submenu(bar, MS(MS_HELP));
    mi(help, TRP(STR_M_HOMEPAGE), @selector(homepage:), nil, self);
    NSApp.helpMenu = help;

    NSApp.mainMenu = bar;
}

- (void)about:(id)sender { dlgAbout(); }
- (void)preferences:(id)sender { prefsShow(); }
- (void)homepage:(id)sender { [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:GZ_HOMEPAGE]]; }

/* ---------------- start-up ---------------- */

- (void)applicationWillFinishLaunching:(NSNotification *)note
{
    iconsInit();
    [self buildMenus];
}

- (void)showMainOnce
{
    if (_serviceLaunch || _mode != MODE_GUI) return;
    _mainShown = YES;
    [[GZMainWindowController shared] showMain];
}

- (void)applicationDidFinishLaunching:(NSNotification *)note
{
    _launched = YES;
    NSApp.servicesProvider = self;
    NSUpdateDynamicServices();
    tempSweepStale();
    if (_mode != MODE_GUI) {
        [self runCommandLine];
        return;
    }
    NSMutableArray *open = [NSMutableArray arrayWithArray:_files];
    for (NSString *p in _pendingOpen)
        if (![open containsObject:p]) [open addObject:p];
    _pendingOpen = nil;
    if (open.count) {
        _mainShown = YES;
        [[GZMainWindowController shared] openOrCompressPaths:open];
        return;
    }
    /* launched by Finder for a service: wait a moment before showing the window */
    NSNumber *isDefault = note.userInfo[NSApplicationLaunchIsDefaultLaunchKey];
    if (isDefault && !isDefault.boolValue) [self performSelector:@selector(showMainOnce) withObject:nil afterDelay:0.8];
    else [self showMainOnce];
}

- (void)application:(NSApplication *)sender openFiles:(NSArray<NSString *> *)filenames
{
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    for (NSString *f in filenames) {
        NSString *p = absPath(f);
        /* files named on our own command line may come back here: they are handled already */
        if (!_launched && [_files containsObject:p]) continue;
        [paths addObject:p];
    }
    [NSApp replyToOpenOrPrint:NSApplicationDelegateReplySuccess];
    if (!paths.count) return;
    if (!_launched) {
        if (!_pendingOpen) _pendingOpen = [NSMutableArray array];
        [_pendingOpen addObjectsFromArray:paths];
        return;
    }
    if (_mode != MODE_GUI) {          /* a command line job runs: open them when it is done */
        if (!_pendingOpen) _pendingOpen = [NSMutableArray array];
        [_pendingOpen addObjectsFromArray:paths];
        return;
    }
    _serviceLaunch = NO;
    _mainShown = YES;
    [[GZMainWindowController shared] openOrCompressPaths:paths];
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag
{
    if (!flag && _mode == MODE_GUI) {
        _serviceLaunch = NO;
        _mainShown = YES;
        [[GZMainWindowController shared] showMain];
        return NO;                    /* handled: no "untitled document" */
    }
    return YES;
}

/* not a document-based app (Info.plist declares document types for opening only) */
- (BOOL)applicationShouldOpenUntitledFile:(NSApplication *)sender { return NO; }

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender
{
    return _mode == MODE_GUI && _mainShown;
}

- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender
{
    if ([GZRun activeCount] || s_batches.count) {      /* cancel the job first */
        NSBeep();
        return NSTerminateCancel;
    }
    return NSTerminateNow;
}

- (void)applicationWillTerminate:(NSNotification *)note
{
    [[GZSettings shared] save];
    tempCleanup();
}

/* ---------------- Finder services ---------------- */

static NSArray<NSString *> *pasteboardPaths(NSPasteboard *pb)
{
    NSMutableArray<NSString *> *r = [NSMutableArray array];
    NSArray *urls = [pb readObjectsForClasses:@[ [NSURL class] ] options:@{ NSPasteboardURLReadingFileURLsOnlyKey : @YES }];
    for (NSURL *u in urls)
        if (u.path.length) [r addObject:u.path];
    if (!r.count) {          /* older senders: the legacy file name list (NSFilenamesPboardType) */
        id list = [pb propertyListForType:@"NSFilenamesPboardType"];
        if ([list isKindOfClass:[NSArray class]])
            for (id p in list)
                if ([p isKindOfClass:[NSString class]] && [p isAbsolutePath]) [r addObject:p];
    }
    return r;
}

- (void)serviceDone
{
    /* launched only for this service: quit once nothing is left to show */
    if (!_serviceLaunch || _mainShown || [GZRun activeCount] || s_batches.count) return;
    for (NSWindow *w in NSApp.windows)
        if (w.visible) return;
    [NSApp terminate:nil];
}

- (void)noteService
{
    if (!_mainShown) {
        _serviceLaunch = YES;
        [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(showMainOnce) object:nil];
    }
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)compressFiles:(NSPasteboard *)pb userData:(NSString *)userData error:(NSString **)error
{
    NSArray<NSString *> *paths = pasteboardPaths(pb);
    if (!paths.count) {
        if (error) *error = TR(STR_NOTHING);
        return;
    }
    [self noteService];
    NSWindow *main = [GZMainWindowController shared].window;
    NSWindow *par = main.visible ? main : nil;
    dlgCreate(par, paths, ^(GZCreateChoice *c) {
        if (!c || !startCompress(paths, c, par, GZ_OW_ASK, RUN_QUIET_OK, ^(GZRun *r, int res) { [self serviceDone]; }))
            [self serviceDone];
    });
}

- (void)extractFrom:(NSPasteboard *)pb mode:(int)mode error:(NSString **)error
{
    NSMutableArray<NSString *> *arcs = [NSMutableArray array];
    for (NSString *p in pasteboardPaths(pb))
        if (!pathIsDir(p)) [arcs addObject:p];
    if (!arcs.count) {
        if (error) *error = TR(STR_NOTHING);
        return;
    }
    [self noteService];
    GZBatch *b = [[GZBatch alloc] initWithFiles:arcs mode:mode dest:nil yes:NO done:^(int code) { [self serviceDone]; }];
    [b start];
}

- (void)extractHere:(NSPasteboard *)pb userData:(NSString *)userData error:(NSString **)error
{
    [self extractFrom:pb mode:BATCH_HERE error:error];
}

- (void)extractSmart:(NSPasteboard *)pb userData:(NSString *)userData error:(NSString **)error
{
    [self extractFrom:pb mode:BATCH_SMART error:error];
}

/* ---------------- command line modes ---------------- */

- (void)finishCommandLine:(int)code
{
    self.exitCode = code;
    if (_pendingOpen.count) {          /* Finder sent documents meanwhile: carry on as the GUI */
        _mode = MODE_GUI;
        _mainShown = YES;
        [[GZMainWindowController shared] openOrCompressPaths:_pendingOpen];
        _pendingOpen = nil;
        return;
    }
    [NSApp stop:nil];
    /* -stop: takes effect after the next event: post one */
    NSEvent *e = [NSEvent otherEventWithType:NSEventTypeApplicationDefined location:NSZeroPoint modifierFlags:0
                                   timestamp:0 windowNumber:0 context:nil subtype:0 data1:0 data2:0];
    [NSApp postEvent:e atStart:YES];
}

- (void)runCommandLine
{
    if (_mode == MODE_COMPRESS) {
        [self compressFromCommandLine];
        return;
    }
    static const int bm[] = { 0, BATCH_HERE, BATCH_SMART, BATCH_TO, BATCH_DIALOG, BATCH_TEST };
    GZBatch *b = [[GZBatch alloc] initWithFiles:_files mode:bm[_mode] dest:_to yes:_yes != 0
                                           done:^(int code) { [self finishCommandLine:code]; }];
    [b start];
}

- (void)compressFromCommandLine
{
    NSMutableArray<NSString *> *paths = _files;
    if (!paths.count) {
        NSOpenPanel *p = [NSOpenPanel openPanel];
        p.canChooseFiles = YES;
        p.canChooseDirectories = YES;
        p.allowsMultipleSelection = YES;
        p.title = TR(STR_C_PICK_FILES);
        p.prompt = TR(STR_SELECT);
        [NSApp activateIgnoringOtherApps:YES];
        if ([p runModal] == NSModalResponseOK)
            for (NSURL *u in p.URLs)
                if (u.path) [paths addObject:u.path];
        if (!paths.count) {
            [self finishCommandLine:EXIT_BREAK];
            return;
        }
    }
    GZSettings *set = [GZSettings shared];
    int flags = RUN_QUIET_OK | (_yes ? RUN_QUIET | RUN_LOG_STDERR | RUN_DELAY : 0);   /* --yes: no window for quick jobs */
    GZRunDone fin = ^(GZRun *r, int res) { [self finishCommandLine:[r exitCode]]; };
    if (_yes && _output.length) {
        GZCreateChoice *c = [[GZCreateChoice alloc] init];
        c.output = absPath(_output);
        gzch *w = gzPathW(c.output);
        c.format = _format ? _format : (w ? gz_format_from_name(w) : 0);
        gz_free(w);
        if (!c.format) {
            const gz_writer *dw = writerDefault(paths.count, paths.count == 1 && !pathIsDir(paths[0]));
            c.format = dw ? dw->format : 0;
        }
        c.level = _level >= 0 ? _level : 5;
        c.solid = YES;
        if (!gz_writer_find(c.format)) {
            fprintf(stderr, "%s: %s\n", gz_ui_str(STR_L_ERROR), gz_ui_str(STR_N_NO_WRITER));
            [self finishCommandLine:EXIT_USAGE];
            return;
        }
        if (!startCompress(paths, c, nil, GZ_OW_ALL, flags, fin)) [self finishCommandLine:EXIT_FATAL];
        return;
    }
    if (_format) set.cFormat = _format;
    if (_level >= 0) set.cLevel = _level;
    dlgCreate(nil, paths, ^(GZCreateChoice *c) {
        if (!c) {
            [self finishCommandLine:EXIT_BREAK];
            return;
        }
        if (!startCompress(paths, c, nil, self->_yes ? GZ_OW_ALL : GZ_OW_ASK, flags, fin))
            [self finishCommandLine:EXIT_FATAL];
    });
}

@end

/* ======================================================================
 * main
 * ====================================================================== */

static int formatByName(const char *s)
{
    static const struct { const char *n; int f; } t[] = {
        { "zip", GZ_WF_ZIP }, { "7z", GZ_WF_7Z }, { "tar", GZ_WF_TAR }, { "tgz", GZ_WF_TGZ }, { "tar.gz", GZ_WF_TGZ },
        { "tbz2", GZ_WF_TBZ2 }, { "tar.bz2", GZ_WF_TBZ2 }, { "txz", GZ_WF_TXZ }, { "tar.xz", GZ_WF_TXZ },
        { "tzst", GZ_WF_TZST }, { "tar.zst", GZ_WF_TZST }, { "gz", GZ_WF_GZ }, { "bz2", GZ_WF_BZ2 },
        { "xz", GZ_WF_XZ }, { "zst", GZ_WF_ZST }, { "iso", GZ_WF_ISO },
    };
    for (size_t i = 0; i < GZ_COUNTOF(t); i++)
        if (!strcasecmp(s, t[i].n)) return t[i].f;
    return 0;
}

static int usage(int code)
{
    fputs(gz_ms(MS_USAGE), code ? stderr : stdout);
    return code;
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        gz_engine_init(-1);
        NSString *lang = nil;
        /* first pass: language (messages of the usage text) */
        for (int i = 1; i + 1 < argc; i++)
            if (!strcmp(argv[i], "--lang")) lang = gzU8(argv[i + 1]);
        gz_ui_set_korean(uiKorean(lang));

        GZAppDelegate *d = [[GZAppDelegate alloc] init];
        d.files = [NSMutableArray array];
        d.level = -1;
        BOOL anyMode = NO;
        for (int i = 1; i < argc; i++) {
            const char *a = argv[i];
            if (!strncmp(a, "-psn_", 5)) continue;                     /* old Finder launches */
            if (a[0] == '-' && a[1] >= 'A' && a[1] <= 'Z' && i + 1 < argc) { i++; continue; }  /* -NSKey value */
            if (!strcmp(a, "--")) {
                for (i++; i < argc; i++) [d.files addObject:absPath(gzU8(argv[i]))];
                break;
            }
            int m = -1;
            if (!strcmp(a, "--extract-here")) m = MODE_HERE;
            else if (!strcmp(a, "--extract-smart")) m = MODE_SMART;
            else if (!strcmp(a, "--extract")) m = MODE_DIALOG;
            else if (!strcmp(a, "--test")) m = MODE_TEST;
            else if (!strcmp(a, "--compress")) m = MODE_COMPRESS;
            else if (!strcmp(a, "--extract-to")) {
                if (i + 1 >= argc) return usage(EXIT_USAGE);
                m = MODE_TO;
                d.to = absPath(gzU8(argv[++i]));
            }
            if (m >= 0) {
                if (anyMode && d.mode != m) return usage(EXIT_USAGE);
                d.mode = m;
                anyMode = YES;
                continue;
            }
            if (!strcmp(a, "--output") || !strcmp(a, "-o")) {
                if (i + 1 >= argc) return usage(EXIT_USAGE);
                d.output = gzU8(argv[++i]);
            } else if (!strcmp(a, "--format")) {
                if (i + 1 >= argc || !(d.format = formatByName(argv[i + 1]))) return usage(EXIT_USAGE);
                i++;
            } else if (!strcmp(a, "--level")) {
                if (i + 1 >= argc) return usage(EXIT_USAGE);
                char *e;
                long v = strtol(argv[++i], &e, 10);
                if (*e || v < 0 || v > 9) return usage(EXIT_USAGE);
                d.level = (int)v;
            } else if (!strcmp(a, "--yes") || !strcmp(a, "-y")) {
                d.yes = 1;
            } else if (!strcmp(a, "--lang")) {
                if (i + 1 < argc) i++;
            } else if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
                return usage(0);
            } else if (!strcmp(a, "--version")) {
                printf("GogitZIP %s\n", GZ_APP_VERSION);
                return 0;
            } else if (a[0] == '-' && a[1]) {
                return usage(EXIT_USAGE);
            } else {
                [d.files addObject:absPath(gzU8(a))];
            }
        }
        if (d.mode != MODE_GUI && d.mode != MODE_COMPRESS && !d.files.count) return usage(EXIT_USAGE);

        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        app.delegate = d;          /* weak in the SDK: d stays alive in this scope */
        [app run];
        tempCleanup();
        return d.exitCode;
    }
}
