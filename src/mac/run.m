/*
 * 고깃ZIP macOS - background jobs and the progress window
 *
 * Engine callbacks arrive on worker threads:
 *   progress  the entry name is copied under a mutex; a 100 ms main-thread timer
 *             (common run loop modes: it keeps running under sheets and menus)
 *             shows it with the job's own counters (gz_job_progress)
 *   ask       dispatch_async to the main queue, where the (non-blocking) question
 *             sheet answers through a completion block; the worker waits on a
 *             semaphore meanwhile, so asks block it until answered
 *   done      dispatch_async to the main queue -> -finish
 * The progress window appears at once, or after 400 ms for short internal jobs
 * (opening, viewing a file, drag and drop), so quick work never flickers.
 */
#import "app.h"
#include <pthread.h>

static NSMutableSet<GZRun *> *s_runs;      /* running jobs keep themselves alive here */

@interface GZRun ()
- (void)noteCurrent:(const gzch *)name;
- (void)askOnMain:(gz_ask *)q done:(void (^)(int answer))done;
- (void)finish;
@end

/* ---------------- worker side (any thread) ---------------- */

static void cbProgress(void *user, const gz_progress *p)
{
    @autoreleasepool {
        GZRun *r = (__bridge GZRun *)user;
        if (p->current) [r noteCurrent:p->current];
    }
}

static int cbAsk(void *user, gz_ask *q)
{
    @autoreleasepool {
        GZRun *r = (__bridge GZRun *)user;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block int answer = GZ_ANS_CANCEL;
        dispatch_async(dispatch_get_main_queue(), ^{
            [r askOnMain:q done:^(int a) {
                answer = a;
                dispatch_semaphore_signal(sem);
            }];
        });
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        return answer;
    }
}

static void cbDone(void *user, int result)
{
    @autoreleasepool {
        GZRun *r = (__bridge GZRun *)user;
        dispatch_async(dispatch_get_main_queue(), ^{ [r finish]; });
    }
}

@implementation GZRun {
    int _flags;
    gz_job *_job;
    gz_handle *_ph, *_h;
    u32 _idx;
    int _cp;
    volatile long _cancel;
    int _childResult;
    BOOL _childDone;
    pthread_mutex_t _m;
    gzch _cur[1024];
    BOOL _haveCur;
    __weak NSWindow *_parent;
    GZRunDone _done;
    NSString *_subtitle;
    int _exitCode;
    /* main thread */
    BOOL _paused, _canceling, _asking;
    NSWindow *_win;
    NSTextField *_title, *_curL, *_l1, *_r1, *_l2, *_r2;
    NSProgressIndicator *_bar;
    NSButton *_pauseB, *_cancelB, *_openChk;
    NSTimer *_timer, *_showTimer;
}

+ (NSInteger)activeCount { return (NSInteger)s_runs.count; }

- (instancetype)initKind:(int)kind flags:(int)flags parent:(NSWindow *)parent done:(GZRunDone)done
{
    self = [super init];
    if (!self) return nil;
    _kind = kind;
    _flags = flags;
    _parent = parent;
    _done = [done copy];
    pthread_mutex_init(&_m, NULL);
    return self;
}

- (void)dealloc
{
    [_timer invalidate];
    [_showTimer invalidate];
    if (_job) gz_job_free(_job);
    if (_h) gz_handle_close(_h);
    pthread_mutex_destroy(&_m);
}

- (gz_callbacks)callbacks
{
    gz_callbacks cb = { (__bridge void *)self, cbAsk, cbProgress, NULL, cbDone };
    return cb;
}

- (void)noteCurrent:(const gzch *)name
{
    pthread_mutex_lock(&_m);
    size_t i = 0;
    for (; name[i] && i + 1 < GZ_COUNTOF(_cur); i++) _cur[i] = name[i];
    _cur[i] = 0;
    _haveCur = YES;
    pthread_mutex_unlock(&_m);
}

/* ---------------- progress window ---------------- */

- (NSString *)kindTitle
{
    switch (_kind) {
    case RK_TEST: return TR(STR_P_TESTING);
    case RK_COMPRESS: return TR(STR_P_COMPRESSING);
    case RK_OPEN: case RK_CHILD: return TR(STR_P_OPENING);
    }
    return TR(STR_P_EXTRACTING);
}

- (int)kindIcon
{
    switch (_kind) {
    case RK_TEST: return IC_TEST;
    case RK_COMPRESS: return IC_NEW;
    case RK_OPEN: case RK_CHILD: return IC_OPEN;
    }
    return IC_EXTRACT;
}

static NSTextField *plabel(NSView *parent, NSRect r, NSString *s, NSFont *f, NSColor *c, NSTextAlignment al)
{
    NSTextField *l = [NSTextField labelWithString:s ? s : @""];
    l.frame = r;
    if (f) l.font = f;
    if (c) l.textColor = c;
    l.alignment = al;
    l.lineBreakMode = NSLineBreakByTruncatingMiddle;
    l.autoresizingMask = NSViewWidthSizable;
    [parent addSubview:l];
    return l;
}

- (void)buildWindow
{
    const CGFloat W = 520, H = 214;
    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, W, H)
                                              styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                        NSWindowStyleMaskMiniaturizable
                                                backing:NSBackingStoreBuffered
                                                  defer:YES];
    w.releasedWhenClosed = NO;
    w.title = [self kindTitle];
    w.delegate = self;
    NSView *v = w.contentView;
    NSFont *small = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
    NSFont *digits = [NSFont monospacedDigitSystemFontOfSize:[NSFont smallSystemFontSize] weight:NSFontWeightRegular];

    NSImageView *iv = [NSImageView imageViewWithImage:gzIcon([self kindIcon], 32)];
    iv.frame = NSMakeRect(20, H - 54, 32, 32);
    [v addSubview:iv];
    _title = plabel(v, NSMakeRect(64, H - 38, W - 84, 20), [self kindTitle], [NSFont boldSystemFontOfSize:15], nil,
                    NSTextAlignmentLeft);
    plabel(v, NSMakeRect(64, H - 56, W - 84, 16), _subtitle, small, [NSColor secondaryLabelColor],
           NSTextAlignmentLeft);
    _curL = plabel(v, NSMakeRect(20, H - 84, W - 40, 16), TR(STR_P_PREPARING), small, [NSColor secondaryLabelColor],
                   NSTextAlignmentLeft);
    _bar = [[NSProgressIndicator alloc] initWithFrame:NSMakeRect(20, H - 108, W - 40, 20)];
    _bar.style = NSProgressIndicatorStyleBar;
    _bar.indeterminate = YES;
    _bar.minValue = 0;
    _bar.maxValue = 1000;
    _bar.autoresizingMask = NSViewWidthSizable;
    [v addSubview:_bar];
    [_bar startAnimation:nil];
    _l1 = plabel(v, NSMakeRect(20, H - 130, 320, 16), @"", digits, nil, NSTextAlignmentLeft);
    _r1 = plabel(v, NSMakeRect(W - 180, H - 130, 160, 16), @"", digits, nil, NSTextAlignmentRight);
    _l2 = plabel(v, NSMakeRect(20, H - 148, 320, 16), @"", digits, nil, NSTextAlignmentLeft);
    _r2 = plabel(v, NSMakeRect(W - 180, H - 148, 160, 16), @"", digits, nil, NSTextAlignmentRight);
    NSString *th = [NSString stringWithFormat:@"%d",
                                              _kind == RK_OPEN || _kind == RK_CHILD
                                                  ? 1
                                                  : [[GZSettings shared] effectiveThreads]];
    plabel(v, NSMakeRect(20, H - 168, W - 40, 14),
           TRF(STR_P_ENGINE, @[ gzU8(gz_dispatch_inflate_name()), gzU8(gz_dispatch_crc_name()), th ]),
           [NSFont systemFontOfSize:[NSFont smallSystemFontSize] - 1], [NSColor tertiaryLabelColor],
           NSTextAlignmentLeft);

    _cancelB = [NSButton buttonWithTitle:TR(STR_CANCEL) target:self action:@selector(cancelJob:)];
    _cancelB.keyEquivalent = @"\e";
    _cancelB.frame = NSMakeRect(W - 20 - 110, 14, 110, 32);
    [v addSubview:_cancelB];
    if (_job && _kind != RK_OPEN) {
        _pauseB = [NSButton buttonWithTitle:TR(STR_P_PAUSE) target:self action:@selector(pauseJob:)];
        _pauseB.frame = NSMakeRect(W - 20 - 226, 14, 110, 32);
        [v addSubview:_pauseB];
    }
    if (_kind == RK_EXTRACT) {
        _openChk = [NSButton checkboxWithTitle:TR(STR_X_OPENFOLDER) target:nil action:NULL];
        _openChk.state = (_flags & RUN_OPEN_DEST) ? NSControlStateValueOn : NSControlStateValueOff;
        _openChk.frame = NSMakeRect(20, 20, W - 280, 20);
        [v addSubview:_openChk];
    }
    _win = w;
}

- (void)showWindow
{
    [_showTimer invalidate];
    _showTimer = nil;
    if (_finished || (_flags & RUN_NO_WINDOW) || _win.visible) return;
    if (!_win) [self buildWindow];
    [self update];
    NSWindow *p = _parent;
    if (p.visible) {
        NSRect pf = p.frame, f = _win.frame;
        [_win setFrameOrigin:NSMakePoint(NSMidX(pf) - f.size.width / 2, NSMidY(pf) - f.size.height / 2 + 40)];
    } else {
        [_win center];
    }
    [NSApp activateIgnoringOtherApps:YES];
    [_win makeKeyAndOrderFront:nil];
}

- (void)showLater:(NSTimer *)t
{
    _showTimer = nil;
    [self showWindow];
}

- (void)update
{
    if (!_win) return;
    gz_progress p;
    memset(&p, 0, sizeof p);
    NSString *cur = nil;
    pthread_mutex_lock(&_m);
    if (_haveCur) cur = gzNS(_cur);
    pthread_mutex_unlock(&_m);
    if (_job) gz_job_progress(_job, &p);
    double frac = p.total_bytes ? (double)p.done_bytes / (double)p.total_bytes : 0;
    if (frac > 1) frac = 1;
    if (_job && p.total_bytes) {
        if (_bar.indeterminate) {
            [_bar stopAnimation:nil];
            _bar.indeterminate = NO;
        }
        _bar.doubleValue = frac * 1000;
    }
    _curL.stringValue = cur.length ? cur : (_canceling ? TR(STR_P_CANCELING) : TR(STR_P_PREPARING));
    if (_job) {
        _l1.stringValue = [NSString stringWithFormat:@"%d%%  ·  %@ / %@", (int)(frac * 100), fmtSize(p.done_bytes),
                                                     fmtSize(p.total_bytes)];
        u64 bps = p.elapsed_ms > 200 ? p.done_bytes * 1000 / p.elapsed_ms : 0;
        if (bps) {
            char sp[48];
            gz_ui_fmt_speed(sp, sizeof sp, bps);
            _r1.stringValue = [NSString stringWithFormat:@"%@ %@", TR(STR_P_SPEED), gzU8(sp)];
        } else {
            _r1.stringValue = @"";
        }
        char a[32], b[32];
        gz_ui_fmt_duration(a, sizeof a, p.elapsed_ms / 1000);
        if (bps && p.total_bytes > p.done_bytes) gz_ui_fmt_duration(b, sizeof b, (p.total_bytes - p.done_bytes) / bps);
        else strcpy(b, "--:--");
        _l2.stringValue = [NSString stringWithFormat:@"%@ %@  ·  %@ %@", TR(STR_P_ELAPSED), gzU8(a), TR(STR_P_REMAIN),
                                                     gzU8(b)];
        if (p.total_files)
            _r2.stringValue = [NSString stringWithFormat:@"%@ %u / %u", TR(STR_P_FILES), p.done_files, p.total_files];
    }
    _title.stringValue = _canceling ? TR(STR_P_CANCELING) : _paused ? TR(STR_P_PAUSED) : [self kindTitle];
}

- (void)tick:(NSTimer *)t { [self update]; }

- (void)cancelJob:(id)sender
{
    if (_finished) return;
    _canceling = YES;
    if (_job) {
        if (_paused) gz_job_pause(_job, 0);
        gz_job_cancel(_job);
    }
    gz_atomic_store(&_cancel, 1);
    _cancelB.enabled = NO;
    _pauseB.enabled = NO;
    [self update];
}

- (void)pauseJob:(id)sender
{
    if (!_job || _finished) return;
    _paused = !_paused;
    gz_job_pause(_job, _paused);
    _pauseB.title = TR(_paused ? STR_P_RESUME : STR_P_PAUSE);
    [self update];
}

- (BOOL)windowShouldClose:(NSWindow *)sender
{
    if (!_asking) [self cancelJob:nil];
    return NO;                                   /* the window goes away when the job ends */
}

/* ---------------- questions ---------------- */

- (void)askOnMain:(gz_ask *)q done:(void (^)(int))done
{
    if (!(_flags & RUN_NO_WINDOW)) [self showWindow];
    _asking = YES;
    NSWindow *host = _win.visible ? _win : (_parent.visible ? _parent : nil);
    askDialog(host, q, ^(int answer) {
        self->_asking = NO;
        done(answer);
    });
}

/* ---------------- start / finish ---------------- */

- (void)started
{
    if (!s_runs) s_runs = [NSMutableSet set];
    [s_runs addObject:self];
    _timer = [NSTimer timerWithTimeInterval:0.1 target:self selector:@selector(tick:) userInfo:nil repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:_timer forMode:NSRunLoopCommonModes];
    if (_flags & RUN_NO_WINDOW) return;
    if (_flags & RUN_DELAY) {
        _showTimer = [NSTimer timerWithTimeInterval:0.4 target:self selector:@selector(showLater:) userInfo:nil
                                            repeats:NO];
        [[NSRunLoop mainRunLoop] addTimer:_showTimer forMode:NSRunLoopCommonModes];
    } else {
        [self showWindow];
    }
}

- (void)finish
{
    if (_finished) return;
    _finished = YES;
    [_timer invalidate];
    _timer = nil;
    [_showTimer invalidate];
    _showTimer = nil;
    int res;
    if (_job) {
        res = gz_job_wait(_job);
        if (_kind == RK_OPEN) _h = gz_job_take_handle(_job);
        else if (_kind == RK_EXTRACT && gz_job_dest(_job)) _dest = gzPathNS(gz_job_dest(_job));
    } else {
        res = _childResult;
    }
    _result = res;
    _exitCode = 0;
    _exitCode = [self exitCode];
    BOOL openDest = _openChk ? _openChk.state == NSControlStateValueOn : (_flags & RUN_OPEN_DEST) != 0;
    if (_openChk) {
        [GZSettings shared].openFolder = openDest;
        [[GZSettings shared] save];
    }
    NSWindow *par = _parent.visible ? _parent : nil;
    if (_win) {
        [_win orderOut:nil];
        _win.delegate = nil;
        _win = nil;
    }
    if (_job && (_flags & RUN_LOG_STDERR)) {
        u32 n = gz_job_log_count(_job);
        for (u32 i = 0; i < n; i++) {
            const gz_log *l = gz_job_log_at(_job, i);
            if (!l || l->level < GZ_LOG_WARN) continue;
            NSString *line = [NSString stringWithFormat:@"%@: %@ : %@%@%@\n",
                                                        TR(l->level == GZ_LOG_ERROR ? STR_L_ERROR : STR_L_WARN),
                                                        gzNS(l->name), gzU8(gz_ui_code_text(l->code)),
                                                        l->detail ? @" : " : @"", l->detail ? gzNS(l->detail) : @""];
            fputs(line.UTF8String, stderr);
        }
        if (res && res != GZ_E_CANCEL && !n)
            fprintf(stderr, "%s: %s\n", gz_ui_str(STR_L_ERROR), gz_ui_code_text(res));
    }
    void (^after)(void) = ^{
        /* no longer active before done runs (done may start the next job); the block keeps self */
        [s_runs removeObject:self];
        if (self->_job && self->_kind != RK_OPEN) {
            gz_job_free(self->_job);
            self->_job = NULL;
        }
        if (openDest && self->_kind == RK_EXTRACT && res != GZ_E_CANCEL && self->_dest) showFolder(self->_dest);
        GZRunDone d = self->_done;
        self->_done = nil;
        if (d) d(self, res);
    };
    if (_job && !(_flags & RUN_QUIET) && (_kind == RK_EXTRACT || _kind == RK_TEST || _kind == RK_COMPRESS))
        dlgResult(par, _job, _kind, res, (_flags & RUN_QUIET_OK) != 0, after);
    else
        after();
}

- (gz_handle *)takeHandle
{
    gz_handle *h = _h;
    _h = NULL;
    return h;
}

- (int)exitCode
{
    if (_exitCode && _finished) return _exitCode;
    if (_result == GZ_E_CANCEL || _canceling) return EXIT_BREAK;
    gz_progress p;
    memset(&p, 0, sizeof p);
    if (_job) gz_job_progress(_job, &p);
    if (p.errors || (_result && _result != GZ_E_SKIP)) return EXIT_FATAL;
    if (p.warnings) return EXIT_WARN;
    return EXIT_OK_;
}

/* ---------------- constructors ---------------- */

+ (GZRun *)extractHandle:(gz_handle *)h options:(const gz_extract_opts *)xo parent:(NSWindow *)parent
                   flags:(int)flags done:(GZRunDone)done
{
    GZRun *r = [[GZRun alloc] initKind:xo->test ? RK_TEST : RK_EXTRACT flags:flags parent:parent done:done];
    r->_subtitle = h->parent || h->temp ? gzNS(h->name) : gzPathNS(h->path);
    if (xo->dest) r->_dest = gzPathNS(xo->dest);
    gz_callbacks cb = [r callbacks];
    r->_job = gz_extract_start(h, xo, &cb);
    if (!r->_job) {
        msgBox(parent, NSAlertStyleCritical, TR(STR_E_NOMEM), nil);
        return nil;
    }
    [r started];
    return r;
}

+ (GZRun *)compressWithOptions:(const gz_compress_opts *)co parent:(NSWindow *)parent flags:(int)flags
                          done:(GZRunDone)done
{
    GZRun *r = [[GZRun alloc] initKind:RK_COMPRESS flags:flags parent:parent done:done];
    r->_subtitle = gzPathNS(co->out);
    r->_dest = r->_subtitle;
    gz_callbacks cb = [r callbacks];
    r->_job = gz_compress_start(co, &cb);
    if (!r->_job) {
        msgBox(parent, NSAlertStyleCritical, TR(STR_E_NOMEM), nil);
        return nil;
    }
    [r started];
    return r;
}

+ (GZRun *)openPath:(NSString *)path codepage:(int)cp parent:(NSWindow *)parent done:(GZRunDone)done
{
    GZRun *r = [[GZRun alloc] initKind:RK_OPEN flags:RUN_DELAY | RUN_QUIET parent:parent done:done];
    r->_subtitle = displayPath(path);
    r->_dest = path;
    gzch *w = gzPathW(path);
    gz_open_req req;
    memset(&req, 0, sizeof req);
    req.codepage = cp;
    gz_callbacks cb = [r callbacks];
    r->_job = w ? gz_open_start(w, &req, &cb) : NULL;
    gz_free(w);
    if (!r->_job) return nil;
    [r started];
    return r;
}

+ (GZRun *)openChildOf:(gz_handle *)ph index:(u32)idx codepage:(int)cp parent:(NSWindow *)parent
                  done:(GZRunDone)done
{
    if (idx >= ph->arc->n) return nil;
    GZRun *r = [[GZRun alloc] initKind:RK_CHILD flags:RUN_DELAY | RUN_QUIET parent:parent done:done];
    r->_ph = ph;
    r->_idx = idx;
    r->_cp = cp;
    r->_subtitle = gzNS(ph->arc->e[idx].name);
    [r started];
    /* gz_handle_open_child is synchronous: run it on a background queue; its questions
     * come back through cbAsk like a job's */
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            gz_callbacks cb = [r callbacks];
            cb.done = NULL;
            gz_open_req req;
            memset(&req, 0, sizeof req);
            req.codepage = r->_cp;
            req.cancel = &r->_cancel;
            gz_handle *h = NULL;
            int res = gz_handle_open_child(&h, r->_ph, r->_idx, &req, &cb);
            if (gz_atomic_load(&r->_cancel) && !res) {
                gz_handle_close(h);
                h = NULL;
                res = GZ_E_CANCEL;
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                r->_h = h;
                r->_childResult = res;
                [r finish];
            });
        }
    });
    return r;
}

@end
