/*
 * 고깃ZIP - macOS Cocoa front end (Objective-C, ARC): shared declarations
 *
 *   main.m      start-up, menus, Finder integration (open documents, Services),
 *               command line modes (--extract-to/-here/-smart, --test, --compress)
 *   mainwnd.m   main window: toolbar, path control, folder tree (NSOutlineView),
 *               file list (NSTableView over a C row array, 100k+ rows), status bar,
 *               welcome view, drag and drop (file promises out, files in)
 *   run.m       background jobs: progress window; engine callbacks are marshalled to
 *               the main queue, questions block the worker until answered
 *   dialogs.m   extract / create / info / result / question dialogs
 *   prefs.m     settings (NSUserDefaults), recent archives, preferences window
 *   icons.m     icon atlas (Resources/assets.bin, decoded with our own inflate)
 *   util.m      text conversion, formatting, temporary folders, small helpers
 *
 * All archive work runs in src/app/engine on worker threads. Paths handed to
 * the engine are gzch (UTF-16 with surrogate escape, see os.h); the UI uses
 * NSString. Deployment target: macOS 10.13 (x86_64), 11.0 (arm64).
 * No nullability annotations on purpose: a header without any needs none.
 */
#ifndef GZ_MAC_APP_H
#define GZ_MAC_APP_H
#import <Cocoa/Cocoa.h>
#include "../app/engine.h"
#include "mstrings.h"
#include "cpu.h"
#include "../win/asset_ids.h"     /* icon ids of res/assets.bin (tools/gen_assets.py) */

#define GZ_HOMEPAGE @"https://niseullent.github.io/Butcherar/"

/* extra icon ids after the atlas (drawn at run time) */
enum { IC_NEW = IC_COUNT };

/* exit codes of the command line modes (as 7-Zip / the CLI tool) */
enum { EXIT_OK_ = 0, EXIT_WARN = 1, EXIT_FATAL = 2, EXIT_USAGE = 7, EXIT_BREAK = 255 };

/* ---------------- util.m ---------------- */

NSString *TR(int sid);                        /* shared UI string                         */
NSString *TRP(int sid);                       /* same without "_x" mnemonics, "..." -> "…" */
NSString *MS(int mid);                        /* mac string (mstrings.h)                  */
NSString *TRF(int sid, NSArray<NSString *> *args);   /* fill the "%s" of a shared template */
NSString *gzU8(const char *s);                /* UTF-8 (invalid -> lossy), never nil      */

NSString *gzNS(const gzch *w);                /* UTF-16 -> NSString, lone surrogates -> U+FFFD */
NSString *gzNSn(const gzch *w, size_t n);
gzch *gzW(NSString *s);                       /* NSString -> UTF-16 (gz_alloc, NULL on failure) */
void  gzWipeFree(gzch *w);                    /* clear (passwords) and gz_free           */
gzch *gzPathW(NSString *path);                /* file system path -> gzch (gz_free)       */
NSString *gzPathNS(const gzch *w);            /* gzch path -> NSString path               */
void  gzCopyAnswer(gzch *dst, NSString *s);   /* into gz_ask.answer (GZ_ASK_CAP)          */

NSString *fmtSize(u64 v);                     /* 1.50 MB                                  */
NSString *fmtThousands(u64 v);                /* 1,234                                    */
NSString *fmtFiletime(u64 ft);                /* 2026-10-24 18:30, @"" if unknown         */
NSString *fmtSizeDate(u64 size, u64 ft);      /* 1.50 MB (1,572,864 B)  ·  2026-10-24 18:30 */

BOOL pathIsDir(NSString *p);
BOOL pathExists(NSString *p);                 /* lstat: dangling links count               */
NSString *absPath(NSString *arg);             /* absolute, standardized (file:// accepted) */
NSString *displayPath(NSString *p);           /* "~/Downloads/a.zip"                        */
BOOL isArchiveName(NSString *name);           /* extension known to a reader, documents excluded */
NSString *engineLine(void);                   /* "AVX2  ·  CRC VPCLMULQDQ  ·  AES-NI"      */
int  gzNameCmpNatural(const gzch *a, const gzch *b);

/* per-process temporary folder <tmp>/GogitZIP-<pid>; folders of dead processes are swept */
NSString *tempRoot(void);
NSString *tempNewDir(NSString *prefix);
void tempSweepStale(void);
void tempCleanup(void);

void openWithDefault(NSString *path, NSWindow *parent);
void showFolder(NSString *path);
void msgBox(NSWindow *parent, NSAlertStyle style, NSString *primary, NSString *secondary);

/* file type description and icon by extension (cached, main thread) */
NSString *typeDescription(const gzch *base);
NSImage *typeIcon(const gzch *base);
NSImage *folderIcon(void);
void typesClear(void);

/* ---------------- icons.m ---------------- */

void iconsInit(void);                         /* decode Resources/assets.bin once          */
NSImage *gzIcon(int ident, CGFloat pt);       /* colored icon (all stored sizes as reps)   */
NSImage *gzTemplateIcon(int ident, CGFloat pt);  /* same, as a template (follows dark mode) */

/* ---------------- prefs.m ---------------- */

#define GZ_RECENT_MAX 8
@interface GZSettings : NSObject
+ (GZSettings *)shared;
@property (nonatomic) NSInteger lang;         /* 0 automatic, 1 Korean, 2 English           */
@property (nonatomic) NSInteger codepage;     /* default for legacy names, 0 = automatic    */
@property (nonatomic) NSInteger threads;      /* 0 = automatic                              */
@property (nonatomic) NSInteger overwrite;    /* GZ_OW_*                                    */
@property (nonatomic) NSInteger pathMode;     /* GZ_PATH_FULL / GZ_PATH_NONE                */
@property (nonatomic) NSInteger destMode;     /* 0 archive folder, 1 custom (dest)          */
@property (nonatomic) NSInteger cFormat, cLevel, cEnc;   /* create dialog: last choices      */
@property (nonatomic) BOOL smart, openFolder, showTree;
@property (nonatomic, copy) NSString *dest;   /* custom destination (absolute) or nil       */
@property (nonatomic, readonly) NSArray<NSString *> *recent;
- (void)addRecent:(NSString *)path;
- (void)clearRecent;
- (void)save;
- (int)effectiveThreads;
@end

BOOL uiKorean(NSString *forced);              /* language choice: --lang, settings, system */
void prefsShow(void);
/* make GogitZIP the default app for the archive types of its Info.plist; returns types changed */
int  assocSetDefault(int *failed);

/* ---------------- run.m ---------------- */

enum { RK_EXTRACT = 1, RK_TEST, RK_COMPRESS, RK_OPEN, RK_CHILD };   /* kinds of runs */
enum {                         /* run flags */
    RUN_QUIET_OK   = 1,        /* no "done" message on success                     */
    RUN_QUIET      = 2,        /* no result window at all (caller reports)         */
    RUN_OPEN_DEST  = 4,        /* open the destination folder afterwards           */
    RUN_NO_WINDOW  = 8,        /* never show the progress window                   */
    RUN_DELAY      = 16,       /* show the progress window only after 400 ms       */
    RUN_LOG_STDERR = 32        /* also print problems on stderr (command line modes) */
};

@class GZRun;
typedef void (^GZRunDone)(GZRun *run, int result);

@interface GZRun : NSObject <NSWindowDelegate>
@property (nonatomic, readonly) int kind;
@property (nonatomic, readonly) int result;
@property (nonatomic, readonly) BOOL finished;
@property (nonatomic, readonly, copy) NSString *dest;   /* extraction folder (after smart naming) / archive */
/* Start a job; nil when it could not start (an error was shown). done runs on the main
 * thread after the result window, exactly once. */
+ (GZRun *)extractHandle:(gz_handle *)h options:(const gz_extract_opts *)xo parent:(NSWindow *)parent
                   flags:(int)flags done:(GZRunDone)done;
+ (GZRun *)compressWithOptions:(const gz_compress_opts *)co parent:(NSWindow *)parent flags:(int)flags
                          done:(GZRunDone)done;
+ (GZRun *)openPath:(NSString *)path codepage:(int)cp parent:(NSWindow *)parent done:(GZRunDone)done;
+ (GZRun *)openChildOf:(gz_handle *)ph index:(u32)idx codepage:(int)cp parent:(NSWindow *)parent
                  done:(GZRunDone)done;
- (gz_handle *)takeHandle;                    /* open runs, inside done                    */
- (int)exitCode;                              /* EXIT_* for the command line modes         */
+ (NSInteger)activeCount;
@end

/* ---------------- dialogs.m ---------------- */

/* a window shown as a sheet on a visible parent, else app-modal */
@interface GZDialog : NSObject <NSWindowDelegate>
@property (nonatomic, strong) NSWindow *window;
- (void)beginOn:(NSWindow *)parent completion:(void (^)(NSModalResponse r))done;
- (void)end:(NSModalResponse)r;
@end

/* the questions of a running job (main thread); done gets GZ_ANS_* */
void askDialog(NSWindow *parent, gz_ask *q, void (^done)(int answer));

@interface GZExtractChoice : NSObject
@property (nonatomic, copy) NSString *dest;
@property (nonatomic) BOOL smart, openFolder, onlySelected;
@property (nonatomic) int overwrite, pathMode;
@end
/* extract options; nsel > 0 offers "selected only". done gets nil when canceled. */
void dlgExtract(NSWindow *parent, gz_handle *h, NSString *arcPath, u32 nsel, void (^done)(GZExtractChoice *c));

@interface GZCreateChoice : NSObject
@property (nonatomic, copy) NSString *output;
@property (nonatomic, copy) NSString *password;   /* nil = no encryption */
@property (nonatomic) int format, method, level, encryption;
@property (nonatomic) BOOL encryptNames, solid;
@end
/* output: archive proposed (nil: named after the inputs); format: proposed (0: from output's
 * extension, else the default). done gets nil when canceled. */
void dlgCreate(NSWindow *parent, NSArray<NSString *> *inputs, NSString *output, int format,
               void (^done)(GZCreateChoice *c));
const gz_writer *writerDefault(NSUInteger ninputs, BOOL singleFile);
NSString *defaultArchiveName(NSArray<NSString *> *inputs, const gz_writer *w);
/* start compressing: owns nothing of c afterwards */
GZRun *startCompress(NSArray<NSString *> *inputs, GZCreateChoice *c, NSWindow *parent, int overwrite, int flags,
                     GZRunDone done);

void dlgInfo(NSWindow *parent, gz_handle *h, NSString *arcPath);
/* result of a finished job: problems list or a short message; done afterwards */
void dlgResult(NSWindow *parent, gz_job *j, int kind, int result, BOOL quietOk, void (^done)(void));
void dlgAbout(void);

/* ---------------- mainwnd.m ---------------- */

@interface GZMainWindowController : NSWindowController
+ (GZMainWindowController *)shared;
- (void)showMain;
- (void)openArchivePath:(NSString *)path;
- (void)compressPaths:(NSArray<NSString *> *)paths;
- (void)openOrCompressPaths:(NSArray<NSString *> *)paths;   /* Finder / Dock drops */
- (BOOL)hasArchive;
- (void)rebuildRecent;
- (NSMenu *)recentMenu;                       /* File > Open Recent (filled on demand)     */
- (NSMenu *)codepageMenu;                     /* View > Code Page (filled on demand)       */
/* menu / toolbar actions (validated by the controller; selectors used in main.m):
 * cmdOpen: cmdNew: cmdClose: cmdBack: cmdInfo: cmdExtract: cmdExtractHere: cmdExtractSmart:
 * cmdExtractSelected: cmdTest: cmdView: cmdUp: cmdToggleTree: cmdSettings: */
- (IBAction)cmdOpen:(id)sender;
- (IBAction)cmdNew:(id)sender;
@end

/* ---------------- main.m ---------------- */

/* extract / test archives one after another (command line, Finder services) */
enum { BATCH_HERE = 1, BATCH_SMART, BATCH_TO, BATCH_DIALOG, BATCH_TEST };
@interface GZBatch : NSObject
- (instancetype)initWithFiles:(NSArray<NSString *> *)files mode:(int)mode dest:(NSString *)dest
                          yes:(BOOL)yes done:(void (^)(int exitCode))done;
- (void)start;
@end

#endif
