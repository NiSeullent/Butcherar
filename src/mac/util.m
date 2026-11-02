/*
 * 고깃ZIP macOS - text conversion, formatting, temporary folders, small helpers
 */
#import "app.h"
#import <CoreServices/CoreServices.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* ======================================================================
 * UI strings
 * ====================================================================== */

NSString *gzU8(const char *s)
{
    if (!s) return @"";
    NSString *r = [NSString stringWithUTF8String:s];
    if (r) return r;
    /* not valid UTF-8 (never for our tables): keep what decodes */
    r = [[NSString alloc] initWithBytes:s length:strlen(s) encoding:NSISOLatin1StringEncoding];
    return r ? r : @"";
}

NSString *TR(int sid) { return gzU8(gz_ui_str(sid)); }
NSString *MS(int mid) { return gzU8(gz_ms(mid)); }

NSString *TRP(int sid)
{
    char b[512];
    gz_ui_plain(b, sizeof b, gz_ui_str(sid));
    NSString *s = gzU8(b);
    if ([s hasSuffix:@"..."]) s = [[s substringToIndex:s.length - 3] stringByAppendingString:@"…"];
    return s;
}

NSString *TRF(int sid, NSArray<NSString *> *args)
{
    const char *a[8];
    uint32_t n = 0;
    for (NSString *s in args) {
        if (n >= 8) break;
        a[n++] = s.UTF8String ? s.UTF8String : "";
    }
    char b[2048];
    gz_ui_format(b, sizeof b, gz_ui_str(sid), a, n);
    return gzU8(b);
}

/* ======================================================================
 * UTF-16 <-> NSString, paths
 * ====================================================================== */

NSString *gzNSn(const gzch *w, size_t n)
{
    if (!w || !n) return @"";
    /* lone surrogates (bytes that were not UTF-8, see os.h) -> U+FFFD for display */
    size_t bad = 0;
    for (size_t i = 0; i < n; i++) {
        gzch c = w[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && w[i + 1] >= 0xDC00 && w[i + 1] < 0xE000) { i++; continue; }
        if (c >= 0xD800 && c < 0xE000) bad++;
    }
    if (!bad) return [NSString stringWithCharacters:(const unichar *)w length:n];
    unichar *t = (unichar *)malloc(n * sizeof(unichar));
    if (!t) return @"";
    for (size_t i = 0; i < n; i++) {
        gzch c = w[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && w[i + 1] >= 0xDC00 && w[i + 1] < 0xE000) {
            t[i] = c;
            t[i + 1] = w[i + 1];
            i++;
            continue;
        }
        t[i] = c >= 0xD800 && c < 0xE000 ? 0xFFFD : c;
    }
    NSString *r = [NSString stringWithCharacters:t length:n];
    free(t);
    return r;
}

NSString *gzNS(const gzch *w) { return w ? gzNSn(w, gz_wcslen(w)) : @""; }

gzch *gzW(NSString *s)
{
    NSUInteger n = s.length;
    gzch *w = (gzch *)gz_alloc((n + 1) * sizeof(gzch));
    if (!w) return NULL;
    if (n) [s getCharacters:(unichar *)w range:NSMakeRange(0, n)];
    w[n] = 0;
    return w;
}

void gzWipeFree(gzch *w)
{
    if (!w) return;
    size_t n = gz_wcslen(w);
    volatile gzch *v = w;
    for (size_t i = 0; i < n; i++) v[i] = 0;
    gz_free(w);
}

gzch *gzPathW(NSString *path)
{
    if (!path.length) return gz_os_path_wide("");
    NSUInteger cap = [path maximumLengthOfBytesUsingEncoding:NSUTF8StringEncoding] + 16;
    char *b = (char *)malloc(cap);
    if (!b) return NULL;
    gzch *w = NULL;
    /* getFileSystemRepresentation never throws (fileSystemRepresentation does) */
    if ([path getFileSystemRepresentation:b maxLength:cap]) w = gz_os_path_wide(b);
    free(b);
    return w;
}

NSString *gzPathNS(const gzch *w)
{
    char *b = gz_os_path_bytes(w ? w : u"");
    if (!b) return gzNS(w);
    NSString *s = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:b length:strlen(b)];
    gz_free(b);
    return s ? s : gzNS(w);
}

void gzCopyAnswer(gzch *dst, NSString *s)
{
    NSUInteger n = s.length;
    if (n > GZ_ASK_CAP - 1) n = GZ_ASK_CAP - 1;
    if (n) [s getCharacters:(unichar *)dst range:NSMakeRange(0, n)];
    dst[n] = 0;
}

/* ======================================================================
 * formatting
 * ====================================================================== */

NSString *fmtSize(u64 v)
{
    char b[48];
    gz_ui_fmt_size(b, sizeof b, v);
    return gzU8(b);
}

NSString *fmtThousands(u64 v)
{
    char b[48];
    gz_ui_fmt_thousands(b, sizeof b, v);
    return gzU8(b);
}

NSString *fmtFiletime(u64 ft)
{
    gz_os_tm tm;
    if (!ft || gz_os_local_time(ft, &tm)) return @"";
    return [NSString stringWithFormat:@"%04d-%02d-%02d %02d:%02d", tm.year, tm.month, tm.day, tm.hour, tm.min];
}

NSString *fmtSizeDate(u64 size, u64 ft)
{
    NSString *s = [NSString stringWithFormat:@"%@ (%@ B)", fmtSize(size), fmtThousands(size)];
    NSString *t = fmtFiletime(ft);
    return t.length ? [NSString stringWithFormat:@"%@  ·  %@", s, t] : s;
}

/* ======================================================================
 * paths
 * ====================================================================== */

BOOL pathIsDir(NSString *p)
{
    BOOL dir = NO;
    return p.length && [[NSFileManager defaultManager] fileExistsAtPath:p isDirectory:&dir] && dir;
}

BOOL pathExists(NSString *p)
{
    struct stat st;
    char b[4096];
    return p.length && [p getFileSystemRepresentation:b maxLength:sizeof b] && !lstat(b, &st);
}

NSString *absPath(NSString *arg)
{
    if ([arg hasPrefix:@"file://"]) {
        NSURL *u = [NSURL URLWithString:arg];
        if (u.isFileURL && u.path.length) return u.path.stringByStandardizingPath;
    }
    NSString *p = arg.stringByExpandingTildeInPath;
    if (!p.absolutePath) p = [[NSFileManager defaultManager].currentDirectoryPath stringByAppendingPathComponent:p];
    return p.stringByStandardizingPath;
}

NSString *displayPath(NSString *p) { return p.stringByAbbreviatingWithTildeInPath; }

/* extensions of formats that are usually opened by other programs */
static const char *const k_docs[] = { "docx", "xlsx", "pptx", "odt", "ods", "odp", "odg", "epub", "doc", "xls",
                                      "ppt", "msg", "bin", "raw", "exe", "dll", "apk", "ipa", "whl", "jar",
                                      "war", "ear", "xpi", "appx", "nupkg", "chm", "chi", "chq", "chw",
                                      "dylib", "so", "o", "a", "ko", "bundle", "macho", "elf", "efi", "sys", 0 };

BOOL isArchiveName(NSString *name)
{
    NSString *ext = name.pathExtension.lowercaseString;
    const char *e8 = ext.UTF8String;
    size_t n = e8 ? strlen(e8) : 0;
    if (!n || n > 16) return NO;
    for (int i = 0; k_docs[i]; i++) if (!strcmp(e8, k_docs[i])) return NO;
    for (int i = 0; gz_formats[i]; i++) {
        const char *e = gz_formats[i]->exts;
        while (e && *e) {
            const char *s = e;
            while (*e && *e != ' ') e++;
            if ((size_t)(e - s) == n && !memcmp(s, e8, n)) return YES;
            while (*e == ' ') e++;
        }
    }
    /* split volumes: name.7z.001 ... are opened by their readers */
    return n == 3 && e8[0] >= '0' && e8[0] <= '9' && e8[1] >= '0' && e8[1] <= '9' && e8[2] >= '0' && e8[2] <= '9';
}

NSString *engineLine(void)
{
    return [NSString stringWithFormat:@"%s  ·  CRC %s  ·  %s", gz_dispatch_inflate_name(), gz_dispatch_crc_name(),
                                      gz_dispatch_aes_name()];
}

static gzch fold(gzch c) { return c >= 'A' && c <= 'Z' ? (gzch)(c + 32) : c; }

/* natural order: case-insensitive, digit runs by value ("a2" < "a10") */
int gzNameCmpNatural(const gzch *a, const gzch *b)
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

/* ======================================================================
 * temporary folders: $TMPDIR/GogitZIP-<pid>/<prefix><n>
 * ($TMPDIR is the per-user folder under /var/folders on macOS)
 * ====================================================================== */

static NSString *s_temp;
static unsigned s_temp_seq;

static BOOL ownDir(NSString *p)
{
    char b[4096];
    struct stat st;
    if (![p getFileSystemRepresentation:b maxLength:sizeof b]) return NO;
    if (mkdir(b, 0700) && errno != EEXIST) return NO;
    if (lstat(b, &st) || !S_ISDIR(st.st_mode) || st.st_uid != getuid()) return NO;
    if ((st.st_mode & 077) && chmod(b, 0700)) return NO;
    return YES;
}

NSString *tempRoot(void)
{
    if (s_temp) return s_temp;
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:
                                              [NSString stringWithFormat:@"GogitZIP-%d", (int)getpid()]];
    if (ownDir(p)) s_temp = p;
    return s_temp;
}

NSString *tempNewDir(NSString *prefix)
{
    NSString *root = tempRoot();
    if (!root) return nil;
    for (int i = 0; i < 1000; i++) {
        NSString *p = [root stringByAppendingPathComponent:[NSString stringWithFormat:@"%@%u", prefix, ++s_temp_seq]];
        char b[4096];
        if (![p getFileSystemRepresentation:b maxLength:sizeof b]) return nil;
        if (!mkdir(b, 0700)) return p;
        if (errno != EEXIST) return nil;
    }
    return nil;
}

void tempSweepStale(void)
{
    NSString *tmp = NSTemporaryDirectory();
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *n in [fm contentsOfDirectoryAtPath:tmp error:NULL]) {
        if (![n hasPrefix:@"GogitZIP-"] || n.length > 20) continue;
        NSString *num = [n substringFromIndex:9];
        long pid = 0;
        BOOL digits = num.length > 0;
        for (NSUInteger i = 0; i < num.length; i++) {
            unichar c = [num characterAtIndex:i];
            if (c < '0' || c > '9') { digits = NO; break; }
            pid = pid * 10 + (c - '0');
        }
        if (!digits || pid <= 0 || pid == (long)getpid()) continue;
        if (kill((pid_t)pid, 0) == 0 || errno == EPERM) continue;      /* still running */
        [fm removeItemAtPath:[tmp stringByAppendingPathComponent:n] error:NULL];
    }
}

void tempCleanup(void)
{
    if (!s_temp) return;
    [[NSFileManager defaultManager] removeItemAtPath:s_temp error:NULL];
    s_temp = nil;
}

/* ======================================================================
 * desktop integration
 * ====================================================================== */

void openWithDefault(NSString *path, NSWindow *parent)
{
    if (![[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:path]])
        msgBox(parent, NSAlertStyleWarning, TR(STR_OPEN_FILE_FAIL), displayPath(path));
}

void showFolder(NSString *path)
{
    if (pathIsDir(path)) [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:path isDirectory:YES]];
}

void msgBox(NSWindow *parent, NSAlertStyle style, NSString *primary, NSString *secondary)
{
    NSAlert *a = [[NSAlert alloc] init];
    a.alertStyle = style;
    a.messageText = primary ? primary : @"";
    if (secondary.length) a.informativeText = secondary;
    [a addButtonWithTitle:TR(STR_OK)];
    if (parent.visible && !parent.attachedSheet) {
        [a beginSheetModalForWindow:parent completionHandler:nil];
    } else {
        [NSApp activateIgnoringOtherApps:YES];
        [a runModal];
    }
}

/* ======================================================================
 * file types: description + icon per lower-case extension
 * ====================================================================== */

static NSMutableDictionary<NSString *, NSArray *> *s_types;

void typesClear(void) { s_types = nil; }

NSImage *folderIcon(void)
{
    static NSImage *img;
    if (!img) img = [NSImage imageNamed:NSImageNameFolder];
    return img;
}

static NSArray *typeInfo(const gzch *name)
{
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
    NSString *k = gzU8(key);
    if (!s_types) s_types = [NSMutableDictionary dictionary];
    NSArray *t = s_types[k];
    if (t) return t;
    NSString *desc = nil;
    NSImage *icon = nil;
    if (n) {
        CFStringRef uti = UTTypeCreatePreferredIdentifierForTag(kUTTagClassFilenameExtension, (__bridge CFStringRef)k,
                                                                NULL);
        if (uti) {
            if (!UTTypeIsDynamic(uti)) desc = CFBridgingRelease(UTTypeCopyDescription(uti));
            CFRelease(uti);
        }
        icon = [[NSWorkspace sharedWorkspace] iconForFileType:k];
    }
    if (!icon) icon = [[NSWorkspace sharedWorkspace] iconForFileType:NSFileTypeForHFSTypeCode(kGenericDocumentIcon)];
    if (!desc.length) desc = n ? [NSString stringWithFormat:@"%@ %@", k.uppercaseString, TR(STR_FILE)] : TR(STR_FILE);
    t = @[ desc, icon ? icon : [NSImage imageNamed:NSImageNameMultipleDocuments] ];
    s_types[k] = t;
    return t;
}

NSString *typeDescription(const gzch *base) { return typeInfo(base)[0]; }
NSImage *typeIcon(const gzch *base) { return typeInfo(base)[1]; }
