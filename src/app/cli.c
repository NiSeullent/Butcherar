/*
 * gogitzip - 고깃ZIP command line tool (Linux / macOS)
 *
 *   gogitzip l archive [names...] [-slt] [-p PASS] [--cp N]
 *   gogitzip x|e archive [names...] [-o DIR] [-p PASS] [-y|-n|-r|--newer] [--smart] [--strip DIR] ...
 *   gogitzip t archive [names...] [-p PASS]
 *   gogitzip a out.tar file|folder... [-f FMT] [-mx0..9] [-p PASS] [--encrypt-names] [--solid|--no-solid]
 *   gogitzip i
 *
 * Messages are Korean when LC_ALL / LC_MESSAGES / LANG starts with "ko".
 * Questions are asked on a terminal (password without echo); without one,
 * existing files are skipped with a warning and passwords must come from -p.
 * Exit codes as 7-Zip: 0 ok, 1 warning, 2 fatal error, 7 command line error,
 * 8 out of memory, 255 stopped by the user.
 */
#if defined(__APPLE__)
#  define _DARWIN_C_SOURCE 1
#elif !defined(_GNU_SOURCE)
#  define _GNU_SOURCE 1
#endif
#include "engine.h"
#include "cpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

enum { EX_OK = 0, EX_WARN = 1, EX_FATAL = 2, EX_USAGE = 7, EX_NOMEM = 8, EX_BREAK = 255 };

/* ---------------- messages ---------------- */

static int g_ko;

enum {
    M_ERROR, M_WARNING, M_NOTE, M_ALL_OK, M_FOLDERS, M_FILES, M_SIZE, M_PACKED, M_ERRORS, M_WARNINGS,
    M_SKIPPED, M_FILES_LC, M_FOLDERS_LC, M_EXTRACTING, M_TESTING, M_LISTING, M_CREATING, M_CANT_OPEN, M_NO_FILE, M_UNKNOWN_CMD,
    M_UNKNOWN_OPT, M_MISSING_ARG, M_NEED_ARCHIVE, M_NEED_INPUT, M_BAD_FORMAT, M_NO_WRITER, M_NO_ENC,
    M_BAD_VALUE, M_EXISTS_SKIP, M_ARC_EXISTS, M_PW_PROMPT, M_PW_RETRY, M_PW_NEEDED, M_OW_HEAD, M_OW_WITH,
    M_OW_KEYS, M_REPLACE_ARC, M_VOL_PROMPT, M_BREAK, M_NO_MATCH, M_ARC_SIZE, M_DEST, M_BYTES, M_HELP,
    M_COUNT
};

static const char *const g_msg[M_COUNT][2] = {
    { "ERROR", "오류" },
    { "WARNING", "경고" },
    { "Note", "참고" },
    { "Everything is Ok", "모두 정상입니다" },
    { "Folders", "폴더" },
    { "Files", "파일" },
    { "Size", "크기" },
    { "Compressed", "압축 크기" },
    { "Errors", "오류 수" },
    { "Warnings", "경고 수" },
    { "Skipped", "건너뜀" },
    { "files", "파일" },
    { "folders", "폴더" },
    { "Extracting archive", "압축 풀기" },
    { "Testing archive", "압축 파일 검사" },
    { "Listing archive", "압축 파일 목록" },
    { "Creating archive", "압축 파일 만들기" },
    { "Cannot open archive", "압축 파일을 열 수 없습니다" },
    { "Cannot find the file", "파일을 찾을 수 없습니다" },
    { "Unknown command", "알 수 없는 명령입니다" },
    { "Unknown option", "알 수 없는 옵션입니다" },
    { "Missing value for option", "옵션 값이 없습니다" },
    { "Archive name expected", "압축 파일 이름이 필요합니다" },
    { "Nothing to compress", "압축할 파일이 없습니다" },
    { "Unknown archive format (use -f)", "알 수 없는 압축 형식입니다 (-f로 지정하세요)" },
    { "Creating this format is not supported", "이 형식으로는 압축할 수 없습니다" },
    { "This format does not support encryption", "이 형식은 암호를 지원하지 않습니다" },
    { "Invalid value", "잘못된 값입니다" },
    { "already exists, skipped (-y overwrites, -r renames)", "이미 있어서 건너뛰었습니다 (-y: 덮어쓰기, -r: 이름 바꾸기)" },
    { "Archive already exists (-y replaces it)", "압축 파일이 이미 있습니다 (-y: 바꾸기)" },
    { "Enter password", "암호를 입력하세요" },
    { "Wrong password, enter it again", "암호가 틀렸습니다. 다시 입력하세요" },
    { "Password required (use -p)", "암호가 필요합니다 (-p로 지정하세요)" },
    { "Would you like to replace the existing file", "이미 있는 파일을 바꿀까요" },
    { "with the file from the archive", "압축 파일 안의 파일" },
    { "(Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (R)ename / (Q)uit? ",
      "(Y)예 / (N)아니요 / (A)모두 예 / (S)모두 건너뛰기 / (U)모두 이름 바꾸기 / (R)이름 바꾸기 / (Q)중단? " },
    { "Replace the existing archive? (Y)es / (N)o? ", "이미 있는 압축 파일을 바꿀까요? (Y)예 / (N)아니요? " },
    { "Volume not found. Enter its path (empty: stop)", "다음 볼륨을 찾을 수 없습니다. 경로를 입력하세요 (빈 줄: 중단)" },
    { "Stopped by the user", "사용자가 중단했습니다" },
    { "No files to process", "처리할 파일이 없습니다" },
    { "Archive size", "압축 파일 크기" },
    { "Destination", "대상 폴더" },
    { "bytes", "바이트" },
    { "고깃ZIP " GZ_APP_VERSION " - archive tool\n"
      "\n"
      "Usage: gogitzip <command> [options] <archive> [names...]\n"
      "\n"
      "Commands:\n"
      "  l   list contents (-slt: technical details)\n"
      "  x   extract with full paths\n"
      "  e   extract without paths\n"
      "  t   test integrity\n"
      "  a   create: gogitzip a out.tar files/folders...\n"
      "  i   show supported formats and CPU kernels\n"
      "\n"
      "Options:\n"
      "  -o DIR          destination folder (x/e)\n"
      "  -p PASS         password\n"
      "  -y | -n | -r    overwrite all / skip existing / rename new files\n"
      "  --newer         overwrite only when the archive's file is newer\n"
      "  --smart         extract into a folder named after the archive when needed\n"
      "  --strip DIR     extract only DIR's contents, without the DIR prefix\n"
      "  --cp N          code page for legacy names (949, 932, 936, 437...)\n"
      "  -t N            threads\n"
      "  -f FMT          format: tar zip 7z tgz tbz2 txz tzst gz bz2 xz zst iso\n"
      "  -mx0..9         compression level      -mm=NAME  method (store deflate lzma2...)\n"
      "  --encrypt-names encrypt file names (7z)  --em=aes256|zipcrypto  ZIP encryption\n"
      "  --solid | --no-solid                    solid 7z archive\n"
      "  --follow-links  store what links point to   --unsafe-links  allow links leaving the folder\n"
      "  --keep-broken   keep damaged files     --keep-setuid  --no-perms  --no-times  --no-links\n"
      "  -bd             no progress display\n",
      "고깃ZIP " GZ_APP_VERSION " - 압축 프로그램\n"
      "\n"
      "사용법: gogitzip <명령> [옵션] <압축 파일> [이름...]\n"
      "\n"
      "명령:\n"
      "  l   목록 보기 (-slt: 자세히)\n"
      "  x   경로를 살려서 풀기\n"
      "  e   경로 없이 풀기\n"
      "  t   압축 파일 검사\n"
      "  a   압축하기: gogitzip a out.tar 파일/폴더...\n"
      "  i   지원 형식과 CPU 커널 보기\n"
      "\n"
      "옵션:\n"
      "  -o 폴더         풀 위치 (x/e)\n"
      "  -p 암호         암호\n"
      "  -y | -n | -r    모두 덮어쓰기 / 있는 파일 건너뛰기 / 새 파일 이름 바꾸기\n"
      "  --newer         압축 파일 쪽이 더 새로울 때만 덮어쓰기\n"
      "  --smart         필요할 때 압축 파일 이름으로 폴더를 만들어 풀기\n"
      "  --strip 폴더    그 폴더의 내용만 폴더 이름 없이 풀기\n"
      "  --cp N          옛 파일 이름의 코드 페이지 (949, 932, 936, 437...)\n"
      "  -t N            스레드 수\n"
      "  -f 형식         tar zip 7z tgz tbz2 txz tzst gz bz2 xz zst iso\n"
      "  -mx0..9         압축 수준              -mm=이름  압축 방식 (store deflate lzma2...)\n"
      "  --encrypt-names 파일 이름도 암호화 (7z)  --em=aes256|zipcrypto  ZIP 암호 방식\n"
      "  --solid | --no-solid                    7z 솔리드 압축\n"
      "  --follow-links  링크 대신 링크가 가리키는 파일 저장   --unsafe-links  폴더 밖을 가리키는 링크 허용\n"
      "  --keep-broken   손상된 파일도 남기기   --keep-setuid  --no-perms  --no-times  --no-links\n"
      "  -bd             진행 표시 끄기\n" },
};
#define T(m) g_msg[m][g_ko]

static const char *const g_err[GZ_E_COUNT][2] = {
    { "OK", "정상" },
    { "Read or write error", "읽기/쓰기 오류" },
    { "Unsupported or damaged archive", "지원하지 않거나 손상된 압축 파일" },
    { "Data error", "데이터 오류" },
    { "CRC failed", "CRC 오류" },
    { "Unsupported compression method", "지원하지 않는 압축 방식" },
    { "Wrong password", "암호가 틀렸습니다" },
    { "Not enough memory", "메모리가 부족합니다" },
    { "Canceled", "취소됨" },
    { "Unexpected end of data", "데이터가 중간에 끝났습니다" },
    { "Skipped", "건너뜀" },
    { "Cannot create file", "파일을 만들 수 없습니다" },
    { "Authentication failed (wrong password or damaged data)", "인증 실패 (암호가 틀렸거나 손상됨)" },
    { "Disk full", "디스크 공간이 부족합니다" },
    { "Missing volume", "다음 볼륨이 없습니다" },
    { "Exceeds a safety limit", "안전 한도를 넘었습니다" },
};

static const char *const g_note[GZ_N_LAST - GZ_N_FIRST][2] = {
    { "renamed to", "다른 이름으로 저장" },
    { "name too long for the file system, shortened", "이름이 너무 길어 줄였습니다" },
    { "path too long", "경로가 너무 깁니다" },
    { "link to an absolute path not created", "절대 경로를 가리키는 링크는 만들지 않았습니다" },
    { "link pointing outside the destination not created", "대상 폴더 밖을 가리키는 링크는 만들지 않았습니다" },
    { "link inside a linked folder not created", "링크된 폴더 안의 링크는 만들지 않았습니다" },
    { "link skipped", "링크를 건너뛰었습니다" },
    { "cannot create link", "링크를 만들 수 없습니다" },
    { "hard link target missing", "하드 링크 대상이 없습니다" },
    { "special file skipped", "특수 파일을 건너뛰었습니다" },
    { "folder loop skipped", "폴더 순환을 건너뛰었습니다" },
    { "not found", "찾을 수 없습니다" },
    { "cannot read", "읽을 수 없습니다" },
    { "this format holds exactly one file", "이 형식에는 파일 하나만 넣을 수 있습니다" },
    { "archive already exists (-y replaces it)", "압축 파일이 이미 있습니다 (-y: 바꾸기)" },
    { "creating this format is not supported", "이 형식으로는 압축할 수 없습니다" },
    { "nothing to compress", "압축할 파일이 없습니다" },
};

static const char *code_text(int code)
{
    if (code >= 0 && code < GZ_E_COUNT) return g_err[code][g_ko];
    if (code >= GZ_N_FIRST && code < GZ_N_LAST) return g_note[code - GZ_N_FIRST][g_ko];
    return g_err[GZ_E_IO][g_ko];
}

static void pick_language(void)
{
    const char *vars[] = { "LC_ALL", "LC_MESSAGES", "LANG" };
    for (int i = 0; i < 3; i++) {
        const char *v = getenv(vars[i]);
        if (v && *v) { g_ko = !strncmp(v, "ko", 2); return; }
    }
}

/* ---------------- text helpers ---------------- */

static char *utf8s(const gzch *w) { return w ? gz_os_path_bytes(w) : 0; }   /* gz_free */

static gzch *wide(const char *s) { return gz_os_path_wide(s); }

static char *xstrdup(const char *s)
{
    size_t n = strlen(s);
    char *d = (char *)malloc(n + 1);
    if (!d) { fprintf(stderr, "%s\n", g_err[GZ_E_NOMEM][g_ko]); exit(EX_NOMEM); }
    memcpy(d, s, n + 1);
    return d;
}

/* absolute, lexically normalised path of a command line argument */
static char *abs_path(const char *arg)
{
    char cwd[4096];
    size_t an = strlen(arg);
    char *buf;
    if (arg[0] == '/') {
        buf = xstrdup(arg);
    } else {
        if (!getcwd(cwd, sizeof cwd)) return xstrdup(arg);     /* stays relative */
        buf = (char *)malloc(strlen(cwd) + an + 2);
        if (!buf) exit(EX_NOMEM);
        sprintf(buf, "%s/%s", cwd, arg);
    }
    /* collapse "//", "/./", "/x/.." */
    size_t n = strlen(buf), o = 0, i = 0;
    char *out = (char *)malloc(n + 2);
    if (!out) exit(EX_NOMEM);
    while (i < n) {
        while (i < n && buf[i] == '/') i++;
        size_t st = i;
        while (i < n && buf[i] != '/') i++;
        size_t len = i - st;
        if (!len || (len == 1 && buf[st] == '.')) continue;
        if (len == 2 && buf[st] == '.' && buf[st + 1] == '.') {
            while (o && out[o - 1] != '/') o--;
            if (o) o--;
            continue;
        }
        out[o++] = '/';
        memcpy(out + o, buf + st, len);
        o += len;
    }
    if (!o) out[o++] = '/';
    out[o] = 0;
    free(buf);
    return out;
}

static void fmt_time(char *o, u64 ft)
{
    gz_os_tm tm;
    if (!ft || gz_os_local_time(ft, &tm)) { strcpy(o, "                   "); return; }
    snprintf(o, 24, "%04d-%02d-%02d %02d:%02d:%02d", tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec);
}

/* ---------------- terminal ---------------- */

static volatile sig_atomic_t g_sigint;
static struct termios g_tios;
static volatile sig_atomic_t g_tios_saved;

static void on_signal(int sig)
{
    (void)sig;
    if (g_tios_saved) tcsetattr(0, TCSANOW, &g_tios);
    if (g_sigint) _exit(EX_BREAK);
    g_sigint = 1;
}

static void install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, 0);
    sigaction(SIGTERM, &sa, 0);
    sigaction(SIGHUP, &sa, 0);
    signal(SIGPIPE, SIG_IGN);
}

typedef struct cli {
    int interactive;          /* stdin and stderr are terminals                 */
    int progress;             /* draw progress on stderr                         */
    int shown;                /* a progress line is on screen                    */
    int prompting;
    int warnings;             /* warnings issued by the CLI itself               */
    int pw_hint;
    gz_os_mutex *tty;
} cli;

static cli g;

static void clear_line(void)
{
    if (g.shown) { fputs("\r\033[K", stderr); g.shown = 0; }
}

/* Show prompt (stderr) and read a line from stdin; 1 ok, 0 end of input, -1 interrupted.
 * Without echo the terminal is switched first, so nothing typed early is shown. */
static int read_line(const char *prompt, char *buf, size_t cap, int echo)
{
    struct termios old;
    int restore = 0;
    if (!echo && isatty(0) && !tcgetattr(0, &old)) {
        struct termios nw = old;
        nw.c_lflag &= ~(tcflag_t)ECHO;
        g_tios = old;
        g_tios_saved = 1;
        tcsetattr(0, TCSAFLUSH, &nw);
        restore = 1;
    }
    if (prompt) { fputs(prompt, stderr); fflush(stderr); }
    size_t n = 0;
    int ok = 1;
    for (;;) {
        if (g_sigint) { ok = -1; break; }
        struct pollfd pf = { 0, POLLIN, 0 };
        int pr = poll(&pf, 1, 100);
        if (pr < 0) { if (errno == EINTR) continue; ok = 0; break; }
        if (!pr) continue;
        char ch;
        ssize_t r = read(0, &ch, 1);
        if (r < 0) { if (errno == EINTR || errno == EAGAIN) continue; ok = 0; break; }
        if (r == 0) { ok = n ? 1 : 0; break; }
        if (ch == '\n' || ch == '\r') break;
        if (n + 1 < cap) buf[n++] = ch;
    }
    buf[n] = 0;
    if (restore) {
        tcsetattr(0, TCSANOW, &old);
        g_tios_saved = 0;
        fputc('\n', stderr);
    }
    return ok;
}

static void print_wrapped(FILE *f, const char *label, const gzch *w)
{
    char *s = utf8s(w);
    fprintf(f, "%s%s\n", label, s ? s : "");
    gz_free(s);
}

static int ask_overwrite(gz_ask *q)
{
    char *p = utf8s(q->path);
    if (!g.interactive) {
        gz_os_mutex_lock(g.tty);
        clear_line();
        fprintf(stderr, "%s: %s : %s\n", T(M_WARNING), p ? p : "", T(M_EXISTS_SKIP));
        g.warnings++;
        gz_os_mutex_unlock(g.tty);
        gz_free(p);
        return GZ_ANS_NO;
    }
    gz_os_mutex_lock(g.tty);
    g.prompting = 1;
    clear_line();
    char t1[32], t2[32];
    fmt_time(t1, q->old_mtime);
    fmt_time(t2, q->new_mtime);
    fprintf(stderr, "\n%s:\n  %s\n  %llu %s  %s\n", T(M_OW_HEAD), p ? p : "",
            (unsigned long long)q->old_size, T(M_BYTES), t1);
    char *en = utf8s(q->entry);
    fprintf(stderr, "%s:\n  %s\n  %llu %s  %s\n", T(M_OW_WITH), en ? en : "", (unsigned long long)q->new_size,
            T(M_BYTES), t2);
    gz_free(en);
    int ans = GZ_ANS_CANCEL;
    for (;;) {
        char line[64];
        int r = read_line(T(M_OW_KEYS), line, sizeof line, 1);
        if (r <= 0) { ans = GZ_ANS_CANCEL; break; }
        char c = line[0] | 32;
        if (c == 'y') { ans = GZ_ANS_YES; break; }
        if (c == 'n') { ans = GZ_ANS_NO; break; }
        if (c == 'a') { ans = GZ_ANS_YES_ALL; break; }
        if (c == 's') { ans = GZ_ANS_NO_ALL; break; }
        if (c == 'u') { ans = GZ_ANS_RENAME_ALL; break; }
        if (c == 'r') { ans = GZ_ANS_RENAME; break; }
        if (c == 'q') { ans = GZ_ANS_CANCEL; break; }
    }
    g.prompting = 0;
    gz_os_mutex_unlock(g.tty);
    gz_free(p);
    return ans;
}

static int ask_password(gz_ask *q)
{
    if (!g.interactive) {
        gz_os_mutex_lock(g.tty);
        if (!g.pw_hint) {
            clear_line();
            fprintf(stderr, "%s: %s\n", T(M_ERROR), T(M_PW_NEEDED));
            g.pw_hint = 1;
        }
        gz_os_mutex_unlock(g.tty);
        return GZ_ANS_NO;
    }
    gz_os_mutex_lock(g.tty);
    g.prompting = 1;
    clear_line();
    char *p = utf8s(q->path), prompt[4200];
    snprintf(prompt, sizeof prompt, "%s (%s): ", q->retry ? T(M_PW_RETRY) : T(M_PW_PROMPT), p ? p : "");
    gz_free(p);
    char line[1024];
    int r = read_line(prompt, line, sizeof line, 0);
    g.prompting = 0;
    gz_os_mutex_unlock(g.tty);
    if (r < 0) return GZ_ANS_CANCEL;
    if (r == 0 || !line[0]) return GZ_ANS_NO;
    gzch *w = wide(line);
    memset(line, 0, sizeof line);
    if (!w) return GZ_ANS_NO;
    size_t i = 0;
    for (; w[i] && i + 1 < GZ_ASK_CAP; i++) q->answer[i] = w[i];
    q->answer[i] = 0;
    gz_free(w);
    return GZ_ANS_YES;
}

static int ask_volume(gz_ask *q)
{
    if (!g.interactive) return GZ_ANS_NO;
    gz_os_mutex_lock(g.tty);
    g.prompting = 1;
    clear_line();
    print_wrapped(stderr, "\n", q->path);
    char prompt[256], line[4096];
    snprintf(prompt, sizeof prompt, "%s: ", T(M_VOL_PROMPT));
    int r = read_line(prompt, line, sizeof line, 1);
    g.prompting = 0;
    gz_os_mutex_unlock(g.tty);
    if (r < 0) return GZ_ANS_CANCEL;
    if (r == 0 || !line[0]) return GZ_ANS_NO;
    char *ap = abs_path(line);
    gzch *w = wide(ap);
    free(ap);
    if (!w) return GZ_ANS_NO;
    size_t i = 0;
    for (; w[i] && i + 1 < GZ_ASK_CAP; i++) q->answer[i] = w[i];
    q->answer[i] = 0;
    gz_free(w);
    return GZ_ANS_YES;
}

static int cb_ask(void *user, gz_ask *q)
{
    (void)user;
    if (g_sigint) return GZ_ANS_CANCEL;
    switch (q->kind) {
    case GZ_ASK_OVERWRITE: return ask_overwrite(q);
    case GZ_ASK_PASSWORD: return ask_password(q);
    case GZ_ASK_VOLUME: return ask_volume(q);
    }
    return GZ_ANS_CANCEL;
}

static int term_cols(void)
{
    struct winsize ws;
    if (!ioctl(2, TIOCGWINSZ, &ws) && ws.ws_col > 20) return ws.ws_col;
    return 80;
}

static void cb_progress(void *user, const gz_progress *p)
{
    (void)user;
    if (!g.progress) return;
    gz_os_mutex_lock(g.tty);
    if (!g.prompting) {
        int pct = p->total_bytes ? (int)(p->done_bytes * 100 / p->total_bytes) : 0;
        if (pct > 100) pct = 100;
        char head[64];
        int hn = snprintf(head, sizeof head, "%3d%% %u", pct, p->done_files);
        if (p->total_files) hn += snprintf(head + hn, sizeof head - (size_t)hn, "/%u", p->total_files);
        int room = term_cols() - hn - 3;
        /* tail of the current name that fits (wide characters take two columns) */
        const gzch *cur = p->current ? p->current : u"";
        size_t n = gz_wcslen(cur), st = n;
        int cols = 0;
        while (st > 0) {
            gzch c = cur[st - 1];
            int w = c >= 0x1100 && !(c >= 0xDC00 && c < 0xE000) ? 2 : 1;
            if (c >= 0xDC00 && c < 0xE000) w = 0;
            if (cols + w > room) break;
            cols += w;
            st--;
        }
        char *s = utf8s(cur + st);
        fprintf(stderr, "\r%s %s\033[K", head, s ? s : "");
        gz_free(s);
        fflush(stderr);
        g.shown = 1;
    }
    gz_os_mutex_unlock(g.tty);
}

static void cb_log(void *user, const gz_log *l)
{
    (void)user;
    gz_os_mutex_lock(g.tty);
    clear_line();
    const char *lv = l->level == GZ_LOG_ERROR ? T(M_ERROR) : l->level == GZ_LOG_WARN ? T(M_WARNING) : T(M_NOTE);
    char *n = utf8s(l->name), *d = utf8s(l->detail);
    if (l->code == GZ_E_PASSWORD && g.pw_hint) {
        fprintf(stderr, "%s: %s : %s\n", lv, n ? n : "", code_text(l->code));
    } else if (d) {
        fprintf(stderr, "%s: %s : %s : %s\n", lv, n ? n : "", code_text(l->code), d);
    } else {
        fprintf(stderr, "%s: %s : %s\n", lv, n ? n : "", code_text(l->code));
    }
    gz_free(n);
    gz_free(d);
    gz_os_mutex_unlock(g.tty);
}

static gz_callbacks g_cb = { 0, cb_ask, cb_progress, cb_log, 0 };

static int wait_job(gz_job *j)
{
    while (!gz_job_wait_for(j, 100)) if (g_sigint) gz_job_cancel(j);
    int r = gz_job_wait(j);
    gz_os_mutex_lock(g.tty);
    clear_line();
    gz_os_mutex_unlock(g.tty);
    return r;
}

/* ---------------- options ---------------- */

typedef struct opts {
    char cmd;
    const char *archive;
    char **names; int nnames;
    const char *outdir, *password, *strip, *fmt, *method, *em;
    int ow, cp, threads, smart, slt, bd, level, enc_names, solid, follow, cpu;
    u32 xflags;
} opts;

static int usage_error(int m, const char *what)
{
    if (what) fprintf(stderr, "%s: %s: %s\n", T(M_ERROR), T(m), what);
    else fprintf(stderr, "%s: %s\n", T(M_ERROR), T(m));
    return EX_USAGE;
}

/* option value: attached ("-oDIR", "--cp=949") or the next argument */
static const char *opt_val(const char *attached, int *i, int argc, char **argv)
{
    if (attached && *attached) return attached[0] == '=' ? attached + 1 : attached;
    if (*i + 1 < argc) return argv[++*i];
    return 0;
}

static int parse_int(const char *s, int lo, int hi, int *out)
{
    if (!s || !*s) return 0;
    char *e;
    long v = strtol(s, &e, 10);
    if (*e || v < lo || v > hi) return 0;
    *out = (int)v;
    return 1;
}

static int parse(int argc, char **argv, opts *o)
{
    memset(o, 0, sizeof *o);
    o->ow = -1;
    o->level = 5;
    o->solid = -1;
    o->cpu = -1;
    o->names = (char **)calloc((size_t)argc + 1, sizeof(char *));
    if (!o->names) exit(EX_NOMEM);
    int done = 0;
    for (int i = 2; i < argc; i++) {
        char *a = argv[i];
        if (done || a[0] != '-' || !a[1]) {
            if (!o->archive) o->archive = a;
            else o->names[o->nnames++] = a;
            continue;
        }
        if (!strcmp(a, "--")) { done = 1; continue; }
        const char *v;
#define LONGV(name) (!strncmp(a, name, sizeof name - 1) && (a[sizeof name - 1] == 0 || a[sizeof name - 1] == '='))
#define NEED(x) do { if (!(x)) return usage_error(M_MISSING_ARG, a); } while (0)
        if (!strncmp(a, "-o", 2) && a[1] == 'o') { NEED(v = opt_val(a + 2, &i, argc, argv)); o->outdir = v; }
        else if (a[1] == 'p') { NEED(v = opt_val(a + 2, &i, argc, argv)); o->password = v; }
        else if (!strcmp(a, "-y")) o->ow = GZ_OW_ALL;
        else if (!strcmp(a, "-n")) o->ow = GZ_OW_SKIP;
        else if (!strcmp(a, "-r")) o->ow = GZ_OW_RENAME;
        else if (!strcmp(a, "--newer")) o->ow = GZ_OW_NEWER;
        else if (!strcmp(a, "--smart")) o->smart = 1;
        else if (!strcmp(a, "-slt")) o->slt = 1;
        else if (!strcmp(a, "-bd")) o->bd = 1;
        else if (LONGV("--cp")) { NEED(v = opt_val(a + 4, &i, argc, argv)); if (!parse_int(v, 1, 65535, &o->cp)) return usage_error(M_BAD_VALUE, a); }
        else if (LONGV("--cpu")) { NEED(v = opt_val(a + 5, &i, argc, argv)); if (!parse_int(v, 0, GZ_TIER_COUNT - 1, &o->cpu)) return usage_error(M_BAD_VALUE, a); }
        else if (LONGV("--strip")) { NEED(v = opt_val(a + 7, &i, argc, argv)); o->strip = v; }
        else if (!strncmp(a, "-t", 2) && a[1] == 't') { NEED(v = opt_val(a + 2, &i, argc, argv)); if (!parse_int(v, 1, 256, &o->threads)) return usage_error(M_BAD_VALUE, a); }
        else if (!strncmp(a, "-f", 2) && a[1] == 'f') { NEED(v = opt_val(a + 2, &i, argc, argv)); o->fmt = v; }
        else if (!strncmp(a, "-mx", 3)) {
            const char *s = a[3] == '=' ? a + 4 : a + 3;
            if (!*s) o->level = 9;
            else if (!parse_int(s, 0, 9, &o->level)) return usage_error(M_BAD_VALUE, a);
        }
        else if (!strncmp(a, "-mm=", 4)) o->method = a + 4;
        else if (LONGV("--method")) { NEED(v = opt_val(a + 8, &i, argc, argv)); o->method = v; }
        else if (!strncmp(a, "-mem=", 5)) o->em = a + 5;
        else if (LONGV("--em")) { NEED(v = opt_val(a + 4, &i, argc, argv)); o->em = v; }
        else if (!strcmp(a, "--encrypt-names") || !strcmp(a, "-mhe=on") || !strcmp(a, "-mhe")) o->enc_names = 1;
        else if (!strcmp(a, "--solid") || !strcmp(a, "-ms=on")) o->solid = 1;
        else if (!strcmp(a, "--no-solid") || !strcmp(a, "-ms=off")) o->solid = 0;
        else if (!strcmp(a, "--follow-links")) o->follow = 1;
        else if (!strcmp(a, "--unsafe-links")) o->xflags |= GZ_XF_UNSAFE_LINKS;
        else if (!strcmp(a, "--keep-broken")) o->xflags |= GZ_XF_KEEP_BROKEN;
        else if (!strcmp(a, "--keep-setuid")) o->xflags |= GZ_XF_SETUID;
        else if (!strcmp(a, "--no-perms")) o->xflags |= GZ_XF_NO_PERMS;
        else if (!strcmp(a, "--no-times")) o->xflags |= GZ_XF_NO_TIMES;
        else if (!strcmp(a, "--no-links")) o->xflags |= GZ_XF_NO_LINKS;
        else return usage_error(M_UNKNOWN_OPT, a);
#undef LONGV
#undef NEED
    }
    return 0;
}

/* ---------------- selection by names / wildcards ---------------- */

static int wild(const char *p, const char *s)
{
    const char *star = 0, *ss = 0;
    while (*s) {
        if (*p == '?' || *p == *s) { p++; s++; continue; }
        if (*p == '*') { star = p++; ss = s; continue; }
        if (star) { p = star + 1; s = ++ss; continue; }
        return 0;
    }
    while (*p == '*') p++;
    return !*p;
}

static int name_matches(const char *pat, const char *name)
{
    while (pat[0] == '.' && pat[1] == '/') pat += 2;
    size_t pl = strlen(pat);
    while (pl > 1 && pat[pl - 1] == '/') pl--;
    char p[4096];
    if (pl >= sizeof p) return 0;
    memcpy(p, pat, pl);
    p[pl] = 0;
    int has_wild = strpbrk(p, "*?") != 0;
    /* the name itself or one of its parent folders */
    char tmp[8192];
    size_t n = strlen(name);
    if (n >= sizeof tmp) return 0;
    memcpy(tmp, name, n + 1);
    for (;;) {
        if (has_wild ? wild(p, tmp) : !strcmp(p, tmp)) return 1;
        if (has_wild && !strchr(p, '/')) {
            const char *b = strrchr(tmp, '/');
            if (wild(p, b ? b + 1 : tmp)) return 1;
        }
        char *sl = strrchr(tmp, '/');
        if (!sl) return 0;
        *sl = 0;
    }
}

/* selection mask (NULL = everything); *count = selected entries */
static u8 *select_names(gz_archive *a, opts *o, u32 *count)
{
    *count = a->n;
    if (!o->nnames) return 0;
    u8 *sel = (u8 *)calloc(a->n + 1, 1);
    if (!sel) exit(EX_NOMEM);
    *count = 0;
    for (u32 i = 0; i < a->n; i++) {
        char *nm = utf8s(a->e[i].name);
        if (!nm) continue;
        for (int k = 0; k < o->nnames; k++)
            if (name_matches(o->names[k], nm)) { sel[i] = 1; (*count)++; break; }
        gz_free(nm);
    }
    return sel;
}

/* ---------------- commands ---------------- */

static int open_failed(const char *path, int r)
{
    struct stat st;
    if (r == GZ_E_CANCEL || g_sigint) { fprintf(stderr, "%s\n", T(M_BREAK)); return EX_BREAK; }
    if (r == GZ_E_NOMEM) { fprintf(stderr, "%s: %s\n", T(M_ERROR), code_text(r)); return EX_NOMEM; }
    if (stat(path, &st)) fprintf(stderr, "%s: %s: %s\n", T(M_ERROR), T(M_NO_FILE), path);
    else fprintf(stderr, "%s: %s: %s : %s\n", T(M_ERROR), T(M_CANT_OPEN), path, code_text(r));
    return EX_FATAL;
}

static int open_handle(opts *o, gz_handle **h, char **ap)
{
    if (!o->archive) return usage_error(M_NEED_ARCHIVE, 0);
    *ap = abs_path(o->archive);
    gzch *wp = wide(*ap);
    gzch *pw = o->password ? wide(o->password) : 0;
    if (!wp) exit(EX_NOMEM);
    gz_open_req req;
    memset(&req, 0, sizeof req);
    req.codepage = o->cp;
    req.password = pw;
    int r = gz_handle_open(h, wp, &req, &g_cb);
    gz_os_mutex_lock(g.tty);
    clear_line();
    gz_os_mutex_unlock(g.tty);
    gz_free(wp);
    gz_free(pw);
    if (r) {
        r = open_failed(*ap, r);
        free(*ap);
        *ap = 0;
    }
    return r;
}

static void attr_text(const gz_entry *e, char *o)
{
    o[0] = e->is_dir ? 'D' : '.';
    o[1] = (e->attr & 1) ? 'R' : '.';
    o[2] = (e->attr & 2) ? 'H' : '.';
    o[3] = (e->attr & 4) ? 'S' : '.';
    o[4] = e->is_dir ? '.' : (e->is_link ? 'L' : 'A');
    o[5] = 0;
}

static void mode_text(u32 m, char *o)
{
    u32 t = m & 0170000;
    o[0] = t == 0040000 ? 'd' : t == 0120000 ? 'l' : t == 0100000 ? '-' : t ? '?' : '-';
    const char *r = "rwxrwxrwx";
    for (int i = 0; i < 9; i++) o[1 + i] = (m & (0400u >> i)) ? r[i] : '-';
    if (m & 04000) o[3] = (m & 0100) ? 's' : 'S';
    if (m & 02000) o[6] = (m & 0010) ? 's' : 'S';
    if (m & 01000) o[9] = (m & 0001) ? 't' : 'T';
    o[10] = 0;
}

static int cmd_list(opts *o)
{
    gz_handle *h;
    char *ap;
    int r = open_handle(o, &h, &ap);
    if (r) return r;
    gz_archive *a = h->arc;
    u32 cnt;
    u8 *sel = select_names(a, o, &cnt);
    printf("%s: %s\n\n", T(M_LISTING), ap);
    printf("Path = %s\nType = %s\nPhysical Size = %llu\n", ap, gz_arc_type_name(a), (unsigned long long)h->src->size);
    if (a->comment) { char *c = utf8s(a->comment); printf("Comment = %s\n", c ? c : ""); gz_free(c); }
    printf("\n");
    u64 tu = 0, tc = 0;
    u32 nf = 0, nd = 0;
    if (!o->slt) {
        printf("   Date      Time    Attr         Size   Compressed  Name\n");
        printf("------------------- ----- ------------ ------------  ------------------------\n");
    } else {
        printf("----------\n");
    }
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        if ((sel && !sel[i]) || !e->name[0]) continue;
        char t[32], at[8], *nm = utf8s(e->name);
        fmt_time(t, gz_entry_time(e));
        attr_text(e, at);
        if (e->is_dir) nd++;
        else {
            nf++;
            if (e->usize != GZ_SIZE_UNKNOWN) tu += e->usize;
            if (e->csize != GZ_SIZE_UNKNOWN) tc += e->csize;
        }
        char us[24] = "", cs[24] = "";
        if (!e->is_dir && e->usize != GZ_SIZE_UNKNOWN) snprintf(us, sizeof us, "%llu", (unsigned long long)e->usize);
        if (!e->is_dir && e->csize != GZ_SIZE_UNKNOWN) snprintf(cs, sizeof cs, "%llu", (unsigned long long)e->csize);
        if (!o->slt) {
            printf("%s %s %12s %12s  %s\n", t, at, us, cs, nm ? nm : "");
        } else {
            gzch mw[96];
            gz_arc_method(a, e, mw, 96);
            char *m = utf8s(mw);
            char md[16];
            printf("Path = %s\nFolder = %s\n", nm ? nm : "", e->is_dir ? "+" : "-");
            if (!e->is_dir) printf("Size = %s\nPacked Size = %s\n", us, cs);
            printf("Modified = %s\nAttributes = %s", e->mtime_kind ? t : "", at);
            if (e->unix_mode) { mode_text(e->unix_mode, md); printf(" %s", md); }
            printf("\n");
            if (e->has_crc) printf("CRC = %08X\n", e->crc);
            printf("Encrypted = %s\n", e->enc ? "+" : "-");
            if (m && m[0]) printf("Method = %s\n", m);
            gzch *lt = gz_entry_link_target(a, e);
            if (lt) {
                char *ls = utf8s(lt);
                printf("%s = %s\n", e->is_link == 2 ? "Hard Link" : "Symbolic Link", ls ? ls : "");
                gz_free(ls);
                gz_free(lt);
            }
            printf("\n");
            gz_free(m);
        }
        gz_free(nm);
    }
    if (!o->slt) {
        printf("------------------- ----- ------------ ------------  ------------------------\n");
        printf("%19s %5s %12llu %12llu  %u %s, %u %s\n", "", "", (unsigned long long)tu, (unsigned long long)tc,
               nf, T(M_FILES_LC), nd, T(M_FOLDERS_LC));
    }
    int ex = (o->nnames && !cnt) ? EX_WARN : EX_OK;
    if (ex) fprintf(stderr, "%s: %s\n", T(M_WARNING), T(M_NO_MATCH));
    free(sel);
    free(ap);
    gz_handle_close(h);
    return ex;
}

static int job_exit(gz_job *j, int result)
{
    gz_progress p;
    gz_job_progress(j, &p);
    if (g_sigint || result == GZ_E_CANCEL) return EX_BREAK;
    if (result == GZ_E_NOMEM) return EX_NOMEM;
    if (p.errors || (result && result != GZ_E_SKIP)) return EX_FATAL;
    if (p.warnings || g.warnings) return EX_WARN;
    return EX_OK;
}

static void summary(gz_job *j, int ex, u32 folders, int show_packed, u64 packed)
{
    gz_progress p;
    gz_job_progress(j, &p);
    if (ex == EX_OK) printf("%s\n\n", T(M_ALL_OK));
    if (folders) printf("%s: %u\n", T(M_FOLDERS), folders);
    printf("%s: %u\n", T(M_FILES), p.total_files);
    printf("%s: %llu\n", T(M_SIZE), (unsigned long long)p.total_bytes);
    if (show_packed) printf("%s: %llu\n", T(M_PACKED), (unsigned long long)packed);
    if (p.skipped) printf("%s: %u\n", T(M_SKIPPED), p.skipped);
    if (p.warnings || g.warnings) printf("%s: %u\n", T(M_WARNINGS), p.warnings + (u32)g.warnings);
    if (p.errors) printf("%s: %u\n", T(M_ERRORS), p.errors);
}

static int cmd_extract(opts *o)
{
    gz_handle *h;
    char *ap;
    int r = open_handle(o, &h, &ap);
    if (r) return r;
    gz_archive *a = h->arc;
    u32 cnt;
    u8 *sel = select_names(a, o, &cnt);
    if (o->nnames && !cnt) {
        fprintf(stderr, "%s: %s\n", T(M_WARNING), T(M_NO_MATCH));
        free(sel);
        free(ap);
        gz_handle_close(h);
        return EX_WARN;
    }
    char *dest = abs_path(o->outdir ? o->outdir : ".");
    gzch *wd = wide(dest), *pw = o->password ? wide(o->password) : 0, *ws = o->strip ? wide(o->strip) : 0;
    gz_extract_opts xo;
    memset(&xo, 0, sizeof xo);
    xo.dest = wd;
    xo.test = o->cmd == 't';
    xo.path_mode = o->cmd == 'e' ? GZ_PATH_NONE : ws ? GZ_PATH_STRIP : GZ_PATH_FULL;
    xo.strip = ws;
    xo.overwrite = o->ow >= 0 ? o->ow : GZ_OW_ASK;
    xo.smart = o->smart;
    xo.sel = sel;
    xo.threads = o->threads;
    xo.flags = o->xflags;
    xo.password = pw;
    printf("%s: %s\n", xo.test ? T(M_TESTING) : T(M_EXTRACTING), ap);
    printf("Type = %s\n", gz_arc_type_name(a));
    fflush(stdout);
    gz_job *j = gz_extract_start(h, &xo, &g_cb);
    if (!j) {
        fprintf(stderr, "%s\n", code_text(GZ_E_NOMEM));
        gz_handle_close(h);
        return EX_NOMEM;
    }
    int res = wait_job(j);
    int ex = job_exit(j, res);
    if (!xo.test) {
        char *d = utf8s(gz_job_dest(j));
        printf("%s: %s\n", T(M_DEST), d ? d : dest);
        gz_free(d);
    }
    printf("\n");
    u32 folders = 0;
    for (u32 i = 0; i < a->n; i++) folders += (!sel || sel[i]) && a->e[i].is_dir && a->e[i].name[0];
    if (ex == EX_BREAK) fprintf(stderr, "%s\n", T(M_BREAK));
    summary(j, ex, folders, 0, 0);
    gz_job_free(j);
    gz_free(wd);
    gz_free(pw);
    gz_free(ws);
    free(dest);
    free(sel);
    free(ap);
    gz_handle_close(h);
    return ex;
}

static int format_by_name(const char *s)
{
    static const struct { const char *n; int f; } t[] = {
        { "zip", GZ_WF_ZIP }, { "7z", GZ_WF_7Z }, { "tar", GZ_WF_TAR }, { "tgz", GZ_WF_TGZ },
        { "tar.gz", GZ_WF_TGZ }, { "tbz2", GZ_WF_TBZ2 }, { "tar.bz2", GZ_WF_TBZ2 }, { "txz", GZ_WF_TXZ },
        { "tar.xz", GZ_WF_TXZ }, { "tzst", GZ_WF_TZST }, { "tar.zst", GZ_WF_TZST }, { "gz", GZ_WF_GZ },
        { "gzip", GZ_WF_GZ }, { "bz2", GZ_WF_BZ2 }, { "bzip2", GZ_WF_BZ2 }, { "xz", GZ_WF_XZ },
        { "zst", GZ_WF_ZST }, { "zstd", GZ_WF_ZST }, { "iso", GZ_WF_ISO },
    };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) if (!strcasecmp(s, t[i].n)) return t[i].f;
    return 0;
}

static int method_by_name(const char *s)
{
    static const struct { const char *n; int m; } t[] = {
        { "store", GZ_WM_STORE }, { "copy", GZ_WM_STORE }, { "deflate", GZ_WM_DEFLATE },
        { "deflate64", GZ_WM_DEFLATE64 }, { "bzip2", GZ_WM_BZIP2 }, { "lzma", GZ_WM_LZMA },
        { "lzma2", GZ_WM_LZMA2 }, { "ppmd", GZ_WM_PPMD }, { "zstd", GZ_WM_ZSTD },
    };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) if (!strcasecmp(s, t[i].n)) return t[i].m;
    return -1;
}

static int cmd_add(opts *o)
{
    if (!o->archive) return usage_error(M_NEED_ARCHIVE, 0);
    if (!o->nnames) return usage_error(M_NEED_INPUT, 0);
    char *out = abs_path(o->archive);
    gzch *wout = wide(out);
    int fmt = o->fmt ? format_by_name(o->fmt) : gz_format_from_name(wout);
    if (!fmt) { free(out); gz_free(wout); return usage_error(M_BAD_FORMAT, o->fmt ? o->fmt : o->archive); }
    const gz_writer *w = gz_writer_find(fmt);
    if (!w) { free(out); gz_free(wout); return usage_error(M_NO_WRITER, o->fmt ? o->fmt : o->archive); }
    gz_compress_opts co;
    memset(&co, 0, sizeof co);
    co.out = wout;
    co.format = fmt;
    co.level = o->level;
    co.solid = o->solid < 0 ? 1 : o->solid;
    co.threads = o->threads;
    co.flags = o->follow ? GZ_CF_FOLLOW_LINKS : 0;
    co.encrypt_names = o->enc_names;
    if (o->method) {
        int m = method_by_name(o->method);
        if (m < 0 || (m && !(w->methods & (1u << m)))) { free(out); gz_free(wout); return usage_error(M_BAD_VALUE, o->method); }
        co.method = m;
    }
    gzch *pw = 0;
    if (o->password && o->password[0]) {
        if (!w->encryptions) { free(out); gz_free(wout); return usage_error(M_NO_ENC, w->name); }
        int e = (w->encryptions & (1u << GZ_WE_AES256)) ? GZ_WE_AES256 : GZ_WE_ZIPCRYPTO;
        if (o->em) {
            if (!strcasecmp(o->em, "zipcrypto")) e = GZ_WE_ZIPCRYPTO;
            else if (!strcasecmp(o->em, "aes256") || !strcasecmp(o->em, "aes")) e = GZ_WE_AES256;
            else { free(out); gz_free(wout); return usage_error(M_BAD_VALUE, o->em); }
            if (!(w->encryptions & (1u << e))) { free(out); gz_free(wout); return usage_error(M_NO_ENC, o->em); }
        }
        co.encryption = e;
        co.password = pw = wide(o->password);
    }
    struct stat st;
    if (!stat(out, &st)) {
        if (o->ow == GZ_OW_ALL) co.overwrite = GZ_OW_ALL;
        else if (g.interactive && o->ow < 0) {
            fprintf(stderr, "%s\n", out);
            char line[16];
            co.overwrite = (read_line(T(M_REPLACE_ARC), line, sizeof line, 1) > 0 && (line[0] | 32) == 'y')
                         ? GZ_OW_ALL : GZ_OW_SKIP;
        } else {
            co.overwrite = GZ_OW_SKIP;
        }
    }
    gzch **in = (gzch **)calloc((size_t)o->nnames + 1, sizeof(gzch *));
    if (!in) exit(EX_NOMEM);
    for (int i = 0; i < o->nnames; i++) {
        char *p = abs_path(o->names[i]);
        in[i] = wide(p);
        free(p);
    }
    co.inputs = (const gzch *const *)in;
    co.ninputs = (u32)o->nnames;
    printf("%s: %s\n", T(M_CREATING), out);
    printf("Type = %s\n", w->name);
    fflush(stdout);
    gz_job *j = gz_compress_start(&co, &g_cb);
    if (!j) { fprintf(stderr, "%s\n", code_text(GZ_E_NOMEM)); return EX_NOMEM; }
    int res = wait_job(j);
    int ex = job_exit(j, res);
    printf("\n");
    if (ex == EX_BREAK) fprintf(stderr, "%s\n", T(M_BREAK));
    u64 asz = 0;
    if (!res && !stat(out, &st)) asz = (u64)st.st_size;
    summary(j, ex, 0, 0, 0);
    if (!res) printf("%s: %llu\n", T(M_ARC_SIZE), (unsigned long long)asz);
    gz_job_free(j);
    for (int i = 0; i < o->nnames; i++) gz_free(in[i]);
    free(in);
    gz_free(pw);
    gz_free(wout);
    free(out);
    return ex;
}

static int cmd_info(void)
{
    printf("고깃ZIP %s\n\n", GZ_APP_VERSION);
    printf("%s:\n", g_ko ? "읽기 형식" : "Formats (read)");
    for (int i = 0; gz_formats[i]; i++)
        printf("  %-12s %s\n", gz_formats[i]->name, gz_formats[i]->exts ? gz_formats[i]->exts : "");
    printf("\n%s:\n", g_ko ? "만들기 형식" : "Formats (create)");
    static const char *const mn[GZ_WM_COUNT] = { "default", "store", "deflate", "deflate64", "bzip2", "lzma",
                                                 "lzma2", "ppmd", "zstd" };
    for (int i = 0; gz_writers[i]; i++) {
        const gz_writer *w = gz_writers[i];
        printf("  %-12s .%-8s", w->name, w->ext);
        for (int m = 1; m < GZ_WM_COUNT; m++) if (w->methods & (1u << m)) printf(" %s", mn[m]);
        if (w->encryptions & (1u << GZ_WE_ZIPCRYPTO)) printf(" +ZipCrypto");
        if (w->encryptions & (1u << GZ_WE_AES256)) printf(" +AES-256");
        printf("\n");
    }
    printf("\nCPU: %s (%s)\n", g_cpu.brand, g_cpu.vendor);
    printf("%s: %s / %s: %s\n", g_ko ? "단계" : "Tier", gz_tier_name(g_cpu.active), g_ko ? "최고" : "best",
           gz_tier_name(g_cpu.tier));
    printf("Inflate: %s\nCRC-32: %s\nAES: %s\n", gz_dispatch_inflate_name(), gz_dispatch_crc_name(),
           gz_dispatch_aes_name());
    printf("%s: %d\n", g_ko ? "스레드" : "Threads", gz_os_cpu_count());
    return EX_OK;
}

int main(int argc, char **argv)
{
    pick_language();
    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
        fputs(T(M_HELP), argc < 2 ? stderr : stdout);
        return argc < 2 ? EX_USAGE : EX_OK;
    }
    const char *c = argv[1];
    if (strlen(c) != 1 || !strchr("lxeati", c[0])) {
        fprintf(stderr, "%s: %s: %s\n", T(M_ERROR), T(M_UNKNOWN_CMD), c);
        return EX_USAGE;
    }
    opts o;
    int r = parse(argc, argv, &o);
    if (r) { free(o.names); return r; }
    o.cmd = c[0];
    gz_engine_init(o.cpu);
    install_signals();
    g.tty = gz_os_mutex_new();
    if (!g.tty) return EX_NOMEM;
    g.interactive = isatty(0) && isatty(2);
    g.progress = isatty(2) && !o.bd;
    switch (o.cmd) {
    case 'l': r = cmd_list(&o); break;
    case 'x': case 'e': case 't': r = cmd_extract(&o); break;
    case 'a': r = cmd_add(&o); break;
    default: r = cmd_info(); break;
    }
    free(o.names);
    fflush(stdout);
    gz_os_mutex_free(g.tty);
    return r;
}
