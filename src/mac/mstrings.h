/*
 * 고깃ZIP macOS - strings only the Cocoa front end needs (menus AppKit expects,
 * Finder integration, the app's command line help). Everything else comes from
 * the shared table in src/app/strings.h (gz_ui_str), so both front ends say the
 * same things. Plain C: tests/cases/app_mac.py compiles it to check that both
 * languages are complete.
 *
 * The shared header is included by its relative path, never through an -I
 * directory: src/app/strings.h shares its name with the C library's <strings.h>
 * and only chains to it when it is found on the include path (GTK build).
 */
#ifndef GZ_MAC_MSTRINGS_H
#define GZ_MAC_MSTRINGS_H
#ifndef GZ_UI_STRINGS_IMPL
#  define GZ_UI_STRINGS_IMPL 1      /* included by path: no <strings.h> chaining */
#endif
#include "../app/strings.h"

#define GZ_MAC_STRINGS(X) \
X(MS_ABOUT,          "고깃ZIP 정보", "About GogitZIP") \
X(MS_PREFS,          "설정…", "Settings…") \
X(MS_SERVICES,       "서비스", "Services") \
X(MS_HIDE,           "고깃ZIP 가리기", "Hide GogitZIP") \
X(MS_HIDE_OTHERS,    "기타 가리기", "Hide Others") \
X(MS_SHOW_ALL,       "모두 보기", "Show All") \
X(MS_QUIT,           "고깃ZIP 종료", "Quit GogitZIP") \
X(MS_FILE,           "파일", "File") \
X(MS_EDIT,           "편집", "Edit") \
X(MS_UNDO,           "실행 취소", "Undo") \
X(MS_REDO,           "실행 복귀", "Redo") \
X(MS_CUT,            "오려두기", "Cut") \
X(MS_COPY,           "복사하기", "Copy") \
X(MS_PASTE,          "붙여넣기", "Paste") \
X(MS_SELECT_ALL,     "전체 선택", "Select All") \
X(MS_ACTIONS,        "작업", "Actions") \
X(MS_VIEW,           "보기", "View") \
X(MS_WINDOW,         "윈도우", "Window") \
X(MS_HELP,           "도움말", "Help") \
X(MS_MINIMIZE,       "최소화", "Minimize") \
X(MS_ZOOM,           "확대/축소", "Zoom") \
X(MS_FRONT,          "모두 앞으로 가져오기", "Bring All to Front") \
X(MS_TOOLBAR_SHOW,   "도구 막대 보기", "Show Toolbar") \
X(MS_TOOLBAR_CUSTOM, "도구 막대 사용자화…", "Customize Toolbar…") \
X(MS_FULLSCREEN,     "전체 화면 시작", "Enter Full Screen") \
X(MS_CLEAR_RECENT,   "메뉴 지우기", "Clear Menu") \
X(MS_CLOSE_WINDOW,   "윈도우 닫기", "Close Window") \
X(MS_CLOSE_ARCHIVE,  "압축 파일 닫기", "Close Archive") \
X(MS_SHOW_IN_FINDER, "Finder에서 보기", "Show in Finder") \
X(MS_ASSOC_DESC,     "압축 파일을 두 번 클릭하면 고깃ZIP으로 열리게 합니다.", "Open archives with GogitZIP when they are double-clicked in Finder.") \
X(MS_ASSOC_FAIL,     "일부 형식의 기본 앱을 바꾸지 못했습니다.", "Some archive types could not be changed.") \
X(MS_SERVICES_NOTE,  "Finder에서 파일을 선택한 뒤 오른쪽 클릭 > 빠른 동작 또는 서비스 메뉴에서 고깃ZIP 항목을 사용할 수 있습니다.", "In Finder, select files and use the GogitZIP items in the context menu (Quick Actions / Services).") \
X(MS_DEST_CHOOSE,    "선택…", "Choose…") \
X(MS_DRAG_FAIL,      "끌어 놓은 항목을 풀지 못했습니다.", "The dragged items could not be extracted.") \
X(MS_USAGE,          "사용법: GogitZIP [압축 파일]\n" \
                     "       GogitZIP --extract-here 압축 파일...\n" \
                     "       GogitZIP --extract-smart 압축 파일...\n" \
                     "       GogitZIP --extract-to 폴더 압축 파일...\n" \
                     "       GogitZIP --extract 압축 파일...          (풀기 창에서 묻기)\n" \
                     "       GogitZIP --test 압축 파일...\n" \
                     "       GogitZIP --compress 파일/폴더... [--output 압축 파일] [--format 형식] [--level 0-9] [--yes]\n" \
                     "옵션:  --yes  질문 없이 진행 (덮어쓰기, 결과 창 없음, 오류는 표준 오류로)\n" \
                     "       --lang ko|en\n" \
                     "종료 코드: 0 정상, 1 경고, 2 오류, 7 사용법 오류, 255 취소\n", \
                     "Usage: GogitZIP [archive]\n" \
                     "       GogitZIP --extract-here ARCHIVE...\n" \
                     "       GogitZIP --extract-smart ARCHIVE...\n" \
                     "       GogitZIP --extract-to DIR ARCHIVE...\n" \
                     "       GogitZIP --extract ARCHIVE...           (ask with the extract window)\n" \
                     "       GogitZIP --test ARCHIVE...\n" \
                     "       GogitZIP --compress FILE/FOLDER... [--output ARCHIVE] [--format FMT] [--level 0-9] [--yes]\n" \
                     "Options: --yes  never ask (overwrite, no result windows, problems on stderr)\n" \
                     "         --lang ko|en\n" \
                     "Exit codes: 0 ok, 1 warnings, 2 errors, 7 usage, 255 canceled\n")

#define GZ_MS_ENUM(id, ko, en) id,
enum { GZ_MAC_STRINGS(GZ_MS_ENUM) MS__COUNT };
#undef GZ_MS_ENUM

/* the text of a mac string in the current UI language (gz_ui_set_korean) */
static inline const char *gz_ms(int id)
{
#define GZ_MS_KO(id, ko, en) ko,
#define GZ_MS_EN(id, ko, en) en,
    static const char *const ko[MS__COUNT] = { GZ_MAC_STRINGS(GZ_MS_KO) };
    static const char *const en[MS__COUNT] = { GZ_MAC_STRINGS(GZ_MS_EN) };
#undef GZ_MS_KO
#undef GZ_MS_EN
    if (id < 0 || id >= MS__COUNT) return "";
    return gz_ui_korean() ? ko[id] : en[id];
}

#endif
