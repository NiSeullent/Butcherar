/*
 * 고깃ZIP - user interface strings shared by the Linux (GTK) and macOS front ends
 *
 * UTF-8, Korean and English, keyed by an enum. Templates use only "%s"
 * placeholders, filled in order by gz_ui_format() (no printf: translations can
 * never break a format string, and the module needs no C library).
 * Menu texts carry GTK-style mnemonics ("_F"); gz_ui_plain() strips them.
 *
 *     gz_ui_set_korean(gz_ui_locale_korean(getenv("LANG")));
 *     char b[256];
 *     GZ_UI_FMT(b, sizeof b, STR_ST_SELECTED, "3", "1.5 MB");   -> "3개 선택 (1.5 MB)"
 *
 * The file name matches the C library's <strings.h>: with -Isrc/app on the
 * command line, "#include <strings.h>" (glibc's <string.h> does that) lands
 * here, so the system header is chained first and this header only adds
 * self-contained declarations (stdint types, no project headers).
 */
#if defined(__has_include_next) && !defined(GZ_UI_STRINGS_IMPL)
#  if __has_include_next(<strings.h>)
#    include_next <strings.h>
#  endif
#endif
#ifndef GZ_UI_STRINGS_H
#define GZ_UI_STRINGS_H
#include <stdint.h>

#define GZ_UI_STRINGS(X) \
X(STR_APP,            "고깃ZIP", "GogitZIP") \
X(STR_TAGLINE,        "가볍고 빠른 압축 프로그램", "Lightweight, fast archive manager") \
X(STR_COMMENT,        "압축 파일을 열고, 풀고, 새로 만듭니다", "Open, extract and create archives") \
/* toolbar */ \
X(STR_TB_OPEN,        "열기", "Open") \
X(STR_TB_EXTRACT,     "풀기", "Extract") \
X(STR_TB_NEW,         "새로 압축", "New archive") \
X(STR_TB_TEST,        "테스트", "Test") \
X(STR_TB_INFO,        "정보", "Info") \
X(STR_TB_CODEPAGE,    "코드 페이지", "Code page") \
X(STR_TB_SETTINGS,    "설정", "Settings") \
X(STR_TT_OPEN,        "압축 파일 열기 (Ctrl+O)", "Open an archive (Ctrl+O)") \
X(STR_TT_EXTRACT,     "압축 풀기 (Ctrl+E)", "Extract files (Ctrl+E)") \
X(STR_TT_NEW,         "파일과 폴더로 새 압축 파일 만들기 (Ctrl+N)", "Create an archive from files and folders (Ctrl+N)") \
X(STR_TT_TEST,        "압축 파일이 손상되지 않았는지 검사 (Ctrl+T)", "Check the archive for errors (Ctrl+T)") \
X(STR_TT_INFO,        "압축 파일 정보 (Alt+Enter)", "Archive properties (Alt+Enter)") \
X(STR_TT_CODEPAGE,    "파일 이름이 깨질 때 인코딩 바꾸기", "Change the encoding of garbled file names") \
X(STR_TT_SETTINGS,    "설정", "Preferences") \
X(STR_TT_UP,          "상위 폴더 (Backspace)", "Up one level (Backspace)") \
/* menus */ \
X(STR_M_FILE,         "파일(_F)", "_File") \
X(STR_M_OPEN,         "압축 파일 열기(_O)...", "_Open archive...") \
X(STR_M_NEW,          "새로 압축(_N)...", "_New archive...") \
X(STR_M_RECENT,       "최근 파일(_R)", "_Recent files") \
X(STR_M_NORECENT,     "(없음)", "(none)") \
X(STR_M_CLOSE,        "닫기(_C)", "_Close") \
X(STR_M_BACK,         "상위 압축 파일로 돌아가기(_B)", "_Back to the outer archive") \
X(STR_M_INFO,         "압축 파일 정보(_I)", "Archive _info") \
X(STR_M_QUIT,         "끝내기(_X)", "_Quit") \
X(STR_M_ACTION,       "작업(_A)", "_Actions") \
X(STR_M_EXTRACT,      "압축 풀기(_E)...", "_Extract...") \
X(STR_M_EXTRACT_HERE, "여기에 풀기(_H)", "Extract _here") \
X(STR_M_EXTRACT_SMART,"폴더를 만들어 바로 풀기(_Q)", "_Quick extract to a folder") \
X(STR_M_EXTRACT_SEL,  "선택한 항목 풀기(_S)...", "Extract _selected...") \
X(STR_M_TEST,         "압축 파일 테스트(_T)", "_Test archive") \
X(STR_M_VIEW,         "보기(_V)", "_View") \
X(STR_M_OPENITEM,     "열기(_O)", "_Open") \
X(STR_M_UP,           "상위 폴더(_U)", "_Up one level") \
X(STR_M_TREE,         "폴더 트리 보기(_F)", "_Folder tree") \
X(STR_M_SELECTALL,    "모두 선택(_A)", "Select _all") \
X(STR_M_CODEPAGE,     "코드 페이지(_C)", "_Code page") \
X(STR_M_OPTIONS,      "옵션(_O)", "_Options") \
X(STR_M_SETTINGS,     "설정(_S)...", "_Settings...") \
X(STR_M_HELP,         "도움말(_H)", "_Help") \
X(STR_M_HOMEPAGE,     "공식 홈페이지(_W)", "Official _website") \
X(STR_M_ABOUT,        "고깃ZIP 정보(_A)...", "_About GogitZIP...") \
/* code pages */ \
X(STR_CP_AUTO,        "자동 감지", "Auto detect") \
X(STR_CP_UTF8,        "유니코드 (UTF-8)", "Unicode (UTF-8)") \
X(STR_CP_949,         "한국어 (CP949)", "Korean (CP949)") \
X(STR_CP_932,         "일본어 (Shift-JIS)", "Japanese (Shift-JIS)") \
X(STR_CP_936,         "중국어 간체 (GBK)", "Chinese Simplified (GBK)") \
X(STR_CP_950,         "중국어 번체 (Big5)", "Chinese Traditional (Big5)") \
X(STR_CP_1252,        "서유럽 (Windows-1252)", "Western (Windows-1252)") \
X(STR_CP_1250,        "중유럽 (Windows-1250)", "Central European (Windows-1250)") \
X(STR_CP_1251,        "키릴 (Windows-1251)", "Cyrillic (Windows-1251)") \
X(STR_CP_437,         "영어 DOS (CP437)", "English DOS (CP437)") \
X(STR_CP_850,         "서유럽 DOS (CP850)", "Western DOS (CP850)") \
X(STR_CP_866,         "러시아어 DOS (CP866)", "Russian DOS (CP866)") \
/* file list */ \
X(STR_COL_NAME,       "이름", "Name") \
X(STR_COL_SIZE,       "원본 크기", "Size") \
X(STR_COL_PACKED,     "압축 크기", "Packed") \
X(STR_COL_TYPE,       "종류", "Type") \
X(STR_COL_MTIME,      "수정한 날짜", "Modified") \
X(STR_COL_RATIO,      "압축률", "Ratio") \
X(STR_COL_METHOD,     "방식", "Method") \
X(STR_COL_CRC,        "CRC32", "CRC32") \
X(STR_PARENT,         "상위 폴더", "Parent folder") \
X(STR_FOLDER,         "파일 폴더", "File folder") \
X(STR_FILE,           "파일", "File") \
X(STR_LINK,           "바로 가기 (링크)", "Link") \
/* status bar */ \
X(STR_ST_SUMMARY,     "파일 %s개, 폴더 %s개  ·  원본 %s  ·  압축 %s (%s)", "%s files, %s folders  ·  %s  ·  packed %s (%s)") \
X(STR_ST_SELECTED,    "%s개 선택 (%s)", "%s selected (%s)") \
X(STR_ST_ENGINE,      "%s 엔진  ·  %s스레드", "%s engine  ·  %s threads") \
X(STR_ST_READY,       "준비", "Ready") \
X(STR_ST_OPENING,     "여는 중: %s", "Opening %s") \
/* welcome screen */ \
X(STR_W_DROP,         "압축 파일을 이곳에 끌어다 놓으세요", "Drop an archive here") \
X(STR_W_DROP2,        "다른 파일이나 폴더를 놓으면 새로 압축합니다", "Drop other files or folders to compress them") \
X(STR_W_MORE,         "외 %s개 형식", "and %s more formats") \
X(STR_W_OPEN,         "압축 파일 열기", "Open archive") \
X(STR_W_NEW,          "새로 압축...", "New archive...") \
X(STR_W_RECENT,       "최근 사용한 파일", "Recent files") \
X(STR_W_ENGINE,       "가속 엔진", "Engine") \
X(STR_THREADS,        "%s 스레드", "%s threads") \
/* common buttons */ \
X(STR_OK,             "확인", "OK") \
X(STR_CANCEL,         "취소", "Cancel") \
X(STR_CLOSE,          "닫기", "Close") \
X(STR_BROWSE,         "찾아보기...", "Browse...") \
X(STR_YES,            "예", "Yes") \
X(STR_NO,             "아니요", "No") \
X(STR_SELECT,         "선택", "Select") \
X(STR_SAVE,           "저장", "Save") \
/* extract dialog */ \
X(STR_X_TITLE,        "압축 풀기", "Extract") \
X(STR_X_DEST,         "압축을 풀 위치", "Destination folder") \
X(STR_X_HERE,         "압축 파일 위치", "Archive folder") \
X(STR_X_DESKTOP,      "바탕 화면", "Desktop") \
X(STR_X_DOCS,         "문서", "Documents") \
X(STR_X_DOWNLOADS,    "다운로드", "Downloads") \
X(STR_X_MAKEFOLDER,   "압축 파일 이름으로 폴더 만들기 (최상위 폴더가 하나뿐이면 생략)", "Create a folder named after the archive (skip if it has one top folder)") \
X(STR_X_PATHS,        "경로", "Paths") \
X(STR_X_PATH_FULL,    "전체 경로", "Full paths") \
X(STR_X_PATH_NONE,    "경로 없이 (파일만)", "No paths (files only)") \
X(STR_X_OVERWRITE,    "같은 이름의 파일이 있으면", "If a file already exists") \
X(STR_OW_ASK,         "매번 물어보기", "Ask me") \
X(STR_OW_ALL,         "항상 덮어쓰기", "Overwrite") \
X(STR_OW_SKIP,        "건너뛰기", "Skip") \
X(STR_OW_RENAME,      "자동으로 이름 바꾸기", "Rename automatically") \
X(STR_OW_NEWER,       "더 새로운 파일만 덮어쓰기", "Overwrite older files") \
X(STR_X_OPENFOLDER,   "압축을 푼 다음 폴더 열기", "Open the folder when done") \
X(STR_X_SELECTED,     "선택한 항목만 풀기 (%s개)", "Extract selected items only (%s)") \
X(STR_X_START,        "압축 풀기", "Extract") \
X(STR_X_SUMMARY,      "파일 %s개  ·  %s", "%s files  ·  %s") \
X(STR_X_PICK,         "압축을 풀 폴더를 선택하세요", "Choose the destination folder") \
/* progress */ \
X(STR_P_EXTRACTING,   "압축 푸는 중", "Extracting") \
X(STR_P_TESTING,      "테스트 중", "Testing") \
X(STR_P_COMPRESSING,  "압축하는 중", "Compressing") \
X(STR_P_OPENING,      "압축 파일을 여는 중...", "Opening archive...") \
X(STR_P_PAUSE,        "일시 정지", "Pause") \
X(STR_P_RESUME,       "계속", "Resume") \
X(STR_P_ELAPSED,      "경과 시간", "Elapsed") \
X(STR_P_REMAIN,       "남은 시간", "Remaining") \
X(STR_P_SPEED,        "속도", "Speed") \
X(STR_P_FILES,        "파일", "Files") \
X(STR_P_PAUSED,       "일시 정지됨", "Paused") \
X(STR_P_CANCELING,    "취소하는 중...", "Canceling...") \
X(STR_P_PREPARING,    "준비하는 중...", "Preparing...") \
X(STR_P_ENGINE,       "%s  ·  CRC %s  ·  %s스레드", "%s  ·  CRC %s  ·  %s threads") \
/* password */ \
X(STR_PW_TITLE,       "비밀번호 입력", "Password required") \
X(STR_PW_PROMPT,      "암호로 보호된 파일입니다. 비밀번호를 입력하세요.", "This file is encrypted. Please enter the password.") \
X(STR_PW_WRONG,       "비밀번호가 올바르지 않습니다. 다시 입력하세요.", "Wrong password. Please try again.") \
X(STR_PW_SHOW,        "비밀번호 표시", "Show password") \
/* overwrite question */ \
X(STR_OWQ_TITLE,      "파일 덮어쓰기 확인", "Confirm file replace") \
X(STR_OWQ_PROMPT,     "대상 폴더에 같은 이름의 파일이 이미 있습니다.", "The destination already contains a file with this name.") \
X(STR_OWQ_ARC_PROMPT, "같은 이름의 압축 파일이 이미 있습니다. 바꿀까요?", "An archive with this name already exists. Replace it?") \
X(STR_OWQ_EXISTING,   "기존 파일", "Existing file") \
X(STR_OWQ_NEW,        "압축 파일 안의 파일", "File in archive") \
X(STR_OWQ_APPLYALL,   "남은 파일에도 모두 적용", "Apply to all remaining files") \
X(STR_OWQ_OVERWRITE,  "덮어쓰기", "Replace") \
X(STR_OWQ_SKIP,       "건너뛰기", "Skip") \
X(STR_OWQ_RENAME,     "이름 바꾸기", "Rename") \
X(STR_OWQ_INFO,       "%s  ·  %s", "%s  ·  %s") \
/* missing volume */ \
X(STR_VOL_TITLE,      "다음 볼륨 찾기", "Locate the next volume") \
X(STR_VOL_PROMPT,     "분할 압축 파일의 다음 볼륨을 찾을 수 없습니다. 볼륨 파일을 선택하세요.", "The next volume of the split archive was not found. Please locate it.") \
/* results */ \
X(STR_R_TITLE,        "작업 결과", "Result") \
X(STR_R_TEST_OK,      "테스트를 마쳤습니다. 모든 파일에 이상이 없습니다.", "Test finished. No errors were found.") \
X(STR_R_EXTRACT_OK,   "압축을 모두 풀었습니다.", "Extraction finished.") \
X(STR_R_COMPRESS_OK,  "압축 파일을 만들었습니다.", "The archive was created.") \
X(STR_R_ERRORS,       "작업을 마쳤지만 %s개 항목에 문제가 있습니다.", "Finished, but %s item(s) had problems.") \
X(STR_R_WARNINGS,     "작업을 마쳤습니다. 경고 %s개가 있습니다.", "Finished with %s warning(s).") \
X(STR_R_FAILED,       "작업을 마치지 못했습니다.", "The operation failed.") \
X(STR_R_CANCELED,     "작업이 취소되었습니다.", "The operation was canceled.") \
X(STR_R_STATS,        "파일 %s개  ·  %s  ·  %s  ·  평균 %s", "%s files  ·  %s  ·  %s  ·  avg %s") \
X(STR_R_OPEN_FOLDER,  "폴더 열기", "Open folder") \
X(STR_L_ERROR,        "오류", "Error") \
X(STR_L_WARN,         "경고", "Warning") \
X(STR_L_NOTE,         "참고", "Note") \
X(STR_L_ITEM,         "항목", "Item") \
X(STR_L_PROBLEM,      "내용", "Problem") \
/* errors (GZ_E_*) */ \
X(STR_E_OK,           "정상", "OK") \
X(STR_E_IO,           "읽기/쓰기 오류", "Read/write error") \
X(STR_E_FORMAT,       "지원하지 않거나 손상된 압축 파일입니다", "Unsupported or damaged archive") \
X(STR_E_DATA,         "압축 데이터가 손상되었습니다", "Compressed data is corrupt") \
X(STR_E_CRC,          "CRC 오류 (파일이 손상됨)", "CRC error (file is damaged)") \
X(STR_E_METHOD,       "지원하지 않는 압축 방식입니다", "Unsupported compression method") \
X(STR_E_PASSWORD,     "비밀번호가 틀렸거나 파일이 손상되었습니다", "Wrong password or damaged file") \
X(STR_E_NOMEM,        "메모리가 부족합니다", "Out of memory") \
X(STR_E_CANCEL,       "취소됨", "Canceled") \
X(STR_E_TRUNC,        "압축 파일이 잘렸습니다 (다운로드가 덜 되었을 수 있음)", "The archive is truncated") \
X(STR_E_SKIP,         "건너뜀", "Skipped") \
X(STR_E_CREATE,       "파일을 만들 수 없습니다", "Cannot create the file") \
X(STR_E_AUTH,         "인증 실패 (비밀번호가 틀렸거나 변조됨)", "Authentication failed (wrong password or tampered data)") \
X(STR_E_DISK,         "디스크 공간이 부족합니다", "The disk is full") \
X(STR_E_VOLUME,       "분할 압축 파일의 다음 볼륨이 없습니다", "A volume of the split archive is missing") \
X(STR_E_LIMIT,        "안전 한도를 넘었습니다", "Exceeds a safety limit") \
/* engine notes (GZ_N_*) */ \
X(STR_N_RENAMED,      "다른 이름으로 저장했습니다", "Saved under another name") \
X(STR_N_SHORTENED,    "이름이 너무 길어 줄였습니다", "Name too long for the file system, shortened") \
X(STR_N_PATH_LONG,    "경로가 너무 깁니다", "Path too long") \
X(STR_N_LINK_ABS,     "절대 경로를 가리키는 링크는 만들지 않았습니다", "Link to an absolute path not created") \
X(STR_N_LINK_ESCAPE,  "대상 폴더 밖을 가리키는 링크는 만들지 않았습니다", "Link pointing outside the destination not created") \
X(STR_N_LINK_THROUGH, "링크된 폴더 안의 링크는 만들지 않았습니다", "Link inside a linked folder not created") \
X(STR_N_LINK_SKIP,    "링크를 건너뛰었습니다", "Link skipped") \
X(STR_N_LINK_FAILED,  "링크를 만들 수 없습니다", "Cannot create the link") \
X(STR_N_LINK_TARGET,  "하드 링크 대상이 없습니다", "Hard link target missing") \
X(STR_N_SPECIAL,      "특수 파일을 건너뛰었습니다", "Special file skipped") \
X(STR_N_LOOP,         "폴더 순환을 건너뛰었습니다", "Folder loop skipped") \
X(STR_N_NOT_FOUND,    "찾을 수 없습니다", "Not found") \
X(STR_N_UNREADABLE,   "읽을 수 없습니다", "Cannot read") \
X(STR_N_ONE_FILE,     "이 형식에는 파일 하나만 넣을 수 있습니다", "This format holds exactly one file") \
X(STR_N_EXISTS,       "압축 파일이 이미 있습니다", "The archive already exists") \
X(STR_N_NO_WRITER,    "이 형식으로는 압축할 수 없습니다", "Creating this format is not supported") \
X(STR_N_NO_FILES,     "압축할 파일이 없습니다", "Nothing to compress") \
X(STR_OPEN_FAIL,      "압축 파일을 열 수 없습니다.", "Cannot open the archive.") \
X(STR_FILTER_ARC,     "압축 파일", "Archives") \
X(STR_FILTER_ALL,     "모든 파일", "All files") \
/* create dialog */ \
X(STR_C_TITLE,        "새로 압축", "New archive") \
X(STR_C_SOURCE_ONE,   "%s", "%s") \
X(STR_C_SOURCE_MANY,  "%s 외 %s개", "%s and %s more") \
X(STR_C_OUT,          "압축 파일 이름", "Archive name") \
X(STR_C_FORMAT,       "형식", "Format") \
X(STR_C_LEVEL,        "압축 수준", "Level") \
X(STR_C_METHOD,       "압축 방식", "Method") \
X(STR_C_DEFAULT,      "기본값", "Default") \
X(STR_LV_0,           "저장 (압축 안 함)", "Store (no compression)") \
X(STR_LV_1,           "가장 빠르게", "Fastest") \
X(STR_LV_3,           "빠르게", "Fast") \
X(STR_LV_5,           "보통", "Normal") \
X(STR_LV_7,           "최대", "Maximum") \
X(STR_LV_9,           "최고", "Ultra") \
X(STR_C_OPTIONS,      "옵션", "Options") \
X(STR_C_SOLID,        "솔리드 압축 (더 작게, 일부만 풀 때는 느림)", "Solid archive (smaller, slower to extract single files)") \
X(STR_C_ENCRYPTION,   "암호 설정", "Encryption") \
X(STR_C_PASSWORD,     "암호", "Password") \
X(STR_C_PASSWORD2,    "암호 확인", "Confirm password") \
X(STR_C_ENC_METHOD,   "암호화 방식", "Encryption method") \
X(STR_C_ENC_NAMES,    "파일 이름도 암호화", "Encrypt file names") \
X(STR_C_NO_ENC,       "이 형식은 암호를 지원하지 않습니다", "This format does not support encryption") \
X(STR_C_PW_MISMATCH,  "암호가 서로 다릅니다", "The passwords do not match") \
X(STR_C_START,        "압축", "Compress") \
X(STR_C_SAVE_AS,      "압축 파일 저장 위치", "Save the archive as") \
X(STR_C_NO_WRITERS,   "만들 수 있는 압축 형식이 없습니다", "No archive format can be created") \
X(STR_C_NEED_NAME,    "압축 파일 이름을 입력하세요", "Please enter an archive name") \
X(STR_C_PICK_FILES,   "압축할 파일 선택", "Choose files to compress") \
/* info dialog */ \
X(STR_I_TITLE,        "압축 파일 정보", "Archive information") \
X(STR_I_PATH,         "위치", "Location") \
X(STR_I_FORMAT,       "형식", "Format") \
X(STR_I_FILESIZE,     "파일 크기", "File size") \
X(STR_I_CONTENTS,     "내용", "Contents") \
X(STR_I_CONTENTS_FMT, "파일 %s개, 폴더 %s개", "%s files, %s folders") \
X(STR_I_USIZE,        "원본 크기", "Original size") \
X(STR_I_RATIO,        "압축률", "Compression") \
X(STR_I_METHOD,       "압축 방식", "Method") \
X(STR_I_ENC,          "암호화", "Encryption") \
X(STR_I_YES,          "있음", "Yes") \
X(STR_I_NO,           "없음", "No") \
X(STR_I_HDR_ENC,      "있음 (파일 이름 포함)", "Yes (including file names)") \
X(STR_I_SOLID,        "솔리드", "Solid") \
X(STR_I_CP,           "파일 이름 인코딩", "Name encoding") \
X(STR_I_COMMENT,      "주석", "Comment") \
X(STR_I_SFX,          "자동 압축 풀림(SFX) 데이터 %s 포함", "Includes %s of self-extractor data") \
X(STR_I_VOLUMES,      "볼륨", "Volumes") \
/* settings */ \
X(STR_S_TITLE,        "설정", "Settings") \
X(STR_S_GENERAL,      "일반", "General") \
X(STR_S_LANG,         "언어 (Language)", "Language") \
X(STR_S_LANG_AUTO,    "자동 (시스템 언어)", "Automatic (system language)") \
X(STR_S_LANG_KO,      "한국어", "Korean (한국어)") \
X(STR_S_LANG_EN,      "English", "English") \
X(STR_S_CODEPAGE,     "옛 파일 이름의 기본 코드 페이지", "Default code page for legacy names") \
X(STR_S_THREADS,      "동시에 사용할 스레드", "Worker threads") \
X(STR_S_AUTO_N,       "자동 (%s개)", "Automatic (%s)") \
X(STR_S_EXTRACT,      "압축 풀기", "Extraction") \
X(STR_S_DEST,         "기본 풀기 위치", "Default destination") \
X(STR_S_DEST_ARC,     "압축 파일이 있는 폴더", "The archive's folder") \
X(STR_S_DEST_CUSTOM,  "지정한 폴더", "This folder") \
X(STR_S_SMART,        "압축 파일 이름으로 폴더 만들기", "Create a folder named after the archive") \
X(STR_S_OVERWRITE,    "덮어쓰기 기본값", "Default overwrite mode") \
X(STR_S_ASSOC,        "파일 연결", "File associations") \
X(STR_S_ASSOC_DESC,   "압축 파일을 두 번 클릭하면 고깃ZIP으로 열리게 합니다 (현재 사용자만).", "Open archives with GogitZIP when they are double-clicked (current user only).") \
X(STR_S_ASSOC_BTN,    "고깃ZIP을 기본 프로그램으로 설정", "Make GogitZIP the default") \
X(STR_S_ASSOC_DONE,   "압축 형식 %s개를 고깃ZIP에 연결했습니다.", "%s archive types now open with GogitZIP.") \
X(STR_S_ASSOC_FAIL,   "파일 연결을 바꾸지 못했습니다. gogitzip.desktop이 설치되어 있는지 확인하세요 (make install).", "Could not change the associations. Make sure gogitzip.desktop is installed (make install).") \
X(STR_S_RESTART,      "언어 설정은 프로그램을 다시 시작하면 적용됩니다.", "Restart GogitZIP to apply the language.") \
/* about */ \
X(STR_A_TITLE,        "고깃ZIP 정보", "About GogitZIP") \
X(STR_A_VERSION,      "버전 %s", "Version %s") \
X(STR_A_CPU,          "프로세서", "Processor") \
X(STR_A_ENGINE,       "가속 엔진", "Acceleration") \
X(STR_A_FORMATS,      "읽기 %s개 형식  ·  만들기 %s개 형식", "Reads %s formats  ·  creates %s formats") \
X(STR_A_COPY,         "© 2026 Butcherar 프로젝트 · MIT 라이선스로 배포되는 자유 소프트웨어", "© 2026 Butcherar project · free software under the MIT license") \
X(STR_A_HOME,         "공식 홈페이지 방문", "Visit the website") \
/* misc */ \
X(STR_NO_ARCHIVE,     "압축 파일이 열려 있지 않습니다.", "No archive is open.") \
X(STR_DND_PREPARE,    "끌어 놓을 파일을 준비하는 중", "Preparing the dragged files") \
X(STR_OPEN_FILE_FAIL, "파일을 열 프로그램을 찾지 못했습니다.", "No application was found to open the file.") \
X(STR_NOTHING,        "처리할 파일이 없습니다", "No files to process") \
X(STR_USAGE,          "사용법: gogitzip-gtk [압축 파일]\n" \
                      "        gogitzip-gtk --extract-here 압축 파일...\n" \
                      "        gogitzip-gtk --extract-smart 압축 파일...\n" \
                      "        gogitzip-gtk --extract-to 폴더 압축 파일...\n" \
                      "        gogitzip-gtk --compress 파일/폴더... [--output 압축 파일] [--format 형식] [--level 0-9] [--yes]\n" \
                      "        gogitzip-gtk --test 압축 파일...\n", \
                      "Usage: gogitzip-gtk [archive]\n" \
                      "       gogitzip-gtk --extract-here ARCHIVE...\n" \
                      "       gogitzip-gtk --extract-smart ARCHIVE...\n" \
                      "       gogitzip-gtk --extract-to DIR ARCHIVE...\n" \
                      "       gogitzip-gtk --compress FILE/FOLDER... [--output ARCHIVE] [--format FMT] [--level 0-9] [--yes]\n" \
                      "       gogitzip-gtk --test ARCHIVE...\n")

#define GZ_UI_SX_ENUM(id, ko, en) id,
enum { GZ_UI_STRINGS(GZ_UI_SX_ENUM) STR__COUNT };
#undef GZ_UI_SX_ENUM

/* language: 1 Korean, 0 English (default) */
void gz_ui_set_korean(int korean);
int  gz_ui_korean(void);
/* "ko", "ko_KR.UTF-8", "ko-KR"... -> 1; NULL or anything else -> 0 */
int  gz_ui_locale_korean(const char *locale);

const char *gz_ui_str(int id);                       /* never NULL                         */
/* copy of s without the "_x" mnemonic markers ("파일(_F)" -> "파일", "_File" -> "File") */
void gz_ui_plain(char *out, uint32_t cap, const char *s);

/* Fill the "%s" placeholders of tmpl with args[0..n) in order ("%%" = '%').
 * Missing arguments are left empty. Always NUL-terminates (cuts at a UTF-8
 * character boundary). Returns the length written. */
uint32_t gz_ui_format(char *out, uint32_t cap, const char *tmpl, const char *const *args, uint32_t n);
#define GZ_UI_FMT(out, cap, id, ...)                                                            \
    gz_ui_format((out), (uint32_t)(cap), gz_ui_str(id), (const char *const[]){ __VA_ARGS__ },   \
                 (uint32_t)(sizeof((const char *const[]){ __VA_ARGS__ }) / sizeof(const char *)))

/* text of an error code (GZ_E_*) or an engine note (GZ_N_*) */
const char *gz_ui_code_text(int code);

/* code pages offered in menus, in display order (cp 0 = automatic) */
typedef struct gz_ui_cp { int cp; int sid; } gz_ui_cp;
extern const gz_ui_cp gz_ui_codepages[];
extern const uint32_t gz_ui_ncodepages;
const char *gz_ui_cp_name(int cp);                   /* NULL when not in the list          */

/* writer methods (GZ_WM_*) as shown in the create dialog ("Deflate", "LZMA2"...) */
const char *gz_ui_method_name(int method);
/* compression levels offered by the create dialog */
extern const uint8_t gz_ui_levels[6];                /* 0 1 3 5 7 9                        */
const char *gz_ui_level_name(int level);

/* ---------------- number formatting (ASCII, no C library) ---------------- */
void gz_ui_fmt_u64(char *o, uint32_t cap, uint64_t v);          /* 1234567                  */
void gz_ui_fmt_thousands(char *o, uint32_t cap, uint64_t v);    /* 1,234,567                */
void gz_ui_fmt_size(char *o, uint32_t cap, uint64_t v);         /* 512 B, 1.50 KB, 12.3 MB  */
void gz_ui_fmt_kb(char *o, uint32_t cap, uint64_t v);           /* 1,206 KB (list columns)  */
void gz_ui_fmt_speed(char *o, uint32_t cap, uint64_t bps);      /* 12.3 MB/s                */
void gz_ui_fmt_duration(char *o, uint32_t cap, uint64_t sec);   /* 01:05, 1:02:03           */
void gz_ui_fmt_percent(char *o, uint32_t cap, uint64_t part, uint64_t whole); /* 13%, "" if whole 0 */
void gz_ui_fmt_hex32(char *o, uint32_t cap, uint32_t v);        /* 2CC362F6                 */

#endif
