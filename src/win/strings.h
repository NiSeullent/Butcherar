/*
 * 고깃ZIP - UI strings (Korean / English)
 * English is used automatically when no Korean font is installed
 * (e.g. Western Windows 2000/XP without East Asian language support).
 */
#ifndef GZ_STRINGS_H
#define GZ_STRINGS_H

#define GZ_STRINGS(X) \
X(S_APP,            L"고깃ZIP", L"GogitZIP") \
X(S_TAGLINE,        L"가볍고 빠른 압축 해제 프로그램", L"Lightweight, fast archive extractor") \
X(S_TB_OPEN,        L"열기", L"Open") \
X(S_TB_EXTRACT,     L"압축 풀기", L"Extract") \
X(S_TB_HERE,        L"바로 풀기", L"Quick") \
X(S_TB_TEST,        L"테스트", L"Test") \
X(S_TB_VIEW,        L"파일 보기", L"View") \
X(S_TB_INFO,        L"정보", L"Info") \
X(S_TB_CODEPAGE,    L"코드페이지", L"Codepage") \
X(S_TB_SETTINGS,    L"설정", L"Settings") \
X(S_M_FILE,         L"파일(&F)", L"&File") \
X(S_M_OPEN,         L"압축 파일 열기(&O)...\tCtrl+O", L"&Open archive...\tCtrl+O") \
X(S_M_RECENT,       L"최근 파일(&R)", L"&Recent files") \
X(S_M_NORECENT,     L"(없음)", L"(none)") \
X(S_M_CLOSE,        L"닫기(&C)\tCtrl+W", L"&Close\tCtrl+W") \
X(S_M_INFO,         L"압축 파일 정보(&I)\tAlt+Enter", L"Archive &info\tAlt+Enter") \
X(S_M_EXIT,         L"끝내기(&X)", L"E&xit") \
X(S_M_ACTION,       L"작업(&A)", L"&Actions") \
X(S_M_EXTRACT,      L"압축 풀기(&E)...\tCtrl+E", L"&Extract...\tCtrl+E") \
X(S_M_EXTRACT_HERE, L"여기에 풀기(&H)", L"Extract &here") \
X(S_M_EXTRACT_SMART,L"폴더를 만들어 바로 풀기(&Q)\tCtrl+Q", L"&Quick extract to folder\tCtrl+Q") \
X(S_M_EXTRACT_SEL,  L"선택한 항목 풀기(&S)...", L"Extract &selected...") \
X(S_M_TEST,         L"압축 파일 테스트(&T)\tCtrl+T", L"&Test archive\tCtrl+T") \
X(S_M_VIEW,         L"보기(&V)", L"&View") \
X(S_M_OPENITEM,     L"열기(&O)\tEnter", L"&Open\tEnter") \
X(S_M_UP,           L"상위 폴더(&U)\tBackspace", L"&Up one level\tBackspace") \
X(S_M_TREE,         L"폴더 트리 보기(&F)", L"&Folder tree") \
X(S_M_SELECTALL,    L"모두 선택(&A)\tCtrl+A", L"Select &all\tCtrl+A") \
X(S_M_CODEPAGE,     L"코드페이지(&C)", L"&Codepage") \
X(S_M_OPTIONS,      L"옵션(&O)", L"&Options") \
X(S_M_SETTINGS,     L"설정(&S)...", L"&Settings...") \
X(S_M_BENCH,        L"CPU 가속 벤치마크(&B)...", L"CPU &benchmark...") \
X(S_M_HELP,         L"도움말(&H)", L"&Help") \
X(S_M_HOMEPAGE,     L"공식 홈페이지(&W)", L"Official &website") \
X(S_M_ABOUT,        L"고깃ZIP 정보(&A)...", L"&About GogitZIP...") \
X(S_CP_AUTO,        L"자동 감지", L"Auto detect") \
X(S_CP_UTF8,        L"유니코드 (UTF-8)", L"Unicode (UTF-8)") \
X(S_CP_949,         L"한국어 (CP949)", L"Korean (CP949)") \
X(S_CP_932,         L"일본어 (Shift-JIS)", L"Japanese (Shift-JIS)") \
X(S_CP_936,         L"중국어 간체 (GBK)", L"Chinese Simplified (GBK)") \
X(S_CP_950,         L"중국어 번체 (Big5)", L"Chinese Traditional (Big5)") \
X(S_CP_1252,        L"서유럽 (Windows-1252)", L"Western (Windows-1252)") \
X(S_CP_437,         L"영어 DOS (CP437)", L"English DOS (CP437)") \
X(S_CP_866,         L"러시아어 DOS (CP866)", L"Russian DOS (CP866)") \
X(S_COL_NAME,       L"이름", L"Name") \
X(S_COL_SIZE,       L"원본 크기", L"Size") \
X(S_COL_PACKED,     L"압축 크기", L"Packed") \
X(S_COL_TYPE,       L"종류", L"Type") \
X(S_COL_MTIME,      L"수정한 날짜", L"Modified") \
X(S_COL_RATIO,      L"압축률", L"Ratio") \
X(S_COL_METHOD,     L"방식", L"Method") \
X(S_COL_CRC,        L"CRC32", L"CRC32") \
X(S_PARENT,         L"상위 폴더", L"Parent folder") \
X(S_FOLDER,         L"파일 폴더", L"File folder") \
X(S_FILE,           L"파일", L"File") \
X(S_ST_SUMMARY,     L"파일 %s개, 폴더 %s개  ·  원본 %s  ·  압축 %s (%s)", L"%s files, %s folders  ·  %s  ·  packed %s (%s)") \
X(S_ST_SELECTED,    L"%s개 선택 (%s)", L"%s selected (%s)") \
X(S_ST_ENGINE,      L"%S 엔진  ·  %d스레드", L"%S engine  ·  %d threads") \
X(S_ST_READY,       L"준비", L"Ready") \
X(S_W_DROP,         L"압축 파일을 이곳에 끌어다 놓으세요", L"Drop an archive here") \
X(S_W_FORMATS,      L"ZIP · ZIP64 · Deflate64 · TAR · TAR.GZ · TGZ · GZ  |  AES · ZipCrypto", L"ZIP · ZIP64 · Deflate64 · TAR · TAR.GZ · TGZ · GZ  |  AES · ZipCrypto") \
X(S_W_OPEN,         L"압축 파일 열기", L"Open archive") \
X(S_W_EXTRACT,      L"압축 풀기...", L"Extract...") \
X(S_W_RECENT,       L"최근 사용한 파일", L"Recent files") \
X(S_W_ENGINE,       L"가속 엔진", L"Engine") \
X(S_BTN_OK,           L"확인", L"OK") \
X(S_CANCEL,         L"취소", L"Cancel") \
X(S_CLOSE,          L"닫기", L"Close") \
X(S_BROWSE,         L"찾아보기...", L"Browse...") \
X(S_X_TITLE,        L"압축 풀기", L"Extract") \
X(S_X_DEST,         L"압축을 풀 위치", L"Destination folder") \
X(S_X_HERE,         L"압축 파일 위치", L"Archive folder") \
X(S_X_DESKTOP,      L"바탕 화면", L"Desktop") \
X(S_X_DOCS,         L"문서", L"Documents") \
X(S_X_MAKEFOLDER,   L"압축 파일 이름으로 폴더 만들기 (최상위 폴더가 하나뿐이면 생략)", L"Create a folder named after the archive (skip if it has one top folder)") \
X(S_X_OVERWRITE,    L"같은 이름의 파일이 있으면", L"If a file already exists") \
X(S_OW_ASK,         L"매번 물어보기", L"Ask me") \
X(S_OW_ALL,         L"항상 덮어쓰기", L"Overwrite") \
X(S_OW_SKIP,        L"건너뛰기", L"Skip") \
X(S_OW_RENAME,      L"자동으로 이름 바꾸기", L"Rename automatically") \
X(S_X_OPENFOLDER,   L"압축을 푼 다음 폴더 열기", L"Open the folder when done") \
X(S_X_SELECTED,     L"선택한 항목만 풀기 (%d개)", L"Extract selected items only (%d)") \
X(S_X_START,        L"압축 풀기", L"Extract") \
X(S_X_SUMMARY,      L"파일 %s개  ·  %s", L"%s files  ·  %s") \
X(S_X_PICK,         L"압축을 풀 폴더를 선택하세요.", L"Choose the destination folder.") \
X(S_P_EXTRACTING,   L"압축 푸는 중", L"Extracting") \
X(S_P_TESTING,      L"테스트 중", L"Testing") \
X(S_P_PAUSE,        L"일시 정지", L"Pause") \
X(S_P_RESUME,       L"계속", L"Resume") \
X(S_P_ELAPSED,      L"경과 시간", L"Elapsed") \
X(S_P_REMAIN,       L"남은 시간", L"Remaining") \
X(S_P_SPEED,        L"속도", L"Speed") \
X(S_P_PROCESSED,    L"처리량", L"Processed") \
X(S_P_FILES,        L"파일", L"Files") \
X(S_P_PAUSED,       L"일시 정지됨", L"Paused") \
X(S_P_CANCELING,    L"취소하는 중...", L"Canceling...") \
X(S_P_PREPARING,    L"준비하는 중...", L"Preparing...") \
X(S_P_OPENING,      L"압축 파일을 여는 중...", L"Opening archive...") \
X(S_P_ENGINE,       L"%S  ·  CRC %S  ·  %d스레드", L"%S  ·  CRC %S  ·  %d threads") \
X(S_PW_TITLE,       L"비밀번호 입력", L"Password required") \
X(S_PW_PROMPT,      L"암호로 보호된 파일입니다. 비밀번호를 입력하세요.", L"This file is encrypted. Please enter the password.") \
X(S_PW_WRONG,       L"비밀번호가 올바르지 않습니다. 다시 입력하세요.", L"Wrong password. Please try again.") \
X(S_PW_SHOW,        L"비밀번호 표시", L"Show password") \
X(S_OW_TITLE,       L"파일 덮어쓰기 확인", L"Confirm file replace") \
X(S_OW_PROMPT,      L"대상 폴더에 같은 이름의 파일이 이미 있습니다.", L"The destination already contains a file with this name.") \
X(S_OW_EXISTING,    L"기존 파일", L"Existing file") \
X(S_OW_NEW,         L"압축 파일 안의 파일", L"File in archive") \
X(S_OW_APPLYALL,    L"남은 파일에도 모두 적용", L"Apply to all remaining files") \
X(S_OW_B_OVERWRITE, L"덮어쓰기", L"Replace") \
X(S_OW_B_SKIP,      L"건너뛰기", L"Skip") \
X(S_OW_B_RENAME,    L"이름 바꾸기", L"Rename") \
X(S_R_TITLE,        L"작업 결과", L"Result") \
X(S_R_TEST_OK,      L"테스트를 마쳤습니다. 모든 파일에 이상이 없습니다.", L"Test finished. No errors were found.") \
X(S_R_ERRORS,       L"작업을 마쳤지만 %d개 항목에 문제가 있습니다.", L"Finished, but %d item(s) had problems.") \
X(S_R_CANCELED,     L"작업이 취소되었습니다.", L"The operation was canceled.") \
X(S_R_STATS,        L"파일 %s개  ·  %s  ·  %s  ·  평균 %s", L"%s files  ·  %s  ·  %s  ·  avg %s") \
X(S_E_OK,           L"정상", L"OK") \
X(S_E_IO,           L"읽기/쓰기 오류", L"Read/write error") \
X(S_E_FORMAT,       L"압축 파일 형식이 올바르지 않습니다", L"Not a valid archive") \
X(S_E_DATA,         L"압축 데이터가 손상되었습니다", L"Compressed data is corrupt") \
X(S_E_CRC,          L"CRC 오류 (파일이 손상됨)", L"CRC error (file is damaged)") \
X(S_E_METHOD,       L"지원하지 않는 압축 방식입니다", L"Unsupported compression method") \
X(S_E_PASSWORD,     L"비밀번호가 틀렸거나 파일이 손상되었습니다", L"Wrong password or damaged file") \
X(S_E_NOMEM,        L"메모리가 부족합니다", L"Out of memory") \
X(S_E_CANCEL,       L"취소됨", L"Canceled") \
X(S_E_TRUNC,        L"압축 파일이 잘렸습니다 (다운로드가 덜 되었을 수 있음)", L"Archive is truncated") \
X(S_E_SKIP,         L"건너뜀", L"Skipped") \
X(S_E_CREATE,       L"파일을 만들 수 없습니다", L"Cannot create file") \
X(S_E_AUTH,         L"AES 인증 실패 (손상되었거나 변조됨)", L"AES authentication failed") \
X(S_E_DISK,         L"디스크 공간이 부족합니다", L"Disk is full") \
X(S_E_SPLIT,        L"분할 압축 파일은 지원하지 않습니다", L"Split archives are not supported") \
X(S_OPEN_FAIL,      L"압축 파일을 열 수 없습니다.", L"Cannot open the archive.") \
X(S_FILTER_ARC,     L"압축 파일", L"Archives") \
X(S_FILTER_ALL,     L"모든 파일", L"All files") \
X(S_S_TITLE,        L"설정", L"Settings") \
X(S_S_GENERAL,      L"일반", L"General") \
X(S_S_CODEPAGE,     L"파일 이름 코드페이지", L"File name codepage") \
X(S_S_OVERWRITE,    L"덮어쓰기 기본값", L"Default overwrite mode") \
X(S_S_LANG,         L"언어 (Language)", L"Language") \
X(S_S_LANG_AUTO,    L"자동", L"Automatic") \
X(S_S_PERF,         L"성능", L"Performance") \
X(S_S_THREADS,      L"동시에 사용할 스레드", L"Worker threads") \
X(S_S_AUTO_N,       L"자동 (%d개)", L"Automatic (%d)") \
X(S_S_ENGINE,       L"CPU 가속 엔진", L"CPU acceleration") \
X(S_S_ENGINE_AUTO,  L"자동 (%S)", L"Automatic (%S)") \
X(S_S_SHELL,        L"탐색기 통합", L"Explorer integration") \
X(S_S_SHELL_MENU,   L"마우스 오른쪽 메뉴에 고깃ZIP 추가", L"Add GogitZIP to the right-click menu") \
X(S_S_SHELL_ASSOC,  L"ZIP 파일을 고깃ZIP으로 열기 (연결 프로그램)", L"Open ZIP files with GogitZIP") \
X(S_S_RESTART,      L"언어 설정은 프로그램을 다시 시작하면 적용됩니다.", L"Restart GogitZIP to apply the language.") \
X(S_S_ASSOC_WIN8,   L"Windows 8 이상에서는 [설정 > 앱 > 기본 앱]에서 고깃ZIP을 선택해 주세요.", L"On Windows 8 or later, choose GogitZIP in Settings > Apps > Default apps.") \
X(S_V_MENU,         L"고깃ZIP", L"GogitZIP") \
X(S_V_OPEN,         L"고깃ZIP으로 열기", L"Open with GogitZIP") \
X(S_V_HERE,         L"여기에 풀기", L"Extract here") \
X(S_V_SMART,        L"폴더를 만들어 풀기", L"Extract to a new folder") \
X(S_V_EXTRACT,      L"압축 풀기...", L"Extract...") \
X(S_V_TEST,         L"압축 파일 테스트", L"Test archive") \
X(S_V_DESC,         L"고깃ZIP 압축 파일", L"GogitZIP archive") \
X(S_A_TITLE,        L"고깃ZIP 정보", L"About GogitZIP") \
X(S_A_VERSION,      L"버전 %s (%s)", L"Version %s (%s)") \
X(S_A_CPU,          L"프로세서", L"Processor") \
X(S_A_ENGINE,       L"가속 엔진", L"Acceleration") \
X(S_A_OS,           L"운영체제", L"Operating system") \
X(S_A_COPY,         L"© 2026 Butcherar 프로젝트 · MIT 라이선스로 배포되는 자유 소프트웨어", L"© 2026 Butcherar project · free software under the MIT license") \
X(S_A_HOME,         L"공식 홈페이지 방문", L"Visit the website") \
X(S_I_TITLE,        L"압축 파일 정보", L"Archive information") \
X(S_I_PATH,         L"위치", L"Location") \
X(S_I_FORMAT,       L"형식", L"Format") \
X(S_I_FILESIZE,     L"파일 크기", L"File size") \
X(S_I_CONTENTS,     L"내용", L"Contents") \
X(S_I_USIZE,        L"원본 크기", L"Original size") \
X(S_I_RATIO,        L"압축률", L"Compression") \
X(S_I_ENC,          L"암호화", L"Encryption") \
X(S_I_YES,          L"있음", L"Yes") \
X(S_I_NO,           L"없음", L"No") \
X(S_I_CP,           L"파일 이름 인코딩", L"Name encoding") \
X(S_I_COMMENT,      L"주석", L"Comment") \
X(S_I_SFX,          L"자동 압축 풀림(SFX) 데이터 %s 포함", L"Includes %s of self-extractor data") \
X(S_B_TITLE,        L"CPU 가속 벤치마크", L"CPU benchmark") \
X(S_B_DESC,         L"이 PC에서 쓸 수 있는 모든 가속 엔진으로 압축 해제(Deflate)와 CRC32 속도를 측정합니다.", L"Measures Deflate decoding and CRC32 speed with every engine this PC supports.") \
X(S_B_RUN,          L"측정 시작", L"Run") \
X(S_B_RUNNING,      L"측정 중...", L"Running...") \
X(S_B_ENGINE,       L"엔진", L"Engine") \
X(S_B_INFLATE,      L"압축 해제", L"Inflate") \
X(S_B_CRC,          L"CRC32", L"CRC32") \
X(S_B_CURRENT,      L"사용 중", L"active") \
X(S_B_UNSUPPORTED,  L"이 CPU/OS에서 지원 안 함", L"not supported here") \
X(S_NO_ARCHIVE,     L"압축 파일이 열려 있지 않습니다.", L"No archive is open.") \
X(S_LINK_SKIP,      L"링크 항목은 건너뜁니다", L"Link entries are skipped") \
X(S_REG_DONE,       L"탐색기 메뉴 설정을 적용했습니다.", L"Explorer integration updated.")

#define GZ_SX_ENUM(id, ko, en) id,
enum { GZ_STRINGS(GZ_SX_ENUM) S__COUNT };
#undef GZ_SX_ENUM

extern const wchar_t *const *g_str;
#define S(id) (g_str[id])
void strings_init(int korean);
int  strings_korean(void);

#endif
