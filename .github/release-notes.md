## 고깃ZIP 2.0.0

1.0의 Windows 전용 압축 해제 프로그램이 **Windows · macOS · Linux에서 쓰는 압축 프로그램**이 되었습니다.
<!-- gen:nread -->52<!-- /gen:nread -->가지 형식을 열고 풀며, ZIP · 7z · TAR · ISO 같은 압축 파일을 새로 만들 수 있습니다.
반디집 같은 익숙한 화면과 C로 직접 짠 엔진은 그대로이고, 모든 운영체제가 같은 엔진을 씁니다.

### 새로 생긴 것

- **macOS 앱** — GogitZIP.app 하나로 Intel Mac(macOS 10.13 이상)과 Apple silicon Mac(macOS 11 이상)에서 모두 실행됩니다. Finder 서비스 메뉴로 바로 풀기 · 압축하기를 할 수 있습니다.
- **Linux 앱** — GTK 3 창 프로그램 `gogitzip-gtk`와 명령줄 도구 `gogitzip`. x86-64와 ARM64(aarch64)용 설치 패키지(.tar.gz)와 Debian · Ubuntu용 .deb를 함께 냅니다. 프로그램 메뉴와 파일 연결이 함께 설치되고, Nautilus · Dolphin · Thunar 오른쪽 클릭 메뉴도 들어 있습니다.
- **압축하기** — ZIP, 7z, TAR, TAR.GZ · TAR.BZ2 · TAR.XZ · TAR.ZST, GZ · BZ2 · XZ · ZST, ISO 파일을 만듭니다. Windows 탐색기 메뉴에 ‘압축하기…’, ‘이름.zip으로 압축’, ‘이름.7z로 압축’이 생겼습니다.
- **읽는 형식 <!-- gen:nread -->52<!-- /gen:nread -->가지** — RAR, 7z, 알집(ALZ · EGG), CAB, MSI, NSIS · Inno Setup 설치 파일, ISO · UDF · DMG · WIM · VHD(X) · VMDK 디스크 이미지, NTFS · FAT · ext4 · HFS+ · APFS · SquashFS 파일 시스템까지 엽니다.
- **명령줄 도구 `gogitzip`** — 7-Zip과 비슷한 `l` · `x` · `e` · `t` · `a` · `i` 명령. 한국어 · 영어 메시지, 덮어쓰기 질문, 암호 입력, 진행률 표시.

### 읽는 형식
<!-- gen:formats-list-ko -->
- **압축 파일** (24): 7z, ZIP, RAR5, RAR, ALZ, EGG, TAR, GZIP, BZIP2, XZ, ZSTD, LZMA, LZIP, LZ4, LZO, Z, CAB, ARJ, LZH / LHA, CPIO, CHM, SZDD / KWAJ, PBZX, 분할 파일
- **설치 파일·실행 파일** (9): NSIS, Inno Setup, MSI / OLE, XAR, RPM, AR, PE, ELF, Mach-O
- **디스크 이미지** (11): ISO, UDF, DMG, WIM, VHD, VHDX, VMDK, VDI, QCOW / QCOW2, Sparse, MBR / GPT
- **파일 시스템** (8): NTFS, FAT, exFAT, ext2/3/4, HFS / HFS+, APFS, SquashFS, CramFS
<!-- /gen:formats-list-ko -->
압축된 TAR(.tar.gz, .tar.xz, .tar.zst …)는 한 번에 열리고, 압축 파일 안의 압축 파일이나 디스크 이미지 안의 파일 시스템도 두 번 눌러 바로 들어갈 수 있습니다.

### 만드는 형식
<!-- gen:writers-ko -->
- **7z**: 저장 · Deflate · BZip2 · LZMA · LZMA2 · PPMd + AES-256, BCJ·ARM64 필터, 파일 이름 암호화 (.7z)
- **ZIP**: 저장 · Deflate · BZip2 · LZMA · PPMd + ZipCrypto · AES-256, ZIP64 (.zip)
- **TAR**: ustar·pax: 긴 이름·링크·권한 (.tar)
- **GZIP**: 저장 · Deflate (.gz, .tar.gz)
- **BZIP2**: BZip2 (.bz2, .tar.bz2)
- **XZ**: 저장 · LZMA2 (.xz, .tar.xz)
- **ZSTD**: 저장 · Zstandard (.zst, .tar.zst)
- **ISO**: Joliet·Rock Ridge (.iso)
<!-- /gen:writers-ko -->

### 압축 방식과 암호

- **풀기**: Deflate · Deflate64, BZip2, LZMA · LZMA2, PPMd(H · I), Zstandard, LZ4, LZO, LZX, Quantum, XPRESS, LZMS, LZFSE, RAR 1.5 ~ 7, 알집 AZO, Implode · Shrink · Reduce, LZH 계열, BCJ · BCJ2 · ARM64 · Delta 필터
- **만들기**: Deflate(1 ~ 9단계), BZip2, LZMA, LZMA2, PPMd, Zstandard. 실행 파일에는 BCJ · ARM64 필터를 자동으로 붙입니다.
- **암호**: ZIP의 WinZip AES-256과 ZipCrypto, 7z의 AES-256과 파일 이름 암호화를 만들고 풉니다. RAR 3(AES-128) · RAR 5(AES-256) · 헤더 암호화, 알집 EGG의 AES · LEA, ALZ의 ZipCrypto 암호도 풉니다.

### 한국 압축 파일과 한글 이름

- 이스트소프트 **알집 ALZ · EGG**를 따로 프로그램 없이 풉니다. 분할 압축(.a00, .vol1.egg), 솔리드, 암호 파일도 됩니다.
- 옛 Windows에서 만든 압축 파일의 CP949 이름과 UTF-8 이름을 파일마다 자동으로 구별하고, macOS에서 자모가 풀어진(NFD) 이름은 다시 합칩니다.

### CPU 가속

- **x86**: 실행할 때 CPU와 운영체제를 확인해서 i586 · MMX · SSE · SSE2 · SSE4.1 · AVX · AVX2 가운데 가장 빠른 엔진을 고릅니다. CRC32는 PCLMULQDQ / VPCLMULQDQ, AES는 AES-NI / VAES, SHA는 SHA-NI를 씁니다. 32비트판은 지금도 Pentium과 Windows 2000에서 돌아갑니다.
- **ARM64**: NEON, ARMv8 CRC32 · PMULL · AES · SHA 명령을 씁니다(Apple silicon Mac, ARM64 Linux).
- 여러 파일을 CPU 코어 수만큼 동시에 풀고, 압축할 때도 여러 스레드를 씁니다.

### 어떤 파일을 받나요?

| 운영체제 | CPU | 파일 |
|---|---|---|
| Windows 7 · 8 · 10 · 11 (64비트), XP x64 · Vista x64 | x64 | **GogitZip64.exe** — 대부분의 PC는 이쪽 |
| Windows 2000 · XP · Vista 이상 모든 Windows | x86 (Pentium 이상) | **GogitZip.exe** (32비트판) |
| macOS 10.13 High Sierra 이상 (Intel), macOS 11 Big Sur 이상 (Apple silicon) | 유니버설 | **GogitZIP-mac.dmg** |
| Linux (glibc 2.35 이상, GTK 3) · Ubuntu 22.04+, Debian 12+, Fedora 36+ … | x86-64 | **GogitZIP-2.0.0-linux-x86_64.tar.gz** 또는 **gogitzip_2.0.0_amd64.deb** |
| Linux (glibc 2.35 이상, GTK 3) · Raspberry Pi OS 64비트 … | ARM64 | **GogitZIP-2.0.0-linux-aarch64.tar.gz** 또는 **gogitzip_2.0.0_arm64.deb** |

- **Windows**: 받은 실행 파일을 아무 폴더에 두고 실행하면 됩니다. 설치가 필요 없고, 설정은 `HKCU\Software\GogitZIP`에 저장됩니다(1.0 설정을 그대로 씁니다). 탐색기 메뉴는 설정 창에서 켜고 끕니다(관리자 권한 필요 없음).
- **macOS**: dmg를 열고 GogitZIP을 ‘응용 프로그램’ 폴더로 끌어다 놓으세요.
- **Linux**: `.deb`는 `sudo apt install ./gogitzip_2.0.0_amd64.deb`, `.tar.gz`는 풀고 `./install.sh`(내 계정의 `~/.local`에 설치, 모든 사용자용은 `sudo ./install.sh --system`)를 실행합니다.

### 알아 두실 점

- **코드 서명이 없습니다.** Windows 10 · 11에서 처음 실행할 때 SmartScreen 경고(“Windows의 PC 보호”)가 나오면 **추가 정보 → 실행**을 누르세요. macOS에서 “확인되지 않은 개발자” 경고가 나오면 Finder에서 앱을 **오른쪽 클릭 → 열기 → 열기**를 누르거나(macOS 15부터는 **시스템 설정 → 개인정보 보호 및 보안 → 그래도 열기**), 터미널에서 `xattr -dr com.apple.quarantine /Applications/GogitZIP.app`을 실행하세요.
- 받은 파일이 원본과 같은지는 아래 SHA-256 값(`SHA256SUMS.txt`)으로 확인할 수 있습니다.
- Windows 실행 파일은 압축 엔진과 형식이 늘어서 1.0의 400KB에서 약 1.4MB가 되었습니다. 여전히 C 런타임 없이 실행 파일 하나로 동작합니다.
- 파일 이름 인코딩 자동 감지가 틀리면 도구 모음의 **코드페이지** 단추로 바로 바꿀 수 있습니다.

공식 홈페이지: https://niseullent.github.io/Butcherar/
