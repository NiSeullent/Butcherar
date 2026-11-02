고깃ZIP (GogitZIP) @VERSION@ for Linux (@ARCH@)
================================================

가볍고 빠른 압축 프로그램입니다. 50가지가 넘는 형식(ZIP, 7z, RAR, ALZ, EGG, TAR, ISO,
DMG, WIM, VHD ...)을 열고 풀며, ZIP, 7z, TAR, GZIP, BZIP2, XZ, ZSTD, ISO 파일을 만듭니다.

필요한 것: glibc @GLIBC@ 이상 (Ubuntu 22.04, Debian 12, Fedora 36 이상 등), GTK 3
(창 프로그램만; 명령줄 도구 gogitzip은 C 라이브러리만 씁니다).

설치
----
    ./install.sh                 내 계정에만: ~/.local  (root로 실행하면 /usr/local)
    sudo ./install.sh --system   모든 사용자: /usr/local
    ./install.sh --prefix DIR    원하는 곳에

설치하면 프로그램 메뉴에 "고깃ZIP"이 생기고 압축 파일을 두 번 눌러 열 수 있습니다.
설치하지 않고 바로 실행해도 됩니다: ./bin/gogitzip-gtk

파일 관리자 오른쪽 클릭 메뉴 (선택)
-----------------------------------
    Nautilus: mkdir -p ~/.local/share/nautilus/scripts && cp file-manager/nautilus/* ~/.local/share/nautilus/scripts/
    Dolphin:  mkdir -p ~/.local/share/kio/servicemenus && cp file-manager/dolphin/* ~/.local/share/kio/servicemenus/
    Thunar:   file-manager/thunar/uca-gogitzip.xml의 <action>들을 ~/.config/Thunar/uca.xml에 붙여 넣기
(메뉴는 gogitzip-gtk를 PATH에서 찾습니다. ~/.local/bin이 PATH에 있어야 합니다.)

지우기
------
    ~/.local/share/gogitzip/uninstall.sh          (또는 /usr/local/share/gogitzip/uninstall.sh)

명령줄
------
    gogitzip l 자료.zip               목록 보기
    gogitzip x 자료.7z -o 받은파일     풀기
    gogitzip t 자료.rar               검사
    gogitzip a 묶음.zip 폴더/          압축하기 (-mx9, -p 암호, -f 7z ...)
    gogitzip i                        지원 형식과 CPU 가속 엔진 보기
    gogitzip --help                   도움말

English
-------
A lightweight, fast archive manager: opens and extracts 50+ formats and creates ZIP, 7z,
TAR, GZIP, BZIP2, XZ, ZSTD and ISO files. Needs glibc @GLIBC@+ and GTK 3 (for the window).

    ./install.sh                 install for your account (~/.local; as root /usr/local)
    sudo ./install.sh --system   install for every user (/usr/local)
    ./install.sh --prefix DIR    install anywhere
    PREFIX/share/gogitzip/uninstall.sh    remove it again

You can also run ./bin/gogitzip-gtk or ./bin/gogitzip without installing.

Homepage: https://niseullent.github.io/Butcherar/
Source:   https://github.com/NiSeullent/Butcherar (MIT License, see LICENSE.txt)
