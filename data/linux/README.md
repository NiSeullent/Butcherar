# 고깃ZIP on Linux (GTK 3)

## Build and install

```sh
sudo apt install build-essential pkg-config libgtk-3-dev   # Debian / Ubuntu
make linux                                                 # build/linux/gogitzip-gtk + build/gogitzip
sudo make install                                          # PREFIX=/usr/local by default
make install PREFIX=/usr DESTDIR=/tmp/stage                # packaging
```

`make install` copies the programs, the launcher (`gogitzip.desktop`), the MIME package for
archive types the freedesktop.org database lacks (`gogitzip-mime.xml`), the AppStream
metainfo and the hicolor icons, then refreshes the MIME, desktop and icon caches.

To make GogitZIP the default program for archives (current user only): *설정 → 파일 연결 →
고깃ZIP을 기본 프로그램으로 설정*, or `gogitzip-gtk --set-default-apps`. This writes
`~/.config/mimeapps.list` (like `xdg-mime default gogitzip.desktop TYPE`); when the launcher
is not installed, a user launcher for the running program is created in
`~/.local/share/applications`.

## Command line (used by the file manager menus)

| command | action |
| --- | --- |
| `gogitzip-gtk [ARCHIVE]` | main window |
| `gogitzip-gtk --extract-here ARCHIVE...` | extract next to each archive |
| `gogitzip-gtk --extract-smart ARCHIVE...` | extract into a folder named after the archive (not when it holds one top folder) |
| `gogitzip-gtk --extract-to DIR ARCHIVE...` | extract into DIR |
| `gogitzip-gtk --extract ARCHIVE...` | extract dialog |
| `gogitzip-gtk --test ARCHIVE...` | test |
| `gogitzip-gtk --compress FILE...` | create dialog, proposing `--output A`, `--format zip` and `--level 5` when given (with `--yes`: no dialog) |
| `--yes` | no questions: overwrite, errors on stderr |

Only progress windows (and questions) appear in these modes. Exit codes: 0 ok, 1 warnings,
2 errors, 7 command line error, 255 canceled.

## File manager integration

* **Nautilus (GNOME Files)** - scripts appear under *Scripts* in the right-click menu:

  ```sh
  mkdir -p ~/.local/share/nautilus/scripts
  cp data/linux/nautilus/* ~/.local/share/nautilus/scripts/
  chmod +x ~/.local/share/nautilus/scripts/고깃ZIP*
  ```

* **Dolphin (KDE 5.85+ / 6)** - a *고깃ZIP* submenu for archives and *고깃ZIP으로 압축하기* for
  any file or folder:

  ```sh
  mkdir -p ~/.local/share/kio/servicemenus
  cp data/linux/dolphin/*.desktop ~/.local/share/kio/servicemenus/
  chmod +x ~/.local/share/kio/servicemenus/gogitzip-*.desktop
  ```

* **Thunar (Xfce)** - merge the `<action>` elements of `data/linux/thunar/uca-gogitzip.xml`
  into `~/.config/Thunar/uca.xml` (inside `<actions>`), then restart Thunar (`thunar -q`).
  The actions can also be entered by hand in *Edit → Configure custom actions* with the
  commands shown in the file.

## Generated files

`gogitzip.desktop`, `gogitzip-mime.xml`, `dolphin/*.desktop`, `thunar/uca-gogitzip.xml`,
`icons/hicolor/*/apps/gogitzip.png` and `src/gtk/mimetypes.h` come from
`python3 tools/gen_linux_data.py` (extensions read from the format modules, icons rendered
with the artwork code of `tools/gen_assets.py`). Run it again after adding a reader;
`tools/gen_linux_data.py --check` reports stale files.
