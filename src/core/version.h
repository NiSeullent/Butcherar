/*
 * 고깃ZIP - program version, the one place to change it.
 *
 * Used by every front end (src/app/engine.h -> CLI, GTK, Cocoa, Windows), by the
 * Windows resource script (res/app.rc: VERSIONINFO) and by the build (Makefile reads
 * GZ_APP_VERSION for the macOS Info.plist and the Linux packages). tests/cases/
 * release_meta.py checks that the README, the web site, the release notes and the
 * Linux metainfo name the same version.
 *
 * Only preprocessor definitions: this file is also read by windres.
 */
#ifndef GZ_VERSION_H
#define GZ_VERSION_H

#define GZ_VER_MAJOR 2
#define GZ_VER_MINOR 0
#define GZ_VER_PATCH 0
#define GZ_APP_VERSION "2.0.0"

#endif
