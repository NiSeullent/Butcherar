#!/usr/bin/env python3
"""
Refresh the Windows screenshots of the web site (web/assets/screens/) under Wine:

  welcome.png   main window without an archive (start screen, recent files)
  create.png    "새로 압축" dialog for D:\\2026 고기 축제
  extract.png   "압축 풀기" dialog for D:\\2026 고기 축제 자료.zip

The files live in a temporary folder mapped as drive D: so the dialogs show short,
clean paths instead of the build tree. main.png (and create.png with a test path) are
also written by tests/cases/app_windows.py with GZ_UPDATE_SCREENS=1; this tool reuses its
Wine/Xvfb harness.

  make build/gzt build/GogitZip.exe && python3 tools/web_screens.py [--only create,welcome]

Needs wine (32-bit prefix, kept in build/wine-gzt32), Xvfb, xdotool, ImageMagick and Pillow.
"""
import os, sys, time, shutil, zipfile, argparse, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "lib"))
sys.path.insert(0, os.path.join(ROOT, "tests", "cases"))
import gztest                     # noqa: E402
import app_windows as aw          # noqa: E402  (Wine harness, blob(), titles)

SHOTS = ("welcome", "create", "extract")


def palette_png(src, dst):
    """palette PNG like the other screenshots (small, crisp UI colours)"""
    from PIL import Image
    im = Image.open(src).convert("RGB")
    im.quantize(256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(dst, optimize=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=",".join(SHOTS), help="comma separated: " + ", ".join(SHOTS))
    ap.add_argument("--out", default=os.path.join(ROOT, "web", "assets", "screens"))
    a = ap.parse_args()
    want = [s for s in a.only.split(",") if s]
    exe = os.path.join(ROOT, "build", "GogitZip.exe")
    if not os.path.exists(exe):
        sys.exit("build/GogitZip.exe missing: make build/GogitZip.exe")
    os.makedirs(a.out, exist_ok=True)
    work = os.path.join(ROOT, "build", "web_screens")
    t = gztest.T(os.path.join(ROOT, "build", "gzt"), work, "web_screens")
    try:
        w = aw.Wine(t, exe)
    except gztest.SkipModule as e:
        sys.exit("cannot run Wine: %s" % e)
    drive = os.path.join(work, "drive_d")
    shutil.rmtree(drive, ignore_errors=True)
    folder = os.path.join(drive, "2026 고기 축제")
    when = (2026, 10, 24, 18, 30, 0)
    files = {"레시피/양념 갈비.txt": aw.blob(4000, 7), "레시피/수육.txt": aw.blob(3000, 8),
             "메뉴판/메뉴판.pdf": aw.blob(90000, 2), "사진/현장 1.jpg": aw.blob(150000, 4),
             "참가 신청서.pdf": aw.blob(212000, 2), "행사 안내.txt": aw.blob(23000, 9)}
    for k, v in files.items():
        p = os.path.join(folder, k)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(v)
    arc = os.path.join(drive, "2026 고기 축제 자료.zip")
    with zipfile.ZipFile(arc, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in sorted(files.items()):
            z.writestr(zipfile.ZipInfo("2026 고기 축제/" + k, when), v)
    dosdev = os.path.join(w.prefix, "dosdevices", "d:")
    if os.path.lexists(dosdev):
        os.remove(dosdev)
    os.symlink(drive, dosdev)
    shots = os.path.join(work, "shots")
    os.makedirs(shots, exist_ok=True)
    made = []
    try:
        w.settings(CFormat=1, CLevel=5, CMethod=0, Language=0, WinX=20, WinY=20, WinW=1200, WinH=700, WinMax=0,
                   ShowTree=1, Split=0, OpenFolder=0, Overwrite=0, SmartFolder=1)     # defaults: ask, smart folder
        for i, name in enumerate(("2026 고기 축제 자료.zip", "한우 레시피 모음.zip", "회계 자료 (암호).zip")):
            w.settings(**{"Recent%d" % i: "D:\\" + name})
        for i in range(3, 6):
            w.settings(**{"Recent%d" % i: ""})
        jobs = {
            "create": (["/add", "D:\\2026 고기 축제"], aw.TITLE_CREATE),
            "extract": (["/extract", "D:\\2026 고기 축제 자료.zip"], "압축 풀기"),
            "welcome": ([], "고깃ZIP"),
        }
        for name in want:
            args, title = jobs[name]
            p = w.start(args)
            win = w.find_window(title, 90)
            if not win:
                print("%s: window not found" % name)
                w.server_kill()
                continue
            subprocess.run(["xdotool", "mousemove", "1390", "890"], env=w.env, capture_output=True)  # no hover
            time.sleep(2.0)
            png = os.path.join(shots, name + ".png")
            if w.shot(win, png):
                palette_png(png, os.path.join(a.out, name + ".png"))
                made.append(name)
            w.key(win, "Escape")
            w.wait(p, 20)
            w.server_kill()
    finally:
        if os.path.islink(dosdev):
            os.remove(dosdev)
        w.close()
    print("updated:", ", ".join(made) or "nothing")


if __name__ == "__main__":
    main()
