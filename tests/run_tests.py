#!/usr/bin/env python3
"""
고깃ZIP test runner: imports every tests/cases/*.py module and calls run(t).

usage: run_tests.py --gzt build/gzt --work build/testwork [-k substring] [-j N] [-v]
"""
import argparse, importlib.util, os, sys, traceback, concurrent.futures as cf

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
import gztest

def run_module(path, gzt, work, verbose):
    name = os.path.splitext(os.path.basename(path))[0]
    t = gztest.T(gzt, os.path.join(work, name), name, verbose)
    try:
        spec = importlib.util.spec_from_file_location("case_" + name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.run(t)
    except gztest.SkipModule as e:
        return name, t.results, "skip: %s" % e
    except Exception:
        t.results.append((False, "exception", traceback.format_exc()[-1500:]))
    return name, t.results, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gzt", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("-k", default="")
    ap.add_argument("-j", type=int, default=max(1, (os.cpu_count() or 2)))
    ap.add_argument("-v", action="store_true")
    a = ap.parse_args()
    gzt = os.path.abspath(a.gzt)
    work = os.path.abspath(a.work)
    mods = sorted(os.path.join(HERE, "cases", f) for f in os.listdir(os.path.join(HERE, "cases"))
                  if f.endswith(".py") and not f.startswith("_") and a.k in f)
    fails = total = 0
    with cf.ThreadPoolExecutor(a.j) as ex:
        futs = [ex.submit(run_module, m, gzt, work, a.v) for m in mods]
        for fu in futs:
            name, results, skip = fu.result()
            if skip:
                print("skip %-18s %s" % (name, skip))
            for ok, label, detail in results:
                total += 1
                fails += not ok
                if not ok or a.v:
                    print("%-4s %-18s %s  %s" % ("ok" if ok else "FAIL", name, label, detail))
            nfail = sum(1 for r in results if not r[0])
            if not a.v and results:
                print("%-4s %-18s %d checks%s" % ("ok" if not nfail else "FAIL", name, len(results),
                                                ", %d failed" % nfail if nfail else ""))
    print("RESULT: %s (%d checks)" % ("OK" if not fails else "%d FAILED" % fails, total))
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
