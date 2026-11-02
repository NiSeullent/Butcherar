/*
 * LD_PRELOAD shim for tests/cases/regress_gtk_mac.py (GTK calls from a worker thread).
 *
 *  - the first gtk_main() starts GZ_SHIM_DELAY_MS late (default 1000): a UI thread that is
 *    preempted right after main.c started the first job, before it enters the main loop.
 *    It changes no logic, it only makes the window in which that job runs without a main
 *    loop wide enough to hit every time.
 *  - every gtk_widget_show_all() / gtk_window_present() made on another thread than the one
 *    that loaded the program is reported on stderr as "GZSHIM: ... on a worker thread".
 *
 *   cc -shared -fPIC gtk_thread_shim.c -o gtk_thread_shim.so -ldl -pthread
 * (with an ASan-built program also set ASAN_OPTIONS=verify_asan_link_order=0)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static pthread_t s_main;

__attribute__((constructor)) static void shim_init(void) { s_main = pthread_self(); }

static void check(const char *fn)
{
    if (!pthread_equal(pthread_self(), s_main)) fprintf(stderr, "GZSHIM: %s on a worker thread\n", fn);
}

void gtk_main(void)
{
    static int started;
    void (*real)(void) = (void (*)(void))dlsym(RTLD_NEXT, "gtk_main");
    if (!started++) {
        const char *d = getenv("GZ_SHIM_DELAY_MS");
        long ms = d ? atol(d) : 1000;
        if (ms > 0 && ms < 60000) usleep((useconds_t)ms * 1000);
    }
    real();
}

void gtk_widget_show_all(void *w)
{
    void (*real)(void *) = (void (*)(void *))dlsym(RTLD_NEXT, "gtk_widget_show_all");
    check("gtk_widget_show_all");
    real(w);
}

void gtk_window_present(void *w)
{
    void (*real)(void *) = (void (*)(void *))dlsym(RTLD_NEXT, "gtk_window_present");
    check("gtk_window_present");
    real(w);
}
