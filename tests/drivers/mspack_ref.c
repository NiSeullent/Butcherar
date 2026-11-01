/*
 * mspack_ref - libmspack reference decoder for SZDD / QBasic SZ / KWAJ files
 * (fmt_legacy.py builds it only when <mspack.h> and -lmspack are available).
 *
 *   mspack_ref szdd|kwaj <in> <out>      prints "status=<libmspack error>"
 */
#include <mspack.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 4) return 2;
    int r;
    if (!strcmp(argv[1], "szdd")) {
        struct msszdd_decompressor *d = mspack_create_szdd_decompressor(NULL);
        if (!d) return 3;
        r = d->decompress(d, argv[2], argv[3]);
        mspack_destroy_szdd_decompressor(d);
    } else {
        struct mskwaj_decompressor *d = mspack_create_kwaj_decompressor(NULL);
        if (!d) return 3;
        r = d->decompress(d, argv[2], argv[3]);
        mspack_destroy_kwaj_decompressor(d);
    }
    printf("status=%d\n", r);
    return 0;
}
