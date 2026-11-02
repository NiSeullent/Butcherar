/* syntax-check stub: GNUstep's headers include it when the compiler has blocks */
#ifndef STUB_BLOCKS_RUNTIME_H
#define STUB_BLOCKS_RUNTIME_H
void *_Block_copy(const void *);
void _Block_release(const void *);
#define Block_copy(x) ((__typeof(x))_Block_copy((const void *)(x)))
#define Block_release(x) _Block_release((const void *)(x))
#endif
