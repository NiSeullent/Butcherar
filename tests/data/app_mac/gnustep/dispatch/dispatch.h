/* syntax-check stub of the libdispatch API used by src/mac (GNUstep is built without it) */
#ifndef STUB_DISPATCH_H
#define STUB_DISPATCH_H
#include <stdint.h>
typedef struct dispatch_queue_s *dispatch_queue_t;
typedef struct dispatch_semaphore_s *dispatch_semaphore_t;
typedef uint64_t dispatch_time_t;
typedef long dispatch_once_t;
typedef void (^dispatch_block_t)(void);
#define DISPATCH_TIME_FOREVER (~0ull)
#define QOS_CLASS_USER_INITIATED 0x19
dispatch_queue_t dispatch_get_main_queue(void);
dispatch_queue_t dispatch_get_global_queue(long identifier, unsigned long flags);
void dispatch_async(dispatch_queue_t queue, dispatch_block_t block);
void dispatch_sync(dispatch_queue_t queue, dispatch_block_t block);
void dispatch_once(dispatch_once_t *predicate, dispatch_block_t block);
dispatch_semaphore_t dispatch_semaphore_create(long value);
long dispatch_semaphore_signal(dispatch_semaphore_t dsema);
long dispatch_semaphore_wait(dispatch_semaphore_t dsema, dispatch_time_t timeout);
#endif
