// lwIP's one system call with NO_SYS: the time in milliseconds, for its timers. tsnet's monotonic clock.
#include "lwip/sys.h"
#include "platform.h"

u32_t sys_now(void)
{
    return (u32_t)tsnet_now_ms();
}
