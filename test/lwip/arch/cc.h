#pragma once
// lwIP's compiler and platform glue for the host build: the C library's types and an assert that aborts.
#include <stdio.h>
#include <stdlib.h>

#define LWIP_PLATFORM_DIAG(x) \
    do {                      \
        printf x;             \
    } while (0)
#define LWIP_PLATFORM_ASSERT(x)                                                        \
    do {                                                                               \
        fprintf(stderr, "lwIP assert \"%s\" at %s:%d\n", x, __FILE__, __LINE__);       \
        abort();                                                                       \
    } while (0)
#define LWIP_RAND() ((u32_t)rand())
