#ifndef JHASH_H
#define JHASH_H

#include <stdint.h>

#define HASH_INITIAL (0x7ab3567c)

uint32_t hashword(
    const uint32_t *k,             /* the key, an array of uint32_t values */
    size_t          length,        /* the length of the key, in uint32_ts */
    uint32_t        initval);      /* the previous hash, or an arbitrary value */

#endif /* JHASH_H */
