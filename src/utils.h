#ifndef UTILS_H
#define UTILS_H

extern void DRE2over(int key_idx, uint8_t *DW);

#define CRC32_INIT (0xffffffff)
uint32_t crc32_recalc(const uint8_t *data, size_t len, uint32_t crc);
uint32_t crc32_calc(const uint8_t *data, size_t len, uint32_t crc);
int crc32_check(const uint8_t *data, size_t len, uint32_t crc);

int my_random_init();
long my_rand();

int is_multicast(struct in_addr *addr);
int multicast_group_join(int fd, struct in_addr *group);
int multicast_group_leave(int fd, struct in_addr *group);
int setnonblocking(int fd);
int set_tcp_congestion_ctl(int fd, const char *ccname);

#endif /* UTILS_H */
