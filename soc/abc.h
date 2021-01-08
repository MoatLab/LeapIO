#include <stdint.h>

void abc_init(unsigned long size);
void abc_deinit();

bool abc_is_block_cached(unsigned long lba, uint8_t **addr);
void abc_get_block_entry(unsigned long lba, uint8_t **addr);
void abc_set_valid(unsigned long lba);
