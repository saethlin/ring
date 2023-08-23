#include <stdint.h>

__attribute__ ((visibility ("hidden"))) extern int32_t GFp_armcap_P;

void GFp_sha256_block_data_order(void) {
    GFp_armcap_P = 1;
}
