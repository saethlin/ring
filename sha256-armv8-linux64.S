.text

.hidden	GFp_armcap_P

.globl	GFp_sha256_block_data_order
.hidden	GFp_sha256_block_data_order
.type	GFp_sha256_block_data_order,%function
.align	6
GFp_sha256_block_data_order:
	adrp	x16,GFp_armcap_P
	ret
.size	GFp_sha256_block_data_order,.-GFp_sha256_block_data_order
