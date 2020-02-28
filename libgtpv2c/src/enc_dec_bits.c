
#include "../include/enc_dec_bits.h"

#include <string.h>
#include <sys/param.h>
#include <stdio.h>


#define UINT64_T_SIZE sizeof(uint64_t)

typedef union byte_value_t {
    uint64_t val64;
    uint8_t val8[UINT64_T_SIZE];
} byte_value_t;

static const uint8_t mask_bits[] =
    { 0x55, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
static const uint8_t xor_mask_bits[] =
    { 0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01, 0x00 };

uint64_t bitmask(const uint8_t bit_count) {
    return (((uint64_t)0x1) << bit_count) - 1;
}

static void copy_start_bits(uint16_t *copy_bit_count, uint8_t *destination,
			int *mod_source_offset, int *mod_destination_offset,
			uint8_t *byte)
{
	if (*copy_bit_count >= (CHAR_BIT - *mod_destination_offset)) {
		*destination &= mask_bits[*mod_destination_offset];
		*copy_bit_count -= CHAR_BIT - *mod_destination_offset;
	} else {
		*destination &= mask_bits[*mod_destination_offset]
		| xor_mask_bits[*mod_destination_offset + *copy_bit_count + 1];

		 *byte &= mask_bits[*mod_destination_offset + *copy_bit_count];
         	 *copy_bit_count = 0;
	}
}

int copybits(const uint8_t* src, const uint16_t src_length,
        const uint16_t src_offset, uint16_t copy_bit_count,
        uint8_t* dest, const uint16_t dest_offset) {

	uint16_t ret = copy_bit_count;

    if(copy_bit_count < 1) {
        return 0;
    }

    const uint8_t* ptr_source = src + (src_offset / CHAR_BIT);
    uint8_t* ptr_destination = dest + (dest_offset / CHAR_BIT);
    int mod_source_offset = src_offset % CHAR_BIT;
    int mod_destination_offset = dest_offset % CHAR_BIT;


    if(mod_source_offset != mod_destination_offset) {

        int left_shift_bit_diff;
       	int right_shift_bit_diff;
       	uint8_t copy_byte;

	 if(mod_source_offset > mod_destination_offset) {
		left_shift_bit_diff = mod_source_offset - mod_destination_offset;
		right_shift_bit_diff = CHAR_BIT - left_shift_bit_diff;
		copy_byte = *ptr_source++ << left_shift_bit_diff;
		copy_byte |= *ptr_source >> right_shift_bit_diff;
		copy_byte &= xor_mask_bits[mod_destination_offset];
       	} else {
       		right_shift_bit_diff = mod_destination_offset - mod_source_offset;
       		left_shift_bit_diff = CHAR_BIT - right_shift_bit_diff;

		copy_byte = *ptr_source >> right_shift_bit_diff &
		xor_mask_bits[mod_destination_offset];
       	}

       	copy_start_bits(&copy_bit_count, ptr_destination, &mod_source_offset,
                                &mod_destination_offset, &copy_byte);
        *ptr_destination++ |= copy_byte;


	int copy_byte_length = copy_bit_count / CHAR_BIT;
	copy_byte_length--;
        while(copy_byte_length >= 0) {
            copy_byte = *ptr_source++ << left_shift_bit_diff;
            copy_byte |= *ptr_source >> right_shift_bit_diff;
            *ptr_destination++ = copy_byte;
	    copy_byte_length--;
        }

        int copy_bit_count_modulo = copy_bit_count % CHAR_BIT;

        if(copy_bit_count_modulo > 0) {
            copy_byte = *ptr_source++ << left_shift_bit_diff;
            copy_byte |= *ptr_source >> right_shift_bit_diff;
            copy_byte &= mask_bits[copy_bit_count_modulo];

            *ptr_destination &= xor_mask_bits[copy_bit_count_modulo];
            *ptr_destination |= copy_byte;
        }
    } else {

        if(mod_source_offset > 0) {
            uint8_t copy_byte = xor_mask_bits[mod_destination_offset] & *ptr_source++;
            copy_start_bits(&copy_bit_count, ptr_destination, &mod_source_offset,
				&mod_destination_offset, &copy_byte);
            *ptr_destination++ |= copy_byte;
        }

        int copy_byte_length = copy_bit_count / CHAR_BIT;
        int copy_bit_count_modulo = copy_bit_count % CHAR_BIT;

        if(copy_byte_length > 0) {
            memcpy(ptr_destination, ptr_source, copy_byte_length);
            ptr_source += copy_byte_length;
            ptr_destination += copy_byte_length;
        }

        if(copy_bit_count_modulo > 0) {
            *ptr_destination &= xor_mask_bits[copy_bit_count_modulo];
            *ptr_destination |= mask_bits[copy_bit_count_modulo] & *ptr_source;
	}
    }

    return ret;
}

uint16_t bits_to_bytes(uint32_t bits) {
    uint8_t byte_count = bits / CHAR_BIT;
    if(bits % CHAR_BIT != 0) {
        ++byte_count;
    }
    return byte_count;
}

uint8_t find_end_bit(const uint16_t numBits) {
    int endBit = numBits % CHAR_BIT;
    return endBit == 0 ? CHAR_BIT : endBit;
}

bool copy_bits_right_aligned(const uint8_t source[], const uint16_t source_length,
                const uint16_t offset, const uint16_t copy_bit_count,
                uint8_t* destination, const uint16_t destination_length) {
    return copybits(source, source_length, offset, copy_bit_count, destination,
            (destination_length - bits_to_bytes(copy_bit_count)) * CHAR_BIT +
                 CHAR_BIT - find_end_bit(copy_bit_count));
}

uint64_t decode_bits(const uint8_t source[],
		const uint16_t offset, const uint16_t bit_count, uint16_t *decoded_bit_count) {
    if(bit_count > 64 || bit_count < 1) {
        // TODO error reporting?
        return 0;
    }

    byte_value_t combined;
    memset(combined.val8, 0, sizeof(combined.val8));
    uint8_t source_length = 255;
    if(copy_bits_right_aligned(source, source_length, offset, bit_count,
            combined.val8, sizeof(combined.val8))) {
        if(BYTE_ORDER == LITTLE_ENDIAN) {
            combined.val64 = __builtin_bswap64(combined.val64);
            *decoded_bit_count = bit_count;
        }
    } else {
        // debug("couldn't copy enough bits from source")
    	*decoded_bit_count = 0;
    }
    return combined.val64;
}

//uint16_t encode_bits(const uint64_t value, const uint16_t offset,
//        const uint16_t bit_count, uint8_t destination[],
//        uint16_t destination_length) {
//
//#if 0
//	if(value > bitmask(bit_count)) {
//        return false;
//    }
//#endif
//
//	byte_value_t byte_val;
//	byte_val.val64 = value;
//
//    byte_val.val64 = __builtin_bswap64(byte_val.val64);
//
//    return copybits(byte_val.val8, sizeof(byte_val.val8),
//            sizeof(byte_val.val8) * CHAR_BIT - bit_count, bit_count,
//            destination, destination_length, offset);
//}

uint16_t encode_bits(const uint64_t value, const uint16_t bit_count,
		 uint8_t destination[],	const uint16_t offset)
{

#if 0
	if(value > bitmask(bit_count)) {
        return false;
    }
#endif

	byte_value_t byte_val;
	byte_val.val64 = value;

    byte_val.val64 = __builtin_bswap64(byte_val.val64);

    return copybits(byte_val.val8, sizeof(byte_val.val8),
            sizeof(byte_val.val8) * CHAR_BIT - bit_count, bit_count,
            destination, offset);
}
