#ifndef __ENC_DEC_BITS_H__
#define __ENC_DEC_BITS_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t decode_bits(const uint8_t source[],
                const uint16_t offset, const uint16_t bit_count, uint16_t *decoded_bit_count);

//uint16_t encode_bits(const uint64_t value, const uint16_t offset,
//        const uint16_t bit_count, uint8_t destination[],
//        uint16_t destination_length);

uint16_t encode_bits(const uint64_t value, const uint16_t bit_count,
				uint8_t destination[], const uint16_t offset);

#ifdef __cplusplus
}
#endif

#endif // __ENC_DEC_BITS_H__
