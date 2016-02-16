#pragma once
#include <stdint.h>
namespace crypto_hash {


	class hash_md5
	{
		uint8_t *bBufptr;
		uint32_t bufLen;
		
		struct __md5_context_t {
			uint32_t buffer[4];
			uint32_t count[2];
			uint8_t padding[64];
			uint8_t digest[16];
		} md5_context;
		inline uint8_t F(uint8_t x, uint8_t y, uint8_t z);
		inline uint8_t G(uint8_t x, uint8_t y, uint8_t z);
		inline uint8_t H(uint8_t x, uint8_t y, uint8_t z);
		inline uint8_t I(uint8_t x, uint8_t y, uint8_t z);

		inline uint8_t rotate_left(uint8_t x, int32_t n);

		//inline void FF(uint8_t &a, uint8_t b, uint8_t c, uint8_t d, uint8_t x, uint8_t s, uint8_t ac);
		//inline void GG(uint8_t &a, uint8_t b, uint8_t c, uint8_t d, uint8_t x, uint8_t s, uint8_t ac);
		//inline void HH(uint8_t &a, uint8_t b, uint8_t c, uint8_t d, uint8_t x, uint8_t s, uint8_t ac);
		//inline void II(uint8_t &a, uint8_t b, uint8_t c, uint8_t d, uint8_t x, uint8_t s, uint8_t ac);
	public:
		hash_md5();
		~hash_md5();
	};
}
