#include "hash_md5.h"


namespace crypto_hash {

	hash_md5::hash_md5() : bBufptr(nullptr)
	{
	}


	hash_md5::~hash_md5()
	{
	}
	inline uint8_t hash_md5::F(uint8_t x, uint8_t y, uint8_t z) {
		return x & y | ~x & z;
	}
	inline uint8_t hash_md5::G(uint8_t x, uint8_t y, uint8_t z) {
		return x & z | y & ~z;
	}
	inline uint8_t hash_md5::H(uint8_t x, uint8_t y, uint8_t z) {
		return x ^ y ^ z;
	}
	inline uint8_t hash_md5::I(uint8_t x, uint8_t y, uint8_t z) {
		return y ^ (x | ~z);
	}
	inline uint8_t hash_md5::rotate_left(uint8_t x, int32_t n) {
		return (x << n) | (x >> ((int32_t)32 - n));
	}
}