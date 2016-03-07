#include "hash_md5.h"
#include <fstream>
#include <thread>
#include <cstring>


namespace crypto_hash {
	const uint64_t INIT_UINT32_MAX = 4294967296;
	// Magic init constants
	const uint32_t STATE_INIT_0 = 0x67452301;
	const uint32_t STATE_INIT_1 = 0xEFCDAB89;
	const uint32_t STATE_INIT_2 = 0x98BADCFE;
	const uint32_t STATE_INIT_3 = 0x10325476;
	const enum R1_CONSTANTS : uint8_t 
	{R1_C1 = 7, R1_C2 = 12, R1_C3 = 17, R1_C4 = 22};
	const enum R2_CONSTANTS : uint8_t 
	{R2_C1 = 5, R2_C2 = 9, R2_C3 = 14, R2_C4 = 20};
	const enum R3_CONSTANTS : uint8_t 
	{R3_C1 = 4, R3_C2 = 11, R3_C3 = 16, R3_C4 = 23};
	const enum R4_CONSTANTS : uint8_t 
	{R4_C1 = 6, R4_C2 = 10, R4_C3 = 15, R4_C4 = 21};
	hash_md5::hash_md5() 
	{
		this->init();
		this->eError = HASH_MD5_NO_DATA;
	}
	hash_md5::hash_md5(const std::string& _str) 
	{
		this->init();
		this->update(_str.c_str(), _str.length());
	}

	hash_md5::~hash_md5()
	{
	}
	hash_md5_result hash_md5::getResult() {
		return this->eError;
	}
	void hash_md5::init() {
		this->bFinalized = false;
		std::memset(&(this->md5_context), 0, sizeof(__md5_context_t));
		std::memset(&(this->T), 0, sizeof(uint32_t) * 64);
		this->md5_context.state[0] = STATE_INIT_0;
		this->md5_context.state[1] = STATE_INIT_1;
		this->md5_context.state[2] = STATE_INIT_2;
		this->md5_context.state[3] = STATE_INIT_3;
		this->T_init();
	}
	void hash_md5::T_init() {

		for (uint16_t ind = 0; ind < 64; ++ind) {
			this->T[ind] = 
				static_cast<uint32_t>(abs(INIT_UINT32_MAX * 
					sin(static_cast<double>(ind + 1))));
		}
	}
	void hash_md5::update(const char *msg, const uint32_t msg_len) {
		this->update(reinterpret_cast<const unsigned char*>(msg), msg_len);
	}
	void hash_md5::update(const unsigned char *msg, const uint32_t msg_len) {
		uint64_t i, partLen, index;
		// compute number of bytes mod 64 (number of bits 64*8 = 512)
		// get count of bits from previous blocks, if exist.
		index = this->md5_context.count / 8 % BLOCK_SIZE;
		// multiply msg_len on 8 (2 ^ 3, or bite-wise shift left on 3)
		// get bits count
		this->md5_context.count += (static_cast<uint64_t>(msg_len) << 3);
		partLen = BLOCK_SIZE - index; // get part of length of previous block
		if (msg_len >= partLen)
		{
			// copy begin of message to end of previous block (concatenation)
			// if no data in buffer before, then it would be simple first
			// chunk of hash.
			std::memcpy(&(this->md5_context.buffer[index]), msg, partLen);
			// transform this block
			this->transform(this->md5_context.buffer);
			// transform every 64-byte chunk
			// variable 'i' collects number of bits
			for (i = partLen; i + BLOCK_SIZE <= msg_len; i += BLOCK_SIZE)
			{
				this->transform(&msg[i]);
			}
			// no non-transformed data in buffer
			index = 0;
		}
		else
		{
			i = 0; // no bits collected
		}
		// copy buffer residue to finilize or next update
		std::memcpy(&this->md5_context.buffer[index], &msg[i], msg_len - i);
	}
	void hash_md5::finalize() {
		uint8_t padding[64];
		std::memset(padding, 0, sizeof(uint8_t) * 64);
		padding[0] = 0x80; // 1000 0000 binary. only uint8_t
		if (!this->bFinalized) {
			uint8_t bits[8];
			uint64_t index, padLen;
			// unpack uint64_t to 8x uint8_t, based on 
			// uint32_t->uint8_t unpacking
			for (uint16_t i = 0, j = 0; j < 64; ++i, j += 8) 
			{
				bits[i] = (this->md5_context.count >> j) & 0xFF;
			}
			index = this->md5_context.count / 8 % BLOCK_SIZE;
			padLen = (index < 56) ? 
				(56 - index) : 
				(120 - index);
			// padding space up to 56 mod 64
			this->update(padding, padLen);
			// append length
			this->update(bits, 8);
			// decode A, B, C, D words to
			this->encode(this->md5_context.state, this->md5_context.digest, 16);
			this->bFinalized = true;
			this->md5_orig = this->resultToString(&md5_context);
		}
	}
	void hash_md5::transform(const uint8_t* block) {
		uint32_t 
			A = this->md5_context.state[0], 
			B = this->md5_context.state[1],
			C = this->md5_context.state[2], 
			D = this->md5_context.state[3];
		uint32_t x[16];
		this->decode(block, x, BLOCK_SIZE);
		// round 1
		this->FF(A, B, C, D, x[0], R1_C1, T[0]);
		this->FF(D, A, B, C, x[1], R1_C2, T[1]);
		this->FF(C, D, A, B, x[2], R1_C3, T[2]);
		this->FF(B, C, D, A, x[3], R1_C4, T[3]);

		this->FF(A, B, C, D, x[4], R1_C1, T[4]);
		this->FF(D, A, B, C, x[5], R1_C2, T[5]);
		this->FF(C, D, A, B, x[6], R1_C3, T[6]);
		this->FF(B, C, D, A, x[7], R1_C4, T[7]);

		this->FF(A, B, C, D, x[8], R1_C1, T[8]);
		this->FF(D, A, B, C, x[9], R1_C2, T[9]);
		this->FF(C, D, A, B, x[10], R1_C3, T[10]);
		this->FF(B, C, D, A, x[11], R1_C4, T[11]);

		this->FF(A, B, C, D, x[12], R1_C1, T[12]);
		this->FF(D, A, B, C, x[13], R1_C2, T[13]);
		this->FF(C, D, A, B, x[14], R1_C3, T[14]);
		this->FF(B, C, D, A, x[15], R1_C4, T[15]);

		// round 2
		this->GG(A, B, C, D, x[1], R2_C1, T[16]);
		this->GG(D, A, B, C, x[6], R2_C2, T[17]);
		this->GG(C, D, A, B, x[11], R2_C3, T[18]);
		this->GG(B, C, D, A, x[0], R2_C4, T[19]);

		this->GG(A, B, C, D, x[5], R2_C1, T[20]);
		this->GG(D, A, B, C, x[10], R2_C2, T[21]);
		this->GG(C, D, A, B, x[15], R2_C3, T[22]);
		this->GG(B, C, D, A, x[4], R2_C4, T[23]);

		this->GG(A, B, C, D, x[9], R2_C1, T[24]);
		this->GG(D, A, B, C, x[14], R2_C2, T[25]);
		this->GG(C, D, A, B, x[3], R2_C3, T[26]);
		this->GG(B, C, D, A, x[8], R2_C4, T[27]);

		this->GG(A, B, C, D, x[13], R2_C1, T[28]);
		this->GG(D, A, B, C, x[2], R2_C2, T[29]);
		this->GG(C, D, A, B, x[7], R2_C3, T[30]);
		this->GG(B, C, D, A, x[12], R2_C4, T[31]);

		// round 3
		this->HH(A, B, C, D, x[5], R3_C1, T[32]);
		this->HH(D, A, B, C, x[8], R3_C2, T[33]);
		this->HH(C, D, A, B, x[11], R3_C3, T[34]);
		this->HH(B, C, D, A, x[14], R3_C4, T[35]);

		this->HH(A, B, C, D, x[1], R3_C1, T[36]);
		this->HH(D, A, B, C, x[4], R3_C2, T[37]);
		this->HH(C, D, A, B, x[7], R3_C3, T[38]);
		this->HH(B, C, D, A, x[10], R3_C4, T[39]);

		this->HH(A, B, C, D, x[13], R3_C1, T[40]);
		this->HH(D, A, B, C, x[0], R3_C2, T[41]);
		this->HH(C, D, A, B, x[3], R3_C3, T[42]);
		this->HH(B, C, D, A, x[6], R3_C4, T[43]);

		this->HH(A, B, C, D, x[9], R3_C1, T[44]);
		this->HH(D, A, B, C, x[12], R3_C2, T[45]);
		this->HH(C, D, A, B, x[15], R3_C3, T[46]);
		this->HH(B, C, D, A, x[2], R3_C4, T[47]);

		// round 4
		this->II(A, B, C, D, x[0], R4_C1, T[48]);
		this->II(D, A, B, C, x[7], R4_C2, T[49]);
		this->II(C, D, A, B, x[14], R4_C3, T[50]);
		this->II(B, C, D, A, x[5], R4_C4, T[51]);

		this->II(A, B, C, D, x[12], R4_C1, T[52]);
		this->II(D, A, B, C, x[3], R4_C2, T[53]);
		this->II(C, D, A, B, x[10], R4_C3, T[54]);
		this->II(B, C, D, A, x[1], R4_C4, T[55]);

		this->II(A, B, C, D, x[8], R4_C1, T[56]);
		this->II(D, A, B, C, x[15], R4_C2, T[57]);
		this->II(C, D, A, B, x[6], R4_C3, T[58]);
		this->II(B, C, D, A, x[13], R4_C4, T[59]);

		this->II(A, B, C, D, x[4], R4_C1, T[60]);
		this->II(D, A, B, C, x[11], R4_C2, T[61]);
		this->II(C, D, A, B, x[2], R4_C3, T[62]);
		this->II(B, C, D, A, x[9], R4_C4, T[63]);

		// finilize block calculation
		this->md5_context.state[0] += A;
		this->md5_context.state[1] += B;
		this->md5_context.state[2] += C;
		this->md5_context.state[3] += D;
		// zeroize sensetive information
		std::memset(x, 0, sizeof(x));
	}
	void hash_md5::encode(const uint32_t in[], uint8_t out[], uint32_t len) {
		for (uint32_t i = 0, j = 0; j < len; i++, j += 4) {
			out[j] = in[i] & 0xFF;
			out[j + 1] = (in[i] >> 8) & 0xFF;
			out[j + 2] = (in[i] >> 16) & 0xFF;
			out[j + 3] = (in[i] >> 24) & 0xFF;
		}
	}
	void hash_md5::decode(const uint8_t in[], uint32_t out[], uint32_t len) {
		for (uint32_t i = 0, j = 0; j < len; i++, j += 4) {
			out[i] = (static_cast<uint32_t>(in[j])) |
				(static_cast<uint32_t>(in[j + 1]) << 8) |
				(static_cast<uint32_t>(in[j + 2]) << 16) |
				(static_cast<uint32_t>(in[j + 3]) << 24);
		}
	}
	inline uint32_t hash_md5::F(uint32_t x, uint32_t y, uint32_t z) {
		return x & y | ~x & z;
	}
	inline uint32_t hash_md5::G(uint32_t x, uint32_t y, uint32_t z) {
		return x & z | y & ~z;
	}
	inline uint32_t hash_md5::H(uint32_t x, uint32_t y, uint32_t z) {
		return x ^ y ^ z;
	}
	inline uint32_t hash_md5::I(uint32_t x, uint32_t y, uint32_t z) {
		return y ^ (x | ~z);
	}
	inline uint32_t hash_md5::rotate_left(uint32_t x, uint32_t n) {
		return (x << n) | (x >> ((uint32_t)32 - n));
	}
	inline void hash_md5::FF(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, 
		uint32_t x, uint32_t s, uint32_t ac) {
		a = this->rotate_left(a + this->F(b, c, d) + x + ac, s) + b;
	}
	inline void hash_md5::GG(uint32_t &a, uint32_t b, uint32_t c, uint32_t d,
		uint32_t x, uint32_t s, uint32_t ac) {
		a = this->rotate_left(a + this->G(b, c, d) + x + ac, s) + b;
	}
	inline void hash_md5::HH(uint32_t &a, uint32_t b, uint32_t c, uint32_t d,
		uint32_t x, uint32_t s, uint32_t ac) {
		a = this->rotate_left(a + this->H(b, c, d) + x + ac, s) + b;
	}
	inline void hash_md5::II(uint32_t &a, uint32_t b, uint32_t c, uint32_t d,
		uint32_t x, uint32_t s, uint32_t ac) {
		a = this->rotate_left(a + this->I(b, c, d) + x + ac, s) + b;
	}
}