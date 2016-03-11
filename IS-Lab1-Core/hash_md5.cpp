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
	uint32_t bitCount(const uint32_t &num) {
		uint32_t i = num;
		i = i - ((i >> 1) & 0x55555555);
		i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
		return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
	}
	inline uint64_t bitDifference(const uint32_t &a, const uint32_t &b) {
		return static_cast<uint64_t>(bitCount(a ^ b));
	}
	const enum R1_CONSTANTS : uint8_t
	{
		R1_C1 = 7, R1_C2 = 12, R1_C3 = 17, R1_C4 = 22
	};
	const enum R2_CONSTANTS : uint8_t
	{
		R2_C1 = 5, R2_C2 = 9, R2_C3 = 14, R2_C4 = 20
	};
	const enum R3_CONSTANTS : uint8_t
	{
		R3_C1 = 4, R3_C2 = 11, R3_C3 = 16, R3_C4 = 23
	};
	const enum R4_CONSTANTS : uint8_t
	{
		R4_C1 = 6, R4_C2 = 10, R4_C3 = 15, R4_C4 = 21
	};
	hash_md5::hash_md5() :
		bAvalancheEffect(false),
		bAvEffectBitChangeEnabled(false),
		uiAvEffectBitNum(static_cast<uint64_t>(0))
	{
		this->init();
	}
	hash_md5::hash_md5(std::string _str) :
		bAvalancheEffect(false),
		bAvEffectBitChangeEnabled(false),
		uiAvEffectBitNum(static_cast<uint64_t>(0))
	{
		this->init();
		this->update(&(this->md5_context), const_cast<char*>(_str.c_str()), _str.length());
		this->finalize(&(this->md5_context));
	}

	hash_md5::~hash_md5()
	{
	}
	void hash_md5::init() {
		this->T_init();
		std::memset(bitDiffs, 0, sizeof(uint64_t) * ROUND_CNT);
		this->md5_context.state[0] = this->md5_avalanch.state[0] = STATE_INIT_0;
		this->md5_context.state[1] = this->md5_avalanch.state[1] = STATE_INIT_1;
		this->md5_context.state[2] = this->md5_avalanch.state[2] = STATE_INIT_2;
		this->md5_context.state[3] = this->md5_avalanch.state[3] = STATE_INIT_3;
	}
	void hash_md5::T_init() {
		std::memset(&(this->T), 0, sizeof(uint32_t) * 64);
		for (uint16_t ind = 0; ind < 64; ++ind) {
			this->T[ind] =
				static_cast<uint32_t>(abs(INIT_UINT32_MAX *
					sin(static_cast<double>(ind + 1))));
		}
	}
	void hash_md5::update(__md5_context_t *ctx, char *msg, const uint32_t msg_len) {
		this->update(ctx, reinterpret_cast<unsigned char*>(msg), msg_len);
	}
	void hash_md5::update(__md5_context_t *ctx,
		unsigned char *msg, const uint32_t msg_len) {
		uint64_t i, partLen, index;
		// compute number of bytes mod 64 (number of bits 64*8 = 512)
		// get count of bits from previous blocks, if exist.
		//index = this->md5_context.count / 8 % BLOCK_SIZE;
		// x % N ~ x & (N - 1)
		index = (ctx->count >> 3) & static_cast<uint64_t>(BLOCK_SIZE - 1);
		if (this->bAvEffectBitChangeEnabled &&
			this->uiAvEffectBitNum >= ctx->count &&
			this->uiAvEffectBitNum < (msg_len << 3)) {
			// calculation offset (!!!)
			// byte position
			uint32_t byte_pos = (this->uiAvEffectBitNum >> 3) - (ctx->count >> 3);
			// bit offset
			uint16_t bit_offset = (this->uiAvEffectBitNum) & static_cast<uint16_t>(0x0007);
			// bit changing
			// move 1 of 1000 0000 to end
			msg[byte_pos] ^= (static_cast<uint8_t>(0x80) >> bit_offset); 
			this->bAvEffectBitChangeEnabled = false;
		}
		// multiply msg_len on 8 (2 ^ 3, or bite-wise shift left on 3)
		// get bits count
		ctx->count += (static_cast<uint64_t>(msg_len) << 3);
		partLen = BLOCK_SIZE - index; // get part of length to end of previous block

		if (msg_len >= partLen)
		{
			// copy begin of message to end of previous block (concatenation)
			// if no data in buffer before, then it would be simple first
			// chunk of hash.
			std::memcpy(&(ctx->buffer[index]), msg, partLen);
			// transform this block
			this->transform(ctx, ctx->buffer);
			// transform every 64-byte chunk
			// variable 'i' collects number of bits
			for (i = partLen; i + BLOCK_SIZE <= msg_len; i += BLOCK_SIZE)
			{
				this->transform(ctx, &msg[i]);
			}
			// no non-transformed data in buffer
			index = 0;
		}
		else
		{
			i = 0; // no bits collected
		}
		// copy buffer residue to finilize or next update
		std::memcpy(&(ctx->buffer[index]), &msg[i], msg_len - i);
	}
	void hash_md5::finalize(__md5_context_t *ctx) {
		uint8_t padding[64];
		std::memset(padding, 0, sizeof(uint8_t) * 64);
		padding[0] = 0x80; // 1000 0000 binary. only uint8_t
		if (!ctx->bFinalized) {
			uint8_t bits[8];
			uint64_t index, padLen;
			// unpack uint64_t to 8x uint8_t, based on 
			// uint32_t->4x uint8_t unpacking
			for (uint16_t i = 0, j = 0; j < 64; ++i, j += 8)
			{
				bits[i] = (ctx->count >> j) & 0xFF;
			}
			index = (ctx->count >> 3) & static_cast<uint64_t>(BLOCK_SIZE - 1);
			// calculation of padding for current block up to 56
			// or next block (64 + 56 = 120) up to 56
			padLen = (index < 56) ? (56 - index) : (120 - index);
			// padding space up to 56 mod 64
			this->update(ctx, padding, padLen);
			// append length
			this->update(ctx, bits, 8);
			// decode A, B, C, D words to
			this->encode(ctx->state, ctx->digest, 16);
			ctx->bFinalized = true;
			this->resultToString(ctx);
		}
	}
	void hash_md5::transform(__md5_context_t *ctx, const uint8_t* block) {
		md5_states states;
		states.A = ctx->state[0],
		states.B = ctx->state[1],
		states.C = ctx->state[2],
		states.D = ctx->state[3];
		uint32_t x[16];
		this->decode(block, x, BLOCK_SIZE);
		// round 1
		this->FF(states.A, states.B, states.C, states.D, x[0], R1_C1, T[0]);
		this->FF(states.D, states.A, states.B, states.C, x[1], R1_C2, T[1]);
		this->FF(states.C, states.D, states.A, states.B, x[2], R1_C3, T[2]);
		this->FF(states.B, states.C, states.D, states.A, x[3], R1_C4, T[3]);

		this->FF(states.A, states.B, states.C, states.D, x[4], R1_C1, T[4]);
		this->FF(states.D, states.A, states.B, states.C, x[5], R1_C2, T[5]);
		this->FF(states.C, states.D, states.A, states.B, x[6], R1_C3, T[6]);
		this->FF(states.B, states.C, states.D, states.A, x[7], R1_C4, T[7]);

		this->FF(states.A, states.B, states.C, states.D, x[8], R1_C1, T[8]);
		this->FF(states.D, states.A, states.B, states.C, x[9], R1_C2, T[9]);
		this->FF(states.C, states.D, states.A, states.B, x[10], R1_C3, T[10]);
		this->FF(states.B, states.C, states.D, states.A, x[11], R1_C4, T[11]);

		this->FF(states.A, states.B, states.C, states.D, x[12], R1_C1, T[12]);
		this->FF(states.D, states.A, states.B, states.C, x[13], R1_C2, T[13]);
		this->FF(states.C, states.D, states.A, states.B, x[14], R1_C3, T[14]);
		this->FF(states.B, states.C, states.D, states.A, x[15], R1_C4, T[15]);

		// save state
		if (this->bAvalancheEffect) {
			ctx->vStates.push_back(states);
		}
		// round 2
		this->GG(states.A, states.B, states.C, states.D, x[1], R2_C1, T[16]);
		this->GG(states.D, states.A, states.B, states.C, x[6], R2_C2, T[17]);
		this->GG(states.C, states.D, states.A, states.B, x[11], R2_C3, T[18]);
		this->GG(states.B, states.C, states.D, states.A, x[0], R2_C4, T[19]);

		this->GG(states.A, states.B, states.C, states.D, x[5], R2_C1, T[20]);
		this->GG(states.D, states.A, states.B, states.C, x[10], R2_C2, T[21]);
		this->GG(states.C, states.D, states.A, states.B, x[15], R2_C3, T[22]);
		this->GG(states.B, states.C, states.D, states.A, x[4], R2_C4, T[23]);

		this->GG(states.A, states.B, states.C, states.D, x[9], R2_C1, T[24]);
		this->GG(states.D, states.A, states.B, states.C, x[14], R2_C2, T[25]);
		this->GG(states.C, states.D, states.A, states.B, x[3], R2_C3, T[26]);
		this->GG(states.B, states.C, states.D, states.A, x[8], R2_C4, T[27]);

		this->GG(states.A, states.B, states.C, states.D, x[13], R2_C1, T[28]);
		this->GG(states.D, states.A, states.B, states.C, x[2], R2_C2, T[29]);
		this->GG(states.C, states.D, states.A, states.B, x[7], R2_C3, T[30]);
		this->GG(states.B, states.C, states.D, states.A, x[12], R2_C4, T[31]);
		// save state
		if (this->bAvalancheEffect) {
			ctx->vStates.push_back(states);
		}
		// round 3
		this->HH(states.A, states.B, states.C, states.D, x[5], R3_C1, T[32]);
		this->HH(states.D, states.A, states.B, states.C, x[8], R3_C2, T[33]);
		this->HH(states.C, states.D, states.A, states.B, x[11], R3_C3, T[34]);
		this->HH(states.B, states.C, states.D, states.A, x[14], R3_C4, T[35]);

		this->HH(states.A, states.B, states.C, states.D, x[1], R3_C1, T[36]);
		this->HH(states.D, states.A, states.B, states.C, x[4], R3_C2, T[37]);
		this->HH(states.C, states.D, states.A, states.B, x[7], R3_C3, T[38]);
		this->HH(states.B, states.C, states.D, states.A, x[10], R3_C4, T[39]);

		this->HH(states.A, states.B, states.C, states.D, x[13], R3_C1, T[40]);
		this->HH(states.D, states.A, states.B, states.C, x[0], R3_C2, T[41]);
		this->HH(states.C, states.D, states.A, states.B, x[3], R3_C3, T[42]);
		this->HH(states.B, states.C, states.D, states.A, x[6], R3_C4, T[43]);

		this->HH(states.A, states.B, states.C, states.D, x[9], R3_C1, T[44]);
		this->HH(states.D, states.A, states.B, states.C, x[12], R3_C2, T[45]);
		this->HH(states.C, states.D, states.A, states.B, x[15], R3_C3, T[46]);
		this->HH(states.B, states.C, states.D, states.A, x[2], R3_C4, T[47]);
		// save state
		if (this->bAvalancheEffect) {
			ctx->vStates.push_back(states);
		}
		// round 4
		this->II(states.A, states.B, states.C, states.D, x[0], R4_C1, T[48]);
		this->II(states.D, states.A, states.B, states.C, x[7], R4_C2, T[49]);
		this->II(states.C, states.D, states.A, states.B, x[14], R4_C3, T[50]);
		this->II(states.B, states.C, states.D, states.A, x[5], R4_C4, T[51]);

		this->II(states.A, states.B, states.C, states.D, x[12], R4_C1, T[52]);
		this->II(states.D, states.A, states.B, states.C, x[3], R4_C2, T[53]);
		this->II(states.C, states.D, states.A, states.B, x[10], R4_C3, T[54]);
		this->II(states.B, states.C, states.D, states.A, x[1], R4_C4, T[55]);

		this->II(states.A, states.B, states.C, states.D, x[8], R4_C1, T[56]);
		this->II(states.D, states.A, states.B, states.C, x[15], R4_C2, T[57]);
		this->II(states.C, states.D, states.A, states.B, x[6], R4_C3, T[58]);
		this->II(states.B, states.C, states.D, states.A, x[13], R4_C4, T[59]);

		this->II(states.A, states.B, states.C, states.D, x[4], R4_C1, T[60]);
		this->II(states.D, states.A, states.B, states.C, x[11], R4_C2, T[61]);
		this->II(states.C, states.D, states.A, states.B, x[2], R4_C3, T[62]);
		this->II(states.B, states.C, states.D, states.A, x[9], R4_C4, T[63]);
		// save state
		if (this->bAvalancheEffect) {
			ctx->vStates.push_back(states);
		}
		// finilize block calculation
		ctx->state[0] += states.A;
		ctx->state[1] += states.B;
		ctx->state[2] += states.C;
		ctx->state[3] += states.D;
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
	hash_md5::__md5_context_t::__md5_context_t() :
		textRes(""),
		vStates(),
		count(static_cast<uint64_t>(0)),
		bFinalized(false)
	{
		memset(&(this->buffer), 0, sizeof(uint8_t) * BLOCK_SIZE);
		memset(&(this->state), 0, sizeof(uint32_t) * 4);
		memset(&(this->digest), 0, sizeof(uint8_t) * 16);
	}
	void hash_md5::resultToString(__md5_context_t *ctx) {
		if (!ctx->bFinalized) {
			ctx->textRes = std::string("");
		}
		else {
			char buf[33];
			for (int i = 0; i < 16; ++i) {
				std::sprintf(buf + i * 2, "%02x", ctx->digest[i]);
			}
			buf[32] = '\0';
			ctx->textRes = std::string(buf);
		}
	}
	std::string hash_md5::digestString(std::string str) {
		this->init();
		this->update(&(this->md5_context), const_cast<char*>(str.c_str()), 
			str.length());
		this->finalize(&(this->md5_context));
		if (this->bAvalancheEffect) {
			this->bAvEffectBitChangeEnabled = true;
			this->update(&(this->md5_avalanch), const_cast<char*>(str.c_str()),
				str.length());
			this->finalize(&(this->md5_avalanch));
			size_t md5_ctx_vStates_size = this->md5_context.vStates.size(),
				md5_avf_vStates_size = this->md5_avalanch.vStates.size();
			
			if (md5_ctx_vStates_size != 0 &&
				md5_avf_vStates_size != 0 &&
				(md5_ctx_vStates_size % ROUND_CNT) == 0 &&
				(md5_avf_vStates_size % ROUND_CNT) == 0 &&
				md5_ctx_vStates_size == md5_avf_vStates_size) {
				uint16_t nRound = 0;
				std::vector<md5_states>::iterator it_ctx =
					this->md5_context.vStates.begin();
				std::vector<md5_states>::iterator it_avef =
					this->md5_avalanch.vStates.begin();
				do {
					bitDiffs[nRound] += bitDifference(it_ctx->A, it_avef->A);
					bitDiffs[nRound] += bitDifference(it_ctx->B, it_avef->B);
					bitDiffs[nRound] += bitDifference(it_ctx->C, it_avef->C);
					bitDiffs[nRound] += bitDifference(it_ctx->D, it_avef->D);
					nRound = (++nRound) & (ROUND_CNT - 1);
					it_ctx++, it_avef++;
				} while (it_ctx != this->md5_context.vStates.end());
			}
		}
		return this->md5_context.textRes;
	}
	void hash_md5::enable_avalanche_research(const uint64_t _bitChanged) {
		if (!this->bAvalancheEffect)
			this->bAvalancheEffect = true;
		this->uiAvEffectBitNum = _bitChanged;
	}
}