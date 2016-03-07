#pragma once
#include <cstdint>
#include <string>

namespace crypto_hash {
	const uint16_t BLOCK_SIZE = 64;
	typedef enum __hash_md5_result_t  : uint8_t {
		HASH_MD5_RESULT_OK = 0,
		HASH_MD5_FILE_IO_ERROR,
		HASH_MD5_NO_DATA,
		HASH_MD5_NO_CALC
	} hash_md5_result;

	class hash_md5
	{
		uint32_t T[64];
		struct __md5_context_t {
			uint32_t state[4];
			uint64_t count;
			uint8_t buffer[BLOCK_SIZE];
			uint8_t digest[16];
		} md5_context;	
		uint64_t uiAvEffectBitNum;
		bool bFinalized;
		bool bAvalancheEffect;
		hash_md5_result eError;
		
		void encode(const uint32_t in[], uint8_t out[], uint32_t len);
		void decode(const uint8_t in[], uint32_t out[], uint32_t len);
		//const char *getResultString();
		//hash_md5_result update();
		inline uint32_t F(uint32_t x, uint32_t y, uint32_t z);
		inline uint32_t G(uint32_t x, uint32_t y, uint32_t z);
		inline uint32_t H(uint32_t x, uint32_t y, uint32_t z);
		inline uint32_t I(uint32_t x, uint32_t y, uint32_t z);

		inline uint32_t rotate_left(uint32_t x, uint32_t n);
		inline void T_init();

		inline void FF(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, 
			uint32_t x, uint32_t s, uint32_t ac);
		inline void GG(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, 
			uint32_t x, uint32_t s, uint32_t ac);
		inline void HH(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, 
			uint32_t x, uint32_t s, uint32_t ac);
		inline void II(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, 
			uint32_t x, uint32_t s, uint32_t ac);

		void transform(const uint8_t *block);
		void update(const char * msg, const uint32_t msg_len);
		void update(const unsigned char *msg, const uint32_t msg_len);
		void finalize();
		void init();
		std::string resultToString(const __md5_context_t *ctx) {
			if (!this->bFinalized) {
				return std::string("");
			}
			char buf[33];
			for (int i = 0; i < 16; ++i) {
				sprintf(buf + i * 2, "%02x", ctx->digest[i]);
			}
			buf[32] = '\0';
			return std::string(buf);
		}
	public:
		std::string md5_orig, md5_mod;
		hash_md5();
		//void enable_avalanche_research(const uint64_t _bitChanged);
		hash_md5(const std::string&);
		std::string digestString(std::string str) {
			this->init();
			this->update(str.c_str(), str.length());
			this->finalize();
			return this->md5_orig;
		}
		// std::string avalanch_md5();
		hash_md5_result getResult();
		~hash_md5();
	};
}
