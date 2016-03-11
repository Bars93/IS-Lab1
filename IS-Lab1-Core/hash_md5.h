#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace crypto_hash {
	const uint16_t BLOCK_SIZE = 64;
	const uint16_t ROUND_CNT = 4;
	typedef struct __md5_states_t {
		uint32_t A, B, C, D;
	} md5_states;
	class hash_md5
	{
		uint64_t bitDiffs[ROUND_CNT];
		uint32_t T[64];
		struct __md5_context_t {
			std::vector<md5_states> vStates;
			uint32_t state[4];
			uint8_t buffer[BLOCK_SIZE];
			uint8_t digest[16];
			std::string textRes;
			uint64_t count;		
			bool bFinalized;
			__md5_context_t();
		} md5_context, md5_avalanch;	
		std::vector<md5_states> vStates_orig, vStates_mod;
		uint64_t uiAvEffectBitNum;
		bool bAvalancheEffect;
		bool bAvEffectBitChangeEnabled;

		void encode(const uint32_t in[], uint8_t out[], uint32_t len);
		void decode(const uint8_t in[], uint32_t out[], uint32_t len);
		inline uint32_t F(uint32_t x, uint32_t y, uint32_t z);
		inline uint32_t G(uint32_t x, uint32_t y, uint32_t z);
		inline uint32_t H(uint32_t x, uint32_t y, uint32_t z);
		inline uint32_t I(uint32_t x, uint32_t y, uint32_t z);
		inline uint32_t rotate_left(uint32_t x, uint32_t n);
		inline void FF(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, 
			uint32_t x, uint32_t s, uint32_t ac);
		inline void GG(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, 
			uint32_t x, uint32_t s, uint32_t ac);
		inline void HH(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, 
			uint32_t x, uint32_t s, uint32_t ac);
		inline void II(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, 
			uint32_t x, uint32_t s, uint32_t ac);

		void init();
		inline void T_init();

		void update(__md5_context_t *ctx, char * msg, const uint32_t msg_len);
		void update(__md5_context_t *ctx, unsigned char *msg, const uint32_t msg_len);
		void transform(__md5_context_t *ctx, const uint8_t *block);
		void finalize(__md5_context_t *ctx);
		void resultToString(__md5_context_t *ctx);
		//void avalancheProcessing();
		//void change_msg_bit(unsigned char *buf, const uint64_t current_flow);
	public:
		hash_md5();
		void enable_avalanche_research(const uint64_t _bitChanged);
		//void disable_avalanche_research();
		hash_md5(std::string);
		std::string digestString(std::string);
		// std::string digestFile(const char* filename);
		// std::string avalanch_digestString();
		~hash_md5();
	};
}
