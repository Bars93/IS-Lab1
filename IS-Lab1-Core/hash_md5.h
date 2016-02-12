#pragma once
#include <stdint.h>
namespace crypto_hash {
	typedef uint8_t BYTE;
	typedef uint16_t WORD;
	typedef uint32_t DWORD;
	typedef uint64_t QWORD;
	class hash_md5
	{
		BYTE *bBufptr;
		QWORD bufLen;
		
		typedef struct __md5_context_t {
			DWORD buffer[4];
			QWORD count[2];
			BYTE padding[64];
		} md5_context;

		void to_byte();
		void to_dword();
	public:
		hash_md5();
		~hash_md5();
	};
}
