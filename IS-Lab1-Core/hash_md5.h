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
			BYTE digest[16];
		} md5_context;

	public:
		hash_md5();
		~hash_md5();
	};
}
