#pragma once
#include "analyser.h"
#include <vector>
#include <memory>
#include <optional>

#define NAME_SIZE 1024
#define NAME_SIZE_SHORT 64
#define NAME_WIDE_MASK 0x1
#define NAME_INDEX_SHIFT 1

namespace pubg
{
	extern uint8_t* xe_decrypt_container;
	extern bool is_init;
	uintptr_t xe_decrypt(const uintptr_t encrypted);
	bool xe_init(const uintptr_t decrypt_ptr);

	template <typename T>
	struct Decryptor {
		static_assert(std::is_same<T, int32_t>::value | std::is_same<T, int64_t>::value, "Type error.");

		bool ror;
		T xor_key[2];

		uint8_t rval;
		uint8_t sval;
		uint8_t offset;

		bool is_valid() const {
			return xor_key[0] && xor_key[1] /*&& rval*/ && sval && offset;
		}

		T decrypt(T encrypted) const {
			T result = T{};

			if constexpr (std::is_same<T, int64_t>::value)
				result = ror ? _rotr64(encrypted ^ xor_key[0], rval) : _rotl64(encrypted ^ xor_key[0], rval);
			else
				result = ror ? _rotr(encrypted ^ xor_key[0], rval) : _rotl(encrypted ^ xor_key[0], rval);

			return result ^ (result << sval) ^ xor_key[1];
		}
	};

	using Decryptor32 = Decryptor<int32_t>;
	using Decryptor64 = Decryptor<int64_t>;

	struct EncryptedPtr {
		uint64_t encrypted_obj;

		operator uintptr_t() const {
			return pubg::xe_decrypt(encrypted_obj);
		}
		operator void* () const {
			return reinterpret_cast<void*>(pubg::xe_decrypt(encrypted_obj));
		}
		operator uint8_t* () const {
			return reinterpret_cast<uint8_t*>(pubg::xe_decrypt(encrypted_obj));
		}
		operator bool() const {
			return encrypted_obj != 0;
		}
		operator uint32_t() const {
			return static_cast<uint32_t>(pubg::xe_decrypt(encrypted_obj));
		}
	};

	using decryptor_list = std::tuple<std::unique_ptr<Decryptor32>, std::unique_ptr<Decryptor32>, std::unique_ptr<Decryptor32>, std::unique_ptr<Decryptor64>, std::unique_ptr<Decryptor64>>;
	std::optional<decryptor_list> get_decryptors(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end);
}