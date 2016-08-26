#include "libtorrent/config.hpp"
#include "libtorrent/error_code.hpp"
#include "libtorrent/random.hpp"
#include "libtorrent/ed25519.hpp"

#if TORRENT_USE_CRYPTOAPI
#include <windows.h>
#include <wincrypt.h>

#elif defined TORRENT_USE_LIBCRYPTO
extern "C" {
#include <openssl/rand.h>
#include <openssl/err.h>
}

#endif

namespace libtorrent {
namespace ed25519
{
	void ed25519_create_seed(ed25519_seed& seed)
	{
#if TORRENT_USE_CRYPTOAPI
		HCRYPTPROV prov;

		if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
#ifndef BOOST_NO_EXCEPTIONS
			throw system_error(error_code(GetLastError(), system_category()));
#else
			std::terminate();
#endif
		}

		if (!CryptGenRandom(prov, 32, reinterpret_cast<BYTE const*>(seed.data())))
		{
			CryptReleaseContext(prov, 0);
#ifndef BOOST_NO_EXCEPTIONS
			throw system_error(error_code(GetLastError(), system_category()));
#else
			std::terminate();
#endif
		}

		CryptReleaseContext(prov, 0);
#elif defined TORRENT_USE_LIBCRYPTO
		int r = RAND_bytes(reinterpret_cast<unsigned char*>(seed.data())
			, int(seed.size()));
		if (r != 1)
		{
#ifndef BOOST_NO_EXCEPTIONS
			throw system_error(error_code(ERR_get_error(), system_category()));
#else
			std::terminate();
#endif
		}
#else
		std::uint32_t s = random(0xffffffff);
		std::independent_bits_engine<std::mt19937, 8, std::uint8_t> generator(s);
		std::generate(seed.begin(), seed.end(), std::ref(generator));
#endif
	}

}}
