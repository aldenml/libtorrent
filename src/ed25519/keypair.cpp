#include "libtorrent/ed25519.hpp"
#include "libtorrent/hasher512.hpp"
#include "libtorrent/ed25519/ge.hpp"

namespace libtorrent {
namespace ed25519
{

	void ed25519_create_keypair(ed25519_public_key& public_key
		, ed25519_private_key& private_key, ed25519_seed const& seed)
	{
		auto public_key_ptr = reinterpret_cast<unsigned char*>(public_key.data());
		auto private_key_ptr = reinterpret_cast<unsigned char*>(private_key.data());

		ge_p3 A;

		hasher512 hash(seed);
		std::memcpy(private_key_ptr, hash.final().data(), 64);
		private_key[0] &= 248;
		private_key[31] &= 63;
		private_key[31] |= 64;


		ge_scalarmult_base(&A, private_key_ptr);
		ge_p3_tobytes(public_key_ptr, &A);
	}

}}
