#ifndef LIBTORRENT_ED25519_HPP
#define LIBTORRENT_ED25519_HPP

#include <libtorrent/config.hpp>
#include <libtorrent/span.hpp>

#include <array>
#include <memory>

namespace libtorrent {
namespace ed25519
{
	using ed25519_seed = std::array<char, 32>;

	TORRENT_EXPORT void ed25519_create_seed(ed25519_seed& seed);

enum
{
	ed25519_seed_size = 32,
	ed25519_private_key_size = 64,
	ed25519_public_key_size = 32,
	ed25519_signature_size = 64,
	ed25519_scalar_size = 32,
	ed25519_shared_secret_size = 32
};

extern "C" {

// TODO: 3 wrap these into C++ calls with proper types (dht::signature,
// public_key and secret_key)
void TORRENT_EXPORT ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void TORRENT_EXPORT ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
int TORRENT_EXPORT ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
void TORRENT_EXPORT ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
void TORRENT_EXPORT ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);

}
}}
#endif // LIBTORRENT_ED25519_HPP
