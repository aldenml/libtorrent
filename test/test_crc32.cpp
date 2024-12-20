/*

Copyright (c) 2014-2017, 2020-2021, Arvid Norberg
Copyright (c) 2016, 2020, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libtorrent/aux_/crc32c.hpp"
#include "libtorrent/aux_/cpuid.hpp"
#include "libtorrent/assert.hpp"
#include "libtorrent/aux_/byteswap.hpp"
#include "test.hpp"

#include "libtorrent/aux_/disable_warnings_push.hpp"
#include <boost/crc.hpp>
#include "libtorrent/aux_/disable_warnings_pop.hpp"

namespace {
std::uint32_t crc32c_buffer(char const* buf, int const len)
{
	boost::crc_optimal<32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc;
	crc.process_block(buf, buf + len);
	return crc.checksum();
}
}

TORRENT_TEST(crc32)
{
	using namespace lt;

	std::uint32_t out;
	std::uint32_t out2;

	std::uint32_t in1 = aux::host_to_network(0xeffea55a);
	out = aux::crc32c_32(in1);
	TEST_EQUAL(out, 0x5ee3b9d5);

	std::uint64_t buf[4];
	memcpy(buf, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
		"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32);

	// https://tools.ietf.org/html/rfc3720#appendix-B.4
	out = aux::crc32c(buf, 4);
	TEST_EQUAL(out, 0x8a9136aaU);
	out2 = crc32c_buffer(reinterpret_cast<char const*>(buf), 32);
	TEST_EQUAL(out, out2);

	memcpy(buf, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 32);
	out = aux::crc32c(buf, 4);
	TEST_EQUAL(out, 0x62a8ab43U);
	out2 = crc32c_buffer(reinterpret_cast<char const*>(buf), 32);
	TEST_EQUAL(out, out2);

	memcpy(buf, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 32);
	out = aux::crc32c(buf, 4);
	TEST_EQUAL(out, 0x46dd794eU);
	out2 = crc32c_buffer(reinterpret_cast<char const*>(buf), 32);
	TEST_EQUAL(out, out2);

#if !TORRENT_HAS_ARM
	TORRENT_ASSERT(!aux::arm_crc32c_support);
#endif
}
