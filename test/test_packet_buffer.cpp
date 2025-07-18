/*

Copyright (c) 2013, 2015-2017, 2019-2021, Arvid Norberg
Copyright (c) 2018, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "test.hpp"
#include "libtorrent/aux_/packet_buffer.hpp"
#include "libtorrent/aux_/packet_pool.hpp"

using lt::aux::packet_buffer;
using lt::aux::packet_ptr;
using lt::aux::packet_pool;
using lt::aux::packet;

namespace {

packet_ptr make_pkt(packet_pool& pool, int const val)
{
	packet_ptr ret = pool.acquire(20);
	*reinterpret_cast<std::uint8_t*>(ret->buf) = std::uint8_t(val);
	return ret;
}

int get_val(packet* pkt)
{
	TORRENT_ASSERT(pkt != nullptr);
	return *reinterpret_cast<std::uint8_t*>(pkt->buf);
}

} // anonymous namespace

// test packet_buffer
TORRENT_TEST(insert)
{
	packet_pool pool;
	packet_buffer pb;

	TEST_EQUAL(pb.capacity(), 0);
	TEST_EQUAL(pb.size(), 0);
	TEST_EQUAL(pb.span(), 0);

	pb.insert(123, make_pkt(pool, 123));
	TEST_CHECK(pb.at(123 + 16) == nullptr);

	TEST_EQUAL(get_val(pb.at(123)), 123);
	TEST_CHECK(pb.capacity() > 0);
	TEST_EQUAL(pb.size(), 1);
	TEST_EQUAL(pb.span(), 1);
	TEST_EQUAL(pb.cursor(), 123);

	pb.insert(125, make_pkt(pool, 125));

	TEST_EQUAL(get_val(pb.at(125)), 125);
	TEST_EQUAL(pb.size(), 2);
	TEST_EQUAL(pb.span(), 3);
	TEST_EQUAL(pb.cursor(), 123);

	pb.insert(500, make_pkt(pool, 4));
	TEST_EQUAL(pb.size(), 3);
	TEST_EQUAL(pb.span(), 501 - 123);
	TEST_EQUAL(pb.capacity(), 512);

	pb.insert(500, make_pkt(pool, 5));
	TEST_EQUAL(pb.size(), 3);
	TEST_EQUAL(get_val(pb.insert(500, make_pkt(pool, 4)).get()), 5);
	TEST_EQUAL(pb.size(), 3);

	TEST_EQUAL(get_val(pb.remove(123).get()), 123);
	TEST_EQUAL(pb.size(), 2);
	TEST_EQUAL(pb.span(), 501 - 125);
	TEST_EQUAL(pb.cursor(), 125);
	TEST_EQUAL(get_val(pb.remove(125).get()), 125);
	TEST_EQUAL(pb.size(), 1);
	TEST_EQUAL(pb.span(), 1);
	TEST_EQUAL(pb.cursor(), 500);

	TEST_EQUAL(get_val(pb.remove(500).get()), 4);
	TEST_EQUAL(pb.size(), 0);
	TEST_EQUAL(pb.span(), 0);

	for (int i = 0; i < 0xff; ++i)
	{
		int index = (i + 0xfff0) & 0xffff;
		pb.insert(packet_buffer::index_type(index), make_pkt(pool, index + 1));
		std::printf("insert: %d (mask: %x)\n", index, pb.capacity() - 1);
		TEST_EQUAL(pb.capacity(), 512);
		if (i >= 14)
		{
			index = (index - 14) & 0xffff;
			std::printf("remove: %d\n", index);
			TEST_EQUAL(get_val(pb.remove(packet_buffer::index_type(index)).get()), std::uint8_t(index + 1));
			TEST_EQUAL(pb.size(), 14);
		}
	}
}

TORRENT_TEST(wrap)
{
	// test wrapping the indices
	packet_pool pool;
	packet_buffer pb;

	TEST_EQUAL(pb.size(), 0);

	pb.insert(0xfffe, make_pkt(pool, 1));
	TEST_EQUAL(get_val(pb.at(0xfffe)), 1);

	pb.insert(2, make_pkt(pool, 2));
	TEST_EQUAL(get_val(pb.at(2)), 2);

	pb.remove(0xfffe);
	TEST_CHECK(pb.at(0xfffe) == nullptr);
	TEST_EQUAL(get_val(pb.at(2)), 2);
}

TORRENT_TEST(wrap2)
{
	// test wrapping the indices
	packet_pool pool;
	packet_buffer pb;

	TEST_EQUAL(pb.size(), 0);

	pb.insert(0xfff3, make_pkt(pool, 1));
	TEST_EQUAL(get_val(pb.at(0xfff3)), 1);

	auto const new_index = packet_buffer::index_type((0xfff3 + pb.capacity()) & 0xffff);
	pb.insert(new_index, make_pkt(pool, 2));
	TEST_EQUAL(get_val(pb.at(new_index)), 2);

	packet_ptr old = pb.remove(0xfff3);
	TEST_CHECK(get_val(old.get()) == 1);
	TEST_CHECK(pb.at(0xfff3) == nullptr);
	TEST_EQUAL(get_val(pb.at(new_index)), 2);
}

TORRENT_TEST(reverse_wrap)
{
	// test wrapping the indices backwards
	packet_pool pool;
	packet_buffer pb;

	TEST_EQUAL(pb.size(), 0);

	pb.insert(0xfff3, make_pkt(pool, 1));
	TEST_EQUAL(get_val(pb.at(0xfff3)), 1);

	auto const new_index = packet_buffer::index_type((0xfff3 + pb.capacity()) & 0xffff);
	pb.insert(new_index, make_pkt(pool, 2));
	TEST_EQUAL(get_val(pb.at(new_index)), 2);

	packet_ptr old = pb.remove(0xfff3);
	TEST_CHECK(get_val(old.get()) == 1);
	TEST_CHECK(pb.at(0xfff3) == nullptr);
	TEST_EQUAL(get_val(pb.at(new_index)), 2);

	pb.insert(0xffff, make_pkt(pool, 3));
}
