/*

Copyright (c) 2015-2020, 2022, Arvid Norberg
Copyright (c) 2016, 2021, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_RESOLVE_LINKS_HPP
#define TORRENT_RESOLVE_LINKS_HPP

#include <vector>
#include <utility>
#include <unordered_map>
#include <memory>
#include <string>

#include "libtorrent/aux_/export.hpp"
#include "libtorrent/aux_/vector.hpp"
#include "libtorrent/units.hpp"
#include "libtorrent/sha1_hash.hpp"
#include "libtorrent/fwd.hpp"

namespace libtorrent::aux {

#ifndef TORRENT_DISABLE_MUTABLE_TORRENTS
	// this class is used for mutable torrents, to discover identical files
	// in other torrents.
	struct TORRENT_EXTRA_EXPORT resolve_links
	{
		explicit resolve_links(std::shared_ptr<torrent_info const> ti);

		// check to see if any files are shared with this torrent
		void match(
			torrent_info const& ti
			, filenames const fs
			, std::string const& save_path);

		aux::vector<std::string, file_index_t> const& get_links() const&
		{ return m_links; }

		aux::vector<std::string, file_index_t> get_links() &&
		{ return std::move(m_links); }

	private:

		void match_v1(torrent_info const& ti, filenames const& fs
			, std::string const& save_path);
		void match_v2(filenames const& fs, std::string const& save_path);

		// this is the torrent we're trying to find files for.
		std::shared_ptr<torrent_info const> m_torrent_file;

		// each file in m_torrent_file has an entry in this vector. Any file
		// that also exists somewhere else, is filled in with the corresponding
		// torrent_info object and file index
		aux::vector<std::string, file_index_t> m_links;

		// maps file size to file index, in m_torrent_file
		std::unordered_multimap<std::int64_t, file_index_t> m_file_sizes;

		// maps file root hash to file index, in m_torrent_file
		std::unordered_multimap<sha256_hash, file_index_t> m_file_roots;
	};
#endif // TORRENT_DISABLE_MUTABLE_TORRENTS

}

#endif
