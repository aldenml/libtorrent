/*

Copyright (c) 2015-2020, Arvid Norberg
Copyright (c) 2016, Alden Torres
Copyright (c) 2017, AllSeeingEyeTolledEweSew
Copyright (c) 2018, Steven Siloti
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_TORRENT_STATUS_HPP_INCLUDED
#define TORRENT_TORRENT_STATUS_HPP_INCLUDED

#include "libtorrent/config.hpp"
#include "libtorrent/torrent_handle.hpp"
#include "libtorrent/bitfield.hpp"
#include "libtorrent/sha1_hash.hpp"
#include "libtorrent/time.hpp" // for time_duration
#include "libtorrent/storage_defs.hpp" // for storage_mode_t
#include "libtorrent/error_code.hpp"
#include "libtorrent/aux_/noexcept_movable.hpp"

#include <cstdint>
#include <string>
#include <ctime>

namespace libtorrent {

#if TORRENT_ABI_VERSION == 1
#include "libtorrent/aux_/disable_deprecation_warnings_push.hpp"
#endif

TORRENT_VERSION_NAMESPACE_4

	// holds a snapshot of the status of a torrent, as queried by
	// torrent_handle::status().
	struct TORRENT_EXPORT torrent_status
	{
#if TORRENT_ABI_VERSION == 1
#include "libtorrent/aux_/disable_warnings_pop.hpp"
#endif
		// hidden
		torrent_status() noexcept;
		~torrent_status();
		torrent_status(torrent_status const&);
		torrent_status& operator=(torrent_status const&);
		torrent_status(torrent_status&&) noexcept;
		torrent_status& operator=(torrent_status&&);

		// compares if the torrent status objects come from the same torrent. i.e.
		// only the torrent_handle field is compared.
		bool operator==(torrent_status const& st) const
		{ return handle == st.handle; }

		// a handle to the torrent whose status the object represents.
		torrent_handle handle;

		// the different overall states a torrent can be in
		enum state_t
		{
#if TORRENT_ABI_VERSION == 1
			// The torrent is in the queue for being checked. But there
			// currently is another torrent that are being checked.
			// This torrent will wait for its turn.
			queued_for_checking TORRENT_DEPRECATED_ENUM,
#else
			// internal
			unused_enum_for_backwards_compatibility,
#endif

			// The torrent has not started its download yet, and is
			// currently checking existing files.
			checking_files,

			// The torrent is trying to download metadata from peers.
			// This implies the ut_metadata extension is in use.
			downloading_metadata,

			// The torrent is being downloaded. This is the state
			// most torrents will be in most of the time. The progress
			// meter will tell how much of the files that has been
			// downloaded.
			downloading,

			// In this state the torrent has finished downloading but
			// still doesn't have the entire torrent. i.e. some pieces
			// are filtered and won't get downloaded.
			finished,

			// In this state the torrent has finished downloading and
			// is a pure seeder.
			seeding,

			// If the torrent was started in full allocation mode, this
			// indicates that the (disk) storage for the torrent is
			// allocated.
#if TORRENT_ABI_VERSION == 1
			allocating TORRENT_DEPRECATED_ENUM,
#else
			unused_enum_for_backwards_compatibility_allocating,
#endif

			// The torrent is currently checking the fast resume data and
			// comparing it to the files on disk. This is typically
			// completed in a fraction of a second, but if you add a
			// large number of torrents at once, they will queue up.
			checking_resume_data
		};

#if TORRENT_ABI_VERSION == 1
		TORRENT_DEPRECATED std::string error;
#endif

		// may be set to an error code describing why the torrent was paused, in
		// case it was paused by an error. If the torrent is not paused or if it's
		// paused but not because of an error, this error_code is not set.
		// if the error is attributed specifically to a file, error_file is set to
		// the index of that file in the .torrent file.
		error_code errc;

		// if the torrent is stopped because of an disk I/O error, this field
		// contains the index of the file in the torrent that encountered the
		// error. If the error did not originate in a file in the torrent, there
		// are a few special values this can be set to: error_file_none,
		// error_file_ssl_ctx, error_file_exception, error_file_partfile or
		// error_file_metadata;
		file_index_t error_file = torrent_status::error_file_none;

		// special values for error_file to describe which file or component
		// encountered the error (``errc``).
		// the error did not occur on a file
		static inline constexpr file_index_t error_file_none{-1};

		// the error occurred setting up the SSL context
		static inline constexpr file_index_t error_file_ssl_ctx{-3};

		// the error occurred while loading the metadata for the torrent
		static inline constexpr file_index_t error_file_metadata{-4};

		// there was a serious error reported in this torrent. The error code
		// or a torrent log alert may provide more information.
		static inline constexpr file_index_t error_file_exception{-5};

		// the error occurred with the partfile
		static inline constexpr file_index_t error_file_partfile{-6};

		// the path to the directory where this torrent's files are stored.
		// It's typically the path as was given to async_add_torrent() or
		// add_torrent() when this torrent was started. This field is only
		// included if the torrent status is queried with
		// ``torrent_handle::query_save_path``.
		std::string save_path;

		// the name of the torrent. Typically this is derived from the
		// .torrent file. In case the torrent was started without metadata,
		// and hasn't completely received it yet, it returns the name given
		// to it when added to the session. See ``session::add_torrent``.
		// This field is only included if the torrent status is queried
		// with ``torrent_handle::query_name``.
		std::string name;

		// set to point to the ``torrent_info`` object for this torrent. It's
		// only included if the torrent status is queried with
		// ``torrent_handle::query_torrent_file``.
		std::weak_ptr<const torrent_info> torrent_file;

		// the time until the torrent will announce itself to the tracker.
		time_duration next_announce = seconds{0};

#if TORRENT_ABI_VERSION == 1
		// the time the tracker want us to wait until we announce ourself
		// again the next time.
		TORRENT_DEPRECATED time_duration announce_interval;
#endif

		// the URL of the last working tracker. If no tracker request has
		// been successful yet, it's set to an empty string.
		std::string current_tracker;

		// the number of bytes downloaded and uploaded to all peers, accumulated,
		// *this session* only. The session is considered to restart when a
		// torrent is paused and restarted again. When a torrent is paused, these
		// counters are reset to 0. If you want complete, persistent, stats, see
		// ``all_time_upload`` and ``all_time_download``.
		std::int64_t total_download = 0;
		std::int64_t total_upload = 0;

		// counts the amount of bytes send and received this session, but only
		// the actual payload data (i.e the interesting data), these counters
		// ignore any protocol overhead. The session is considered to restart
		// when a torrent is paused and restarted again. When a torrent is
		// paused, these counters are reset to 0.
		std::int64_t total_payload_download = 0;
		std::int64_t total_payload_upload = 0;

		// the number of bytes that has been downloaded and that has failed the
		// piece hash test. In other words, this is just how much crap that has
		// been downloaded since the torrent was last started. If a torrent is
		// paused and then restarted again, this counter will be reset.
		std::int64_t total_failed_bytes = 0;

		// the number of bytes that has been downloaded even though that data
		// already was downloaded. The reason for this is that in some situations
		// the same data can be downloaded by mistake. When libtorrent sends
		// requests to a peer, and the peer doesn't send a response within a
		// certain timeout, libtorrent will re-request that block. Another
		// situation when libtorrent may re-request blocks is when the requests
		// it sends out are not replied in FIFO-order (it will re-request blocks
		// that are skipped by an out of order block). This is supposed to be as
		// low as possible. This only counts bytes since the torrent was last
		// started. If a torrent is paused and then restarted again, this counter
		// will be reset.
		std::int64_t total_redundant_bytes = 0;

		// a bitmask that represents which pieces we have (set to true) and the
		// pieces we don't have. It's a pointer and may be set to 0 if the
		// torrent isn't downloading or seeding.
		typed_bitfield<piece_index_t> pieces;

		// a bitmask representing which pieces has had their hash checked. This
		// only applies to torrents in *seed mode*. If the torrent is not in seed
		// mode, this bitmask may be empty.
		typed_bitfield<piece_index_t> verified_pieces;

		// the total number of bytes of the file(s) that we have. All this does
		// not necessarily has to be downloaded during this session (that's
		// ``total_payload_download``).
		std::int64_t total_done = 0;

		// the total number of bytes to download for this torrent. This
		// may be less than the size of the torrent in case there are
		// pad files. This number only counts bytes that will actually
		// be requested from peers.
		std::int64_t total = 0;

		// the number of bytes we have downloaded, only counting the pieces that
		// we actually want to download. i.e. excluding any pieces that we have
		// but have priority 0 (i.e. not wanted).
		// Once a torrent becomes seed, any piece- and file priorities are
		// forgotten and all bytes are considered "wanted".
		std::int64_t total_wanted_done = 0;

		// The total number of bytes we want to download. This may be smaller
		// than the total torrent size in case any pieces are prioritized to 0,
		// i.e.  not wanted.
		// Once a torrent becomes seed, any piece- and file priorities are
		// forgotten and all bytes are considered "wanted".
		std::int64_t total_wanted = 0;

		// are accumulated upload and download payload byte counters. They are
		// saved in and restored from resume data to keep totals across sessions.
		std::int64_t all_time_upload = 0;
		std::int64_t all_time_download = 0;

		// the posix-time when this torrent was added. i.e. what ``time(nullptr)``
		// returned at the time.
		std::time_t added_time = 0;

		// the posix-time when this torrent was finished. If the torrent is not
		// yet finished, this is 0.
		std::time_t completed_time = 0;

		// the time when we, or one of our peers, last saw a complete copy of
		// this torrent.
		std::time_t last_seen_complete = 0;

		// The allocation mode for the torrent. See storage_mode_t for the
		// options. For more information, see storage-allocation_.
		storage_mode_t storage_mode = storage_mode_sparse;

		// a value in the range [0, 1], that represents the progress of the
		// torrent's current task. It may be checking files or downloading.
		float progress = 0.f;

		// progress parts per million (progress * 1000000) when disabling
		// floating point operations, this is the only option to query progress
		//
		// reflects the same value as ``progress``, but instead in a range [0,
		// 1000000] (ppm = parts per million). When floating point operations are
		// disabled, this is the only alternative to the floating point value in
		// progress.
		int progress_ppm = 0;

		// the position this torrent has in the download
		// queue. If the torrent is a seed or finished, this is -1.
		queue_position_t queue_position{};

		// the total rates for all peers for this torrent. These will usually
		// have better precision than summing the rates from all peers. The rates
		// are given as the number of bytes per second.
		int download_rate = 0;
		int upload_rate = 0;

		// the total transfer rate of payload only, not counting protocol
		// chatter. This might be slightly smaller than the other rates, but if
		// projected over a long time (e.g. when calculating ETA:s) the
		// difference may be noticeable.
		int download_payload_rate = 0;
		int upload_payload_rate = 0;

		// the number of peers that are seeding that this client is
		// currently connected to.
		int num_seeds = 0;

		// the number of peers this torrent currently is connected to. Peer
		// connections that are in the half-open state (is attempting to connect)
		// or are queued for later connection attempt do not count. Although they
		// are visible in the peer list when you call get_peer_info().
		int num_peers = 0;

		// if the tracker sends scrape info in its announce reply, these fields
		// will be set to the total number of peers that have the whole file and
		// the total number of peers that are still downloading. set to -1 if the
		// tracker did not send any scrape data in its announce reply.
		int num_complete = -1;
		int num_incomplete = -1;

		// the number of seeds in our peer list and the total number of peers
		// (including seeds). We are not necessarily connected to all the peers
		// in our peer list. This is the number of peers we know of in total,
		// including banned peers and peers that we have failed to connect to.
		int list_seeds = 0;
		int list_peers = 0;

		// the number of peers in this torrent's peer list that is a candidate to
		// be connected to. i.e. It has fewer connect attempts than the max fail
		// count, it is not a seed if we are a seed, it is not banned etc. If
		// this is 0, it means we don't know of any more peers that we can try.
		int connect_candidates = 0;

		// the number of pieces that has been downloaded. It is equivalent to:
		// ``std::accumulate(pieces->begin(), pieces->end())``. So you don't have
		// to count yourself. This can be used to see if anything has updated
		// since last time if you want to keep a graph of the pieces up to date.
		// Note that these pieces have not necessarily been written to disk yet,
		// and there is a risk the write to disk will fail.
		int num_pieces = 0;

		// the number of distributed copies of the torrent. Note that one copy
		// may be spread out among many peers. It tells how many copies there are
		// currently of the rarest piece(s) among the peers this client is
		// connected to.
		int distributed_full_copies = 0;

		// tells the share of pieces that have more copies than the rarest
		// piece(s). Divide this number by 1000 to get the fraction.
		//
		// For example, if ``distributed_full_copies`` is 2 and
		// ``distributed_fraction`` is 500, it means that the rarest pieces have
		// only 2 copies among the peers this torrent is connected to, and that
		// 50% of all the pieces have more than two copies.
		//
		// If we are a seed, the piece picker is deallocated as an optimization,
		// and piece availability is no longer tracked. In this case the
		// distributed copies members are set to -1.
		int distributed_fraction = 0;

		// the number of distributed copies of the file. note that one copy may
		// be spread out among many peers. This is a floating point
		// representation of the distributed copies.
		//
		// the integer part tells how many copies
		//   there are of the rarest piece(s)
		//
		// the fractional part tells the fraction of pieces that
		//   have more copies than the rarest piece(s).
		float distributed_copies = 0.f;

		// the size of a block, in bytes. A block is a sub piece, it is the
		// number of bytes that each piece request asks for and the number of
		// bytes that each bit in the ``partial_piece_info``'s bitset represents,
		// see get_download_queue(). This is typically 16 kB, but it may be
		// smaller, if the pieces are smaller.
		int block_size = 0;

		// the number of unchoked peers in this torrent.
		int num_uploads = 0;

		// the number of peer connections this torrent has, including half-open
		// connections that hasn't completed the bittorrent handshake yet. This
		// is always >= ``num_peers``.
		int num_connections = 0;

		// the set limit of upload slots (unchoked peers) for this torrent.
		int uploads_limit = 0;

		// the set limit of number of connections for this torrent.
		int connections_limit = 0;

		// the number of peers in this torrent that are waiting for more
		// bandwidth quota from the torrent rate limiter. This can determine if
		// the rate you get from this torrent is bound by the torrents limit or
		// not. If there is no limit set on this torrent, the peers might still
		// be waiting for bandwidth quota from the global limiter, but then they
		// are counted in the ``session_status`` object.
		int up_bandwidth_queue = 0;
		int down_bandwidth_queue = 0;

#if TORRENT_ABI_VERSION == 1
		// deprecated in 1.2
		// use last_upload, last_download or
		// seeding_duration, finished_duration and active_duration
		// instead

		// the number of seconds since any peer last uploaded from this torrent
		// and the last time a downloaded piece passed the hash check,
		// respectively. Note, when starting up a torrent that needs its files
		// checked, piece may pass and that will be considered downloading for the
		// purpose of this counter. -1 means there either hasn't been any
		// uploading/downloading, or it was too long ago for libtorrent to
		// remember (currently forgetting happens after about 18 hours)
		TORRENT_DEPRECATED int time_since_upload = 0;
		TORRENT_DEPRECATED int time_since_download = 0;

		// These keep track of the number of seconds this torrent has been active
		// (not paused) and the number of seconds it has been active while being
		// finished and active while being a seed. ``seeding_time`` should be <=
		// ``finished_time`` which should be <= ``active_time``. They are all
		// saved in and restored from resume data, to keep totals across
		// sessions.
		TORRENT_DEPRECATED int active_time = 0;
		TORRENT_DEPRECATED int finished_time = 0;
		TORRENT_DEPRECATED int seeding_time = 0;
#endif

		// A rank of how important it is to seed the torrent, it is used to
		// determine which torrents to seed and which to queue. It is based on
		// the peer to seed ratio from the tracker scrape. For more information,
		// see queuing_. Higher value means more important to seed
		int seed_rank = 0;

#if TORRENT_ABI_VERSION == 1
		// deprecated in 1.2

		// the number of seconds since this torrent acquired scrape data.
		// If it has never done that, this value is -1.
		TORRENT_DEPRECATED int last_scrape = 0;

		// the priority of this torrent
		TORRENT_DEPRECATED int priority = 0;
#endif

		// the main state the torrent is in. See torrent_status::state_t.
		state_t state = checking_resume_data;

#if TORRENT_ABI_VERSION < 4
		// true if this torrent has unsaved changes
		// to its download state and statistics since the last resume data
		// was saved.
		TORRENT_DEPRECATED bool need_save_resume = false;
#endif

		// These are the flags indicating which aspects of this torrent have
		// changed since the last time resume data was saved. See
		// torrent_handle::save_resume_data().
		resume_data_flags_t need_save_resume_data;

#if TORRENT_ABI_VERSION == 1
		// true if the session global IP filter applies
		// to this torrent. This defaults to true.
		TORRENT_DEPRECATED bool ip_filter_applies = false;

		// true if the torrent is blocked from downloading. This typically
		// happens when a disk write operation fails. If the torrent is
		// auto-managed, it will periodically be taken out of this state, in the
		// hope that the disk condition (be it disk full or permission errors)
		// has been resolved. If the torrent is not auto-managed, you have to
		// explicitly take it out of the upload mode by calling set_upload_mode()
		// on the torrent_handle.
		TORRENT_DEPRECATED bool upload_mode = false;

		// true if the torrent is currently in share-mode, i.e. not downloading
		// the torrent, but just helping the swarm out.
		TORRENT_DEPRECATED bool share_mode = false;

		// true if the torrent is in super seeding mode
		TORRENT_DEPRECATED bool super_seeding = false;

		// set to true if the torrent is paused and false otherwise. It's only
		// true if the torrent itself is paused. If the torrent is not running
		// because the session is paused, this is still false. To know if a
		// torrent is active or not, you need to inspect both
		// ``torrent_status::paused`` and ``session::is_paused()``.
		TORRENT_DEPRECATED bool paused = false;

		// set to true if the torrent is auto managed, i.e. libtorrent is
		// responsible for determining whether it should be started or queued.
		// For more info see queuing_
		TORRENT_DEPRECATED bool auto_managed = false;

		// true when the torrent is in sequential download mode. In this mode
		// pieces are downloaded in order rather than rarest first.
		TORRENT_DEPRECATED bool sequential_download = false;
#endif

		// true if all pieces have been downloaded.
		bool is_seeding = false;

		// true if all pieces that have a priority > 0 are downloaded. There is
		// only a distinction between finished and seeding if some pieces or
		// files have been set to priority 0, i.e. are not downloaded.
		bool is_finished = false;

		// true if this torrent has metadata (either it was started from a
		// .torrent file or the metadata has been downloaded). The only scenario
		// where this can be false is when the torrent was started torrent-less
		// (i.e. with just an info-hash and tracker ip, a magnet link for
		// instance).
		bool has_metadata = false;

		// true if there has ever been an incoming connection attempt to this
		// torrent.
		bool has_incoming = false;

#if TORRENT_ABI_VERSION == 1
		// true if the torrent is in seed_mode. If the torrent was started in
		// seed mode, it will leave seed mode once all pieces have been checked
		// or as soon as one piece fails the hash check.
		TORRENT_DEPRECATED bool seed_mode = false;
#endif

		// this is true if this torrent's storage is currently being moved from
		// one location to another. This may potentially be a long operation
		// if a large file ends up being copied from one drive to another.
		bool moving_storage = false;

#if TORRENT_ABI_VERSION == 1
		// true if this torrent is loaded into RAM. A torrent can be started
		// and still not loaded into RAM, in case it has not had any peers interested in it
		// yet. Torrents are loaded on demand.
		TORRENT_DEPRECATED bool is_loaded = false;
#endif

		// these are set to true if this torrent is allowed to announce to the
		// respective peer source. Whether they are true or false is determined by
		// the queue logic/auto manager. Torrents that are not auto managed will
		// always be allowed to announce to all peer sources.
		bool announcing_to_trackers = false;
		bool announcing_to_lsd = false;
		bool announcing_to_dht = false;

#if TORRENT_ABI_VERSION == 1
		// this reflects whether the ``stop_when_ready`` flag is currently enabled
		// on this torrent. For more information, see
		// torrent_handle::stop_when_ready().
		TORRENT_DEPRECATED bool stop_when_ready = false;
#endif

#if TORRENT_ABI_VERSION < 3
		TORRENT_DEPRECATED sha1_hash info_hash;
#endif

		// the info-hash for this torrent
		info_hash_t info_hashes;

		// the timestamps of the last time this torrent uploaded or downloaded
		// payload to any peer.
		time_point last_upload;
		time_point last_download;

		// these are cumulative counters of for how long the torrent has been in
		// different states. active means not paused and added to session. Whether
		// it has found any peers or not is not relevant.
		// finished means all selected files/pieces were downloaded and available
		// to other peers (this is always a subset of active time).
		// seeding means all files/pieces were downloaded and available to
		// peers. Being available to peers does not imply there are other peers
		// asking for the payload.
		seconds active_duration;
		seconds finished_duration;
		seconds seeding_duration;

		// reflects several of the torrent's flags. For more
		// information, see ``torrent_handle::flags()``.
		torrent_flags_t flags{};
	};

TORRENT_VERSION_NAMESPACE_4_END
} // namespace libtorrent

namespace std {
	template <>
	struct hash<libtorrent::torrent_status>
	{
		std::size_t operator()(libtorrent::torrent_status const& ts) const
		{
			return libtorrent::hash_value(ts.handle);
		}
	};
}

#endif // TORRENT_TORRENT_STATUS_HPP_INCLUDED
