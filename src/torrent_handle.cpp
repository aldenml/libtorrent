/*

Copyright (c) 2003-2022, Arvid Norberg
Copyright (c) 2004, Magnus Jonsson
Copyright (c) 2016-2017, 2019-2020, Alden Torres
Copyright (c) 2017, 2020, AllSeeingEyeTolledEweSew
Copyright (c) 2017, Falcosc
Copyright (c) 2018, Steven Siloti
Copyright (c) 2019, Andrei Kurushin
Copyright (c) 2019, ghbplayer
Copyright (c) 2025, Vladimir Golovnev (glassez)
Copyright (c) 2021, Mark Scott
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <ctime>
#include <iterator>
#include <algorithm>
#include <set>
#include <cctype>

#include "libtorrent/torrent_handle.hpp"
#include "libtorrent/aux_/torrent.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/aux_/session_impl.hpp"
#include "libtorrent/aux_/session_call.hpp"
#include "libtorrent/aux_/throw.hpp"
#include "libtorrent/aux_/invariant_check.hpp"
#include "libtorrent/announce_entry.hpp"
#include "libtorrent/write_resume_data.hpp"
#include "libtorrent/torrent_flags.hpp"
#include "libtorrent/pex_flags.hpp"
#include "libtorrent/aux_/ip_helpers.hpp" // for is_v6

#if TORRENT_ABI_VERSION == 1
#include "libtorrent/peer_info.hpp" // for peer_list_entry
#endif

using libtorrent::aux::session_impl;

namespace libtorrent {

	void block_info::set_peer(tcp::endpoint const& ep)
	{
		is_v6_addr = aux::is_v6(ep);
		if (is_v6_addr)
			addr.v6 = ep.address().to_v6().to_bytes();
		else
			addr.v4 = ep.address().to_v4().to_bytes();
		port = ep.port();
	}

	tcp::endpoint block_info::peer() const
	{
		if (is_v6_addr)
			return {address_v6(addr.v6), port};
		else
			return {address_v4(addr.v4), port};
	}

#ifndef BOOST_NO_EXCEPTIONS
	[[noreturn]] void throw_invalid_handle()
	{
		throw system_error(errors::invalid_torrent_handle);
	}
#endif

	template<typename Fun, typename... Args>
	void torrent_handle::async_call(Fun f, Args&&... a) const
	{
		auto t = m_torrent.lock();
		if (!t) aux::throw_ex<system_error>(errors::invalid_torrent_handle);
		auto& ses = static_cast<session_impl&>(t->session());
		dispatch(ses.get_context(), std::bind([t, f, &ses](auto&&... args) mutable
		{
#ifndef BOOST_NO_EXCEPTIONS
			try {
#endif
				(t.get()->*f)(std::forward<Args>(args)...);
#ifndef BOOST_NO_EXCEPTIONS
			} catch (system_error const& e) {
				ses.alerts().emplace_alert<torrent_error_alert>(torrent_handle(t)
					, e.code(), e.what());
			} catch (std::exception const& e) {
				ses.alerts().emplace_alert<torrent_error_alert>(torrent_handle(t)
					, error_code(), e.what());
			} catch (...) {
				ses.alerts().emplace_alert<torrent_error_alert>(torrent_handle(t)
					, error_code(), "unknown error");
			}
#endif
		}, std::forward<Args>(a)...));
	}

	template<typename Fun, typename... Args>
	void torrent_handle::sync_call(Fun f, Args&&... a) const
	{
		auto t = m_torrent.lock();
		if (!t) aux::throw_ex<system_error>(errors::invalid_torrent_handle);
		auto& ses = static_cast<session_impl&>(t->session());

		// this is the flag to indicate the call has completed
		bool done = false;

		std::exception_ptr ex;
		dispatch(ses.get_context(), std::bind([t, f, &done, &ses, &ex](auto&&... args) mutable
		{
#ifndef BOOST_NO_EXCEPTIONS
			try {
#endif
				(t.get()->*f)(std::forward<Args>(args)...);
#ifndef BOOST_NO_EXCEPTIONS
			} catch (...) {
				ex = std::current_exception();
			}
#endif
			std::unique_lock<std::mutex> l(ses.mut);
			done = true;
			ses.cond.notify_all();
		}, std::forward<Args>(a)...));

		aux::torrent_wait(done, ses);
		if (ex) std::rethrow_exception(ex);
	}

	template<typename Ret, typename Fun, typename... Args>
	Ret torrent_handle::sync_call_ret(Ret def, Fun f, Args&&... a) const
	{
		auto t = m_torrent.lock();
		Ret r = def;
#ifndef BOOST_NO_EXCEPTIONS
		if (!t) throw_invalid_handle();
#else
		if (!t) return r;
#endif
		auto& ses = static_cast<session_impl&>(t->session());

		// this is the flag to indicate the call has completed
		bool done = false;

		std::exception_ptr ex;
		dispatch(ses.get_context(), std::bind([t, f, &r, &done, &ses, &ex](auto&&... args) mutable
		{
#ifndef BOOST_NO_EXCEPTIONS
			try {
#endif
				r = (t.get()->*f)(std::forward<Args>(args)...);
#ifndef BOOST_NO_EXCEPTIONS
			} catch (...) {
				ex = std::current_exception();
			}
#endif
			std::unique_lock<std::mutex> l(ses.mut);
			done = true;
			ses.cond.notify_all();
		}, std::forward<Args>(a)...));

		aux::torrent_wait(done, ses);

		if (ex) std::rethrow_exception(ex);
		return r;
	}

	sha1_hash torrent_handle::info_hash() const
	{
		auto t = m_torrent.lock();
		return t ? t->info_hash().get_best() : sha1_hash{};
	}

	info_hash_t torrent_handle::info_hashes() const
	{
		auto t = m_torrent.lock();
		return t ? t->info_hash() : info_hash_t();
	}

	int torrent_handle::max_uploads() const
	{
		return sync_call_ret<int>(0, &aux::torrent::max_uploads);
	}

	void torrent_handle::set_max_uploads(int max_uploads) const
	{
		TORRENT_ASSERT_PRECOND(max_uploads >= 2 || max_uploads == -1);
		async_call(&aux::torrent::set_max_uploads, max_uploads, true);
	}

	int torrent_handle::max_connections() const
	{
		return sync_call_ret<int>(0, &aux::torrent::max_connections);
	}

	void torrent_handle::set_max_connections(int max_connections) const
	{
		TORRENT_ASSERT_PRECOND(max_connections >= 2 || max_connections == -1);
		async_call(&aux::torrent::set_max_connections, max_connections, true);
	}

	void torrent_handle::set_upload_limit(int limit) const
	{
		TORRENT_ASSERT_PRECOND(limit >= -1);
		async_call(&aux::torrent::set_upload_limit, limit);
	}

	int torrent_handle::upload_limit() const
	{
		return sync_call_ret<int>(0, &aux::torrent::upload_limit);
	}

	void torrent_handle::set_download_limit(int limit) const
	{
		TORRENT_ASSERT_PRECOND(limit >= -1);
		async_call(&aux::torrent::set_download_limit, limit);
	}

	int torrent_handle::download_limit() const
	{
		return sync_call_ret<int>(0, &aux::torrent::download_limit);
	}

	void torrent_handle::move_storage(std::string const& save_path, move_flags_t flags) const
	{
		async_call(&aux::torrent::move_storage, save_path, flags);
	}

#if TORRENT_ABI_VERSION == 1
	void torrent_handle::move_storage(
		std::string const& save_path, int const flags) const
	{
		async_call(&aux::torrent::move_storage, save_path, static_cast<move_flags_t>(flags));
	}
#endif // TORRENT_ABI_VERSION

	void torrent_handle::rename_file(file_index_t index, std::string const& new_name) const
	{
		async_call(&aux::torrent::rename_file, index, new_name);
	}

	void torrent_handle::add_extension(
		std::function<std::shared_ptr<torrent_plugin>(torrent_handle const&, client_data_t)> const& ext
		, client_data_t userdata)
	{
#ifndef TORRENT_DISABLE_EXTENSIONS
		async_call(&aux::torrent::add_extension_fun, ext, userdata);
#else
		TORRENT_UNUSED(ext);
		TORRENT_UNUSED(userdata);
#endif
	}

	bool torrent_handle::set_metadata(span<char const> metadata) const
	{
		return sync_call_ret<bool>(false, &aux::torrent::set_metadata, metadata);
	}

	void torrent_handle::pause(pause_flags_t const flags) const
	{
		async_call(&aux::torrent::pause, flags & graceful_pause);
	}

	torrent_flags_t torrent_handle::flags() const
	{
		return sync_call_ret<torrent_flags_t>(torrent_flags_t{}, &aux::torrent::flags);
	}

	void torrent_handle::set_flags(torrent_flags_t const flags
		, torrent_flags_t const mask) const
	{
		async_call(&aux::torrent::set_flags, flags, mask);
	}

	void torrent_handle::set_flags(torrent_flags_t const flags) const
	{
		async_call(&aux::torrent::set_flags, torrent_flags::all, flags);
	}

	void torrent_handle::unset_flags(torrent_flags_t const flags) const
	{
		async_call(&aux::torrent::set_flags, torrent_flags_t{}, flags);
	}

#if TORRENT_ABI_VERSION == 1
	void torrent_handle::stop_when_ready(bool b) const
	{ async_call(&aux::torrent::stop_when_ready, b); }

	void torrent_handle::set_upload_mode(bool b) const
	{ async_call(&aux::torrent::set_upload_mode, b); }

	void torrent_handle::set_share_mode(bool b) const
	{
		TORRENT_UNUSED(b);
#ifndef TORRENT_DISABLE_SHARE_MODE
		async_call(&aux::torrent::set_share_mode, b);
#endif
	}

	void torrent_handle::apply_ip_filter(bool b) const
	{ async_call(&aux::torrent::set_apply_ip_filter, b); }

	void torrent_handle::auto_managed(bool m) const
	{ async_call(&aux::torrent::auto_managed, m); }

	void torrent_handle::set_pinned(bool) const {}

	void torrent_handle::set_sequential_download(bool sd) const
	{ async_call(&aux::torrent::set_sequential_download, sd); }
#endif

	void torrent_handle::flush_cache() const
	{
		async_call(&aux::torrent::flush_cache);
	}

	void torrent_handle::set_ssl_certificate(
		std::string const& certificate
		, std::string const& private_key
		, std::string const& dh_params
		, std::string const& passphrase)
	{
#ifdef TORRENT_SSL_PEERS
		async_call(&aux::torrent::set_ssl_cert, certificate, private_key, dh_params, passphrase);
#else
		TORRENT_UNUSED(certificate);
		TORRENT_UNUSED(private_key);
		TORRENT_UNUSED(dh_params);
		TORRENT_UNUSED(passphrase);
#endif
	}

	void torrent_handle::set_ssl_certificate_buffer(
		std::string const& certificate
		, std::string const& private_key
		, std::string const& dh_params)
	{
#ifdef TORRENT_SSL_PEERS
		async_call(&aux::torrent::set_ssl_cert_buffer, certificate, private_key, dh_params);
#else
		TORRENT_UNUSED(certificate);
		TORRENT_UNUSED(private_key);
		TORRENT_UNUSED(dh_params);
#endif
	}

	void torrent_handle::save_resume_data(resume_data_flags_t f) const
	{
		async_call(&aux::torrent::save_resume_data, f);
	}

	bool torrent_handle::need_save_resume_data() const
	{
		auto const all_categories
			= torrent_handle::if_counters_changed
			| torrent_handle::if_download_progress
			| torrent_handle::if_config_changed
			| torrent_handle::if_state_changed
			| torrent_handle::if_metadata_changed
			;
		return sync_call_ret<bool>(false, &aux::torrent::need_save_resume_data, all_categories);
	}

	bool torrent_handle::need_save_resume_data(resume_data_flags_t const flags) const
	{
		return sync_call_ret<bool>(false, &aux::torrent::need_save_resume_data, flags);
	}

	add_torrent_params torrent_handle::get_resume_data(resume_data_flags_t const flags) const
	{
		return sync_call_ret<add_torrent_params>({}, &aux::torrent::get_resume_data, flags);
	}

	void torrent_handle::force_recheck() const
	{
		async_call(&aux::torrent::force_recheck);
	}

	void torrent_handle::resume() const
	{
		async_call(&aux::torrent::resume);
	}

	queue_position_t torrent_handle::queue_position() const
	{
		return sync_call_ret<queue_position_t>(no_pos
			, &aux::torrent::queue_position);
	}

	void torrent_handle::queue_position_up() const
	{
		async_call(&aux::torrent::queue_up);
	}

	void torrent_handle::queue_position_down() const
	{
		async_call(&aux::torrent::queue_down);
	}

	void torrent_handle::queue_position_set(queue_position_t const p) const
	{
		TORRENT_ASSERT_PRECOND(p >= queue_position_t{});
		if (p < queue_position_t{}) return;
		async_call(&aux::torrent::set_queue_position, p);
	}

	void torrent_handle::queue_position_top() const
	{
		async_call(&aux::torrent::set_queue_position, queue_position_t{});
	}

	void torrent_handle::queue_position_bottom() const
	{
		async_call(&aux::torrent::set_queue_position, last_pos);
	}

	void torrent_handle::clear_error() const
	{
		async_call(&aux::torrent::clear_error);
	}

#if TORRENT_ABI_VERSION == 1
	void torrent_handle::set_priority(int const p) const
	{
		async_call(&aux::torrent::set_priority, p);
	}

	void torrent_handle::set_tracker_login(std::string const& name
		, std::string const& password) const
	{
		async_call(&aux::torrent::set_tracker_login, name, password);
	}
#endif

	void torrent_handle::file_progress(std::vector<std::int64_t>& progress, file_progress_flags_t flags) const
	{
		auto& arg = static_cast<aux::vector<std::int64_t, file_index_t>&>(progress);
		sync_call(&aux::torrent::file_progress, std::ref(arg), flags);
	}

	std::vector<std::int64_t> torrent_handle::file_progress(file_progress_flags_t flags) const
	{
		aux::vector<std::int64_t, file_index_t> ret;
		sync_call(&aux::torrent::file_progress, std::ref(ret), flags);
		return TORRENT_RVO(ret);
	}

	void torrent_handle::post_file_progress(file_progress_flags_t const flags) const
	{
		async_call(&aux::torrent::post_file_progress, flags);
	}

	torrent_status torrent_handle::status(status_flags_t const flags) const
	{
		torrent_status st;
		sync_call(&aux::torrent::status, &st, flags);
		return st;
	}

	void torrent_handle::post_status(status_flags_t const flags) const
	{
		async_call(&aux::torrent::post_status, flags);
	}

	void torrent_handle::post_piece_availability() const
	{
		async_call(&aux::torrent::post_piece_availability);
	}

	void torrent_handle::piece_availability(std::vector<int>& avail) const
	{
		auto& arg = static_cast<aux::vector<int, piece_index_t>&>(avail);
		sync_call(&aux::torrent::piece_availability, std::ref(arg));
	}

	void torrent_handle::piece_priority(piece_index_t index, download_priority_t priority) const
	{
		async_call(&aux::torrent::set_piece_priority, index, priority);
	}

	download_priority_t torrent_handle::piece_priority(piece_index_t index) const
	{
		return sync_call_ret<download_priority_t>(dont_download, &aux::torrent::piece_priority, index);
	}

	void torrent_handle::prioritize_pieces(std::vector<download_priority_t> const& pieces) const
	{
		async_call(&aux::torrent::prioritize_pieces
			, static_cast<aux::vector<download_priority_t, piece_index_t> const&>(pieces));
	}

	void torrent_handle::prioritize_pieces(std::vector<std::pair<piece_index_t
		, download_priority_t>> const& pieces) const
	{
		async_call(&aux::torrent::prioritize_piece_list, pieces);
	}

	std::vector<download_priority_t> torrent_handle::get_piece_priorities() const
	{
		aux::vector<download_priority_t, piece_index_t> ret;
		auto* const retp = &ret;
		sync_call(&aux::torrent::piece_priorities, retp);
		return TORRENT_RVO(ret);
	}

#if TORRENT_ABI_VERSION == 1
	void torrent_handle::prioritize_pieces(std::vector<int> const& pieces) const
	{
		aux::vector<download_priority_t, piece_index_t> p;
		p.reserve(pieces.size());
		for (auto const prio : pieces) {
			p.push_back(download_priority_t(static_cast<std::uint8_t>(prio)));
		}
		async_call(&aux::torrent::prioritize_pieces, p);
	}

	void torrent_handle::prioritize_pieces(std::vector<std::pair<piece_index_t, int>> const& pieces) const
	{
		std::vector<std::pair<piece_index_t, download_priority_t>> p;
		p.reserve(pieces.size());
		async_call(&aux::torrent::prioritize_piece_list, std::move(p));
	}

	std::vector<int> torrent_handle::piece_priorities() const
	{
		aux::vector<download_priority_t, piece_index_t> prio;
		auto* const retp = &prio;
		sync_call(&aux::torrent::piece_priorities, retp);
		std::vector<int> ret;
		ret.reserve(prio.size());
		for (auto p : prio)
			ret.push_back(int(static_cast<std::uint8_t>(p)));
		return ret;
	}
#endif

	void torrent_handle::file_priority(file_index_t index, download_priority_t priority) const
	{
		async_call(&aux::torrent::set_file_priority, index, priority);
	}

	download_priority_t torrent_handle::file_priority(file_index_t index) const
	{
		return sync_call_ret<download_priority_t>(dont_download, &aux::torrent::file_priority, index);
	}

	// TODO: support moving files into this call
	void torrent_handle::prioritize_files(std::vector<download_priority_t> const& files) const
	{
		async_call(&aux::torrent::prioritize_files
			, static_cast<aux::vector<download_priority_t, file_index_t> const&>(files));
	}

	std::vector<download_priority_t> torrent_handle::get_file_priorities() const
	{
		aux::vector<download_priority_t, file_index_t> ret;
		auto* const retp = &ret;
		sync_call(&aux::torrent::file_priorities, retp);
		return TORRENT_RVO(ret);
	}

#if TORRENT_ABI_VERSION == 1

// ============ start deprecation ===============

	void torrent_handle::prioritize_files(std::vector<int> const& files) const
	{
		aux::vector<download_priority_t, file_index_t> file_prio;
		file_prio.reserve(files.size());
		for (auto const p : files) {
			file_prio.push_back(download_priority_t(static_cast<std::uint8_t>(p)));
		}
		async_call(&aux::torrent::prioritize_files, file_prio);
	}

	std::vector<int> torrent_handle::file_priorities() const
	{
		aux::vector<download_priority_t, file_index_t> prio;
		auto* const retp = &prio;
		sync_call(&aux::torrent::file_priorities, retp);
		std::vector<int> ret;
		ret.reserve(prio.size());
		for (auto p : prio)
			ret.push_back(int(static_cast<std::uint8_t>(p)));
		return ret;
	}


	int torrent_handle::get_peer_upload_limit(tcp::endpoint) const { return -1; }
	int torrent_handle::get_peer_download_limit(tcp::endpoint) const { return -1; }
	void torrent_handle::set_peer_upload_limit(tcp::endpoint, int /* limit */) const {}
	void torrent_handle::set_peer_download_limit(tcp::endpoint, int /* limit */) const {}
	void torrent_handle::set_ratio(float) const {}
	void torrent_handle::use_interface(const char* net_interface) const
	{
		async_call(&aux::torrent::use_interface, std::string(net_interface));
	}

#if !TORRENT_NO_FPU
	void torrent_handle::file_progress(std::vector<float>& progress) const
	{
		auto& arg = static_cast<aux::vector<float, file_index_t>&>(progress);
		sync_call(&aux::torrent::file_progress_float, std::ref(arg));
	}
#endif

	bool torrent_handle::is_seed() const
	{ return sync_call_ret<bool>(false, &aux::torrent::is_seed); }

	bool torrent_handle::is_finished() const
	{ return sync_call_ret<bool>(false, &aux::torrent::is_finished); }

	bool torrent_handle::is_paused() const
	{ return sync_call_ret<bool>(false, &aux::torrent::is_torrent_paused); }

	bool torrent_handle::is_sequential_download() const
	{ return sync_call_ret<bool>(false, &aux::torrent::is_sequential_download); }

	bool torrent_handle::is_auto_managed() const
	{ return sync_call_ret<bool>(false, &aux::torrent::is_auto_managed); }

	bool torrent_handle::has_metadata() const
	{ return sync_call_ret<bool>(false, &aux::torrent::valid_metadata); }

	bool torrent_handle::super_seeding() const
	{
#ifndef TORRENT_DISABLE_SUPERSEEDING
		return sync_call_ret<bool>(false, &aux::torrent::super_seeding);
#else
		return false;
#endif
	}

// ============ end deprecation ===============
#endif

	std::vector<announce_entry> torrent_handle::trackers() const
	{
		static const std::vector<announce_entry> empty;
		return sync_call_ret<std::vector<announce_entry>>(empty, &aux::torrent::trackers);
	}

	void torrent_handle::post_trackers() const
	{
		async_call(&aux::torrent::post_trackers);
	}

	void torrent_handle::add_url_seed(std::string const& url) const
	{
		async_call(&aux::torrent::add_web_seed, url
			, std::string(), web_seed_entry::headers_t(), aux::web_seed_flag_t{});
	}

	void torrent_handle::remove_url_seed(std::string const& url) const
	{
		async_call(&aux::torrent::remove_web_seed, url);
	}

	std::set<std::string> torrent_handle::url_seeds() const
	{
		static const std::set<std::string> empty;
		return sync_call_ret<std::set<std::string>>(empty, &aux::torrent::web_seeds);
	}

#if TORRENT_ABI_VERSION < 4
	void torrent_handle::add_http_seed(std::string const&) const {}
	void torrent_handle::remove_http_seed(std::string const&) const {}
	std::set<std::string> torrent_handle::http_seeds() const { return {}; }
#endif

	void torrent_handle::replace_trackers(
		std::vector<announce_entry> const& urls) const
	{
		async_call(&aux::torrent::replace_trackers, urls);
	}

	void torrent_handle::add_tracker(announce_entry const& url) const
	{
		async_call(&aux::torrent::add_tracker, url);
	}

	void torrent_handle::add_piece(piece_index_t piece, char const* data, add_piece_flags_t const flags) const
	{
		sync_call(&aux::torrent::add_piece, piece, data, flags);
	}

	void torrent_handle::add_piece(piece_index_t piece, std::vector<char> data
		, add_piece_flags_t const flags) const
	{
		async_call(&aux::torrent::add_piece_async, piece, std::move(data), flags);
	}

	void torrent_handle::read_piece(piece_index_t piece) const
	{
		async_call(&aux::torrent::read_piece, piece);
	}

	bool torrent_handle::have_piece(piece_index_t piece) const
	{
		return sync_call_ret<bool>(false, &aux::torrent::user_have_piece, piece);
	}

	void torrent_handle::set_sequential_range(piece_index_t const first_piece, piece_index_t const last_piece) const
	{
		TORRENT_ASSERT_PRECOND(first_piece >= piece_index_t(0) && last_piece >= first_piece);
		if (first_piece >= piece_index_t(0) && last_piece >= first_piece)
			async_call(static_cast<void (aux::torrent::*)(piece_index_t,piece_index_t)>(&aux::torrent::set_sequential_range), first_piece, last_piece);
	}

	void torrent_handle::set_sequential_range(piece_index_t const first_piece) const
	{
		TORRENT_ASSERT_PRECOND(first_piece >= piece_index_t(0));
		if (first_piece >= piece_index_t(0))
			async_call(static_cast<void (aux::torrent::*)(piece_index_t)>(&aux::torrent::set_sequential_range), first_piece);
	}

	bool torrent_handle::is_valid() const
	{
		return !m_torrent.expired();
	}

	std::shared_ptr<const torrent_info> torrent_handle::torrent_file() const
	{
		return sync_call_ret<std::shared_ptr<const torrent_info>>(
			std::shared_ptr<const torrent_info>(), &aux::torrent::get_torrent_file);
	}

#if TORRENT_ABI_VERSION < 4
	std::shared_ptr<torrent_info> torrent_handle::torrent_file_with_hashes() const
	{
		return sync_call_ret<std::shared_ptr<torrent_info>>(
			std::shared_ptr<torrent_info>(), &aux::torrent::get_torrent_copy_with_hashes);
	}
#endif

	std::vector<std::vector<sha256_hash>> torrent_handle::piece_layers() const
	{
		return sync_call_ret<std::vector<std::vector<sha256_hash>>>({}
			, &aux::torrent::get_piece_layers);
	}

#if TORRENT_ABI_VERSION == 1
	// this function should either be removed, or return
	// reference counted handle to the torrent_info which
	// forces the torrent to stay loaded while the client holds it
	torrent_info const& torrent_handle::get_torrent_info() const
	{
		static aux::array<std::shared_ptr<const torrent_info>, 4> holder;
		static int cursor = 0;
		static std::mutex holder_mutex;

		std::shared_ptr<const torrent_info> r = torrent_file();

		std::lock_guard<std::mutex> l(holder_mutex);
		holder[cursor++] = r;
		cursor = cursor % holder.end_index();
		return *r;
	}

	entry torrent_handle::write_resume_data() const
	{
		add_torrent_params params;
		sync_call(&aux::torrent::write_resume_data, resume_data_flags_t{}, std::ref(params));
		return libtorrent::write_resume_data(params);
	}

	std::string torrent_handle::save_path() const
	{
		return sync_call_ret<std::string>("", &aux::torrent::save_path);
	}

	std::string torrent_handle::name() const
	{
		return sync_call_ret<std::string>("", &aux::torrent::name);
	}

#endif

	void torrent_handle::connect_peer(tcp::endpoint const& adr
		, peer_source_flags_t const source, pex_flags_t const flags) const
	{
		async_call(&aux::torrent::add_peer, adr, source, flags);
	}

	void torrent_handle::clear_peers()
	{
		async_call(&aux::torrent::clear_peers);
	}

#if TORRENT_ABI_VERSION == 1
	void torrent_handle::force_reannounce(
		boost::posix_time::time_duration duration) const
	{
		async_call(&aux::torrent::force_tracker_request, aux::time_now()
			+ seconds(duration.total_seconds()), -1, reannounce_flags_t{});
	}

	void torrent_handle::file_status(std::vector<open_file_state>& status) const
	{
		status.clear();

		auto t = m_torrent.lock();
		if (!t || !t->has_storage()) return;
		auto& ses = static_cast<session_impl&>(t->session());
		status = ses.disk_thread().get_status(t->storage());
	}
#endif

	void torrent_handle::force_dht_announce() const
	{
#ifndef TORRENT_DISABLE_DHT
		async_call(&aux::torrent::dht_announce);
#endif
	}

	void torrent_handle::force_lsd_announce() const
	{
		async_call(&aux::torrent::lsd_announce);
	}

	// TODO: deprecate the overload that takes an index
	void torrent_handle::force_reannounce(int const s, int const idx, reannounce_flags_t const flags) const
	{
		async_call(&aux::torrent::force_tracker_request, aux::time_now() + seconds(s), idx, flags);
	}

	void torrent_handle::force_reannounce(int const s, std::string const& url, reannounce_flags_t const flags) const
	{
		async_call(&aux::torrent::force_tracker_request_url, aux::time_now() + seconds(s), url, flags);
	}

	void torrent_handle::force_reannounce(int const s, reannounce_flags_t const flags) const
	{
		async_call(&aux::torrent::force_tracker_request, aux::time_now() + seconds(s), -1, flags);
	}

	std::vector<open_file_state> torrent_handle::file_status() const
	{
		auto t = m_torrent.lock();
		if (!t || !t->has_storage()) return {};
		auto& ses = static_cast<session_impl&>(t->session());
		return ses.disk_thread().get_status(t->storage());
	}

	void torrent_handle::scrape_tracker(int idx) const
	{
		async_call(&aux::torrent::scrape_tracker, idx, true);
	}

	void torrent_handle::scrape_tracker(std::string url) const
	{
		async_call(&aux::torrent::scrape_tracker_url, std::move(url), true);
	}

	void torrent_handle::scrape_tracker() const
	{
		async_call(&aux::torrent::scrape_tracker, -1, true);
	}

#if TORRENT_ABI_VERSION == 1
	void torrent_handle::super_seeding(bool on) const
	{
		TORRENT_UNUSED(on);
#ifndef TORRENT_DISABLE_SUPERSEEDING
		async_call(&aux::torrent::set_super_seeding, on);
#endif
	}

	void torrent_handle::get_full_peer_list(std::vector<peer_list_entry>& v) const
	{
		auto* vp = &v;
		sync_call(&aux::torrent::get_full_peer_list, vp);
	}
#endif

	void torrent_handle::get_peer_info(std::vector<peer_info>& v) const
	{
		auto* vp = &v;
		sync_call(&aux::torrent::get_peer_info, vp);
	}

	void torrent_handle::post_peer_info() const
	{
		async_call(&aux::torrent::post_peer_info);
	}

	void torrent_handle::get_download_queue(std::vector<partial_piece_info>& queue) const
	{
		auto* queuep = &queue;
		sync_call(&aux::torrent::get_download_queue, queuep);
	}

	std::vector<partial_piece_info> torrent_handle::get_download_queue() const
	{
		std::vector<partial_piece_info> queue;
		sync_call(&aux::torrent::get_download_queue, &queue);
		return queue;
	}

	void torrent_handle::post_download_queue() const
	{
		async_call(&aux::torrent::post_download_queue);
	}

	void torrent_handle::set_piece_deadline(piece_index_t index, int deadline
		, deadline_flags_t const flags) const
	{
#ifndef TORRENT_DISABLE_STREAMING
		async_call(&aux::torrent::set_piece_deadline, index, deadline, flags);
#else
		TORRENT_UNUSED(deadline);
		if (flags & alert_when_available)
			async_call(&aux::torrent::read_piece, index);
#endif
	}

	void torrent_handle::reset_piece_deadline(piece_index_t index) const
	{
#ifndef TORRENT_DISABLE_STREAMING
		async_call(&aux::torrent::reset_piece_deadline, index);
#else
		TORRENT_UNUSED(index);
#endif
	}

	void torrent_handle::clear_piece_deadlines() const
	{
#ifndef TORRENT_DISABLE_STREAMING
		async_call(&aux::torrent::clear_time_critical);
#endif
	}

	std::shared_ptr<aux::torrent> torrent_handle::native_handle() const
	{
		return m_torrent.lock();
	}

	std::size_t hash_value(torrent_handle const& th)
	{
		// using the locked shared_ptr value as hash doesn't work
		// for expired weak_ptrs. So, we're left with a hack
		return std::size_t(*reinterpret_cast<void* const*>(&th.m_torrent));
	}

	client_data_t torrent_handle::userdata() const
	{
		auto t = m_torrent.lock();
		return t ? t->get_userdata() : client_data_t{};
	}

	bool torrent_handle::in_session() const
	{ return !sync_call_ret<bool>(false, &aux::torrent::is_aborted); }

	static_assert(std::is_nothrow_move_constructible<torrent_handle>::value
		, "should be nothrow move constructible");
	static_assert(std::is_nothrow_move_assignable<torrent_handle>::value
		, "should be nothrow move assignable");
	static_assert(std::is_nothrow_default_constructible<torrent_handle>::value
		, "should be nothrow default constructible");
}
