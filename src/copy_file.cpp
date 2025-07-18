/*

Copyright (c) 2022, Arvid Norberg
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libtorrent/config.hpp"

#include "libtorrent/error_code.hpp"
#include "libtorrent/aux_/path.hpp"
#include "libtorrent/aux_/storage_utils.hpp"

#ifdef TORRENT_WINDOWS
// windows part
#include "libtorrent/aux_/windows.hpp"
#include "libtorrent/aux_/win_file_handle.hpp"
#else

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include "libtorrent/aux_/file_descriptor.hpp"

#include <unistd.h>
#include <sys/stat.h>

#if TORRENT_HAS_COPYFILE
#include <copyfile.h>
#endif

#endif

namespace libtorrent {
namespace aux {

#ifdef TORRENT_WINDOWS
namespace {

// returns true if the given file has any regions that are
// sparse, i.e. not allocated. This is similar to calling lseek(SEEK_DATA) and
// lseek(SEEK_HOLE)
std::pair<std::int64_t, std::int64_t> next_allocated_region(HANDLE file
	, std::int64_t const offset
	, std::int64_t file_size
	, error_code& ec)
{
#ifndef FSCTL_QUERY_ALLOCATED_RANGES
	typedef struct _FILE_ALLOCATED_RANGE_BUFFER {
		LARGE_INTEGER FileOffset;
		LARGE_INTEGER Length;
	} FILE_ALLOCATED_RANGE_BUFFER;
#define FSCTL_QUERY_ALLOCATED_RANGES ((0x9 << 16) | (1 << 14) | (51 << 2) | 3)
#endif
	FILE_ALLOCATED_RANGE_BUFFER in;
	in.FileOffset.QuadPart = offset;
	in.Length.QuadPart = file_size - offset;

	FILE_ALLOCATED_RANGE_BUFFER out;

	DWORD returned_bytes = 0;
	BOOL const ret = DeviceIoControl(file, FSCTL_QUERY_ALLOCATED_RANGES
		, static_cast<void*>(&in), sizeof(in)
		, &out, sizeof(out), &returned_bytes, nullptr);

	if (ret == FALSE)
	{
		int const error = ::GetLastError();
		// we expect this error, since we just ask for one allocated range at a
		// time.
		if (error != ERROR_MORE_DATA)
		{
			ec.assign(error, system_category());
			return {0, 0};
		}
	}

	if (returned_bytes != sizeof(out)) {
		return {file_size, file_size};
	}

	return {out.FileOffset.QuadPart, out.FileOffset.QuadPart + out.Length.QuadPart};
}

void copy_range(HANDLE const in_handle, HANDLE const out_handle
	, std::int64_t in_offset, std::int64_t len, storage_error& se)
{
	char buffer[16384];
	while (len > 0)
	{
		OVERLAPPED in_ol{};
		in_ol.Offset = in_offset & 0xffffffff;
		in_ol.OffsetHigh = in_offset >> 32;
		DWORD num_read = 0;
		if (ReadFile(in_handle, buffer, DWORD(std::min(len, std::int64_t(sizeof(buffer))))
			, &num_read, &in_ol) == 0)
		{
			int const error = ::GetLastError();
			if (error == ERROR_HANDLE_EOF) return;

			se.operation = operation_t::file_read;
			se.ec.assign(error, system_category());
			return;
		}

		len -= num_read;
		int buf_offset = 0;
		while (num_read > 0)
		{
			OVERLAPPED out_ol{};
			out_ol.Offset = in_offset & 0xffffffff;
			out_ol.OffsetHigh = in_offset >> 32;
			DWORD num_written = 0;
			if (WriteFile(out_handle, buffer + buf_offset, DWORD(num_read - buf_offset)
				, &num_written, &out_ol) == 0)
			{
				se.operation = operation_t::file_write;
				se.ec.assign(::GetLastError(), system_category());
				return;
			}
			buf_offset += num_written;
			num_read -= num_written;
			in_offset += num_written;
		}
	}
	return;
}

}

void copy_file(std::string const& inf, std::string const& newf, storage_error& se)
{
	se.ec.clear();
	native_path_string f1 = convert_to_native_path_string(inf);
	native_path_string f2 = convert_to_native_path_string(newf);

	WIN32_FILE_ATTRIBUTE_DATA in_stat;
	if (!GetFileAttributesExW(f1.c_str(), GetFileExInfoStandard, &in_stat))
	{
		se.ec.assign(GetLastError(), system_category());
		se.operation = operation_t::file_stat;
		return;
	}

	if ((in_stat.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) == 0)
	{
		// if the input file is not sparse, use the system copy function
		if (CopyFileW(f1.c_str(), f2.c_str(), false) == 0)
		{
			se.operation = operation_t::file_copy;
			se.ec.assign(GetLastError(), system_category());
		}
		return;
	}

	std::int64_t const in_size = (std::int64_t(in_stat.nFileSizeHigh) << 32)
		| in_stat.nFileSizeLow;

#ifdef TORRENT_WINRT
	aux::win_file_handle in_handle = ::CreateFile2(f1.c_str()
			, GENERIC_READ
			, FILE_SHARE_READ
			, OPEN_EXISTING
			, nullptr);
#else
	aux::win_file_handle in_handle = ::CreateFileW(f1.c_str()
			, GENERIC_READ
			, FILE_SHARE_READ
			, nullptr
			, OPEN_EXISTING
			, FILE_FLAG_SEQUENTIAL_SCAN
			, nullptr);
#endif
	if (in_handle.handle() == INVALID_HANDLE_VALUE)
	{
		se.operation = operation_t::file_open;
		se.ec.assign(GetLastError(), system_category());
		return;
	}

#ifdef TORRENT_WINRT
	aux::win_file_handle out_handle = ::CreateFile2(f1.c_str()
			, GENERIC_WRITE
			, FILE_SHARE_WRITE
			, OPEN_ALWAYS
			, nullptr);
#else
	aux::win_file_handle out_handle = ::CreateFileW(f2.c_str()
			, GENERIC_WRITE
			, FILE_SHARE_WRITE
			, nullptr
			, OPEN_ALWAYS
			, FILE_FLAG_WRITE_THROUGH
			, nullptr);
#endif
	if (out_handle.handle() == INVALID_HANDLE_VALUE)
	{
		se.operation = operation_t::file_open;
		se.ec.assign(GetLastError(), system_category());
		return;
	}

	DWORD temp;
	if (::DeviceIoControl(out_handle.handle(), FSCTL_SET_SPARSE
		, nullptr, 0, nullptr, 0, &temp, nullptr) == 0)
	{
		se.operation = operation_t::iocontrol;
		se.ec.assign(GetLastError(), system_category());
		return;
	}

	std::pair<std::int64_t, std::int64_t> data(0, 0);
	for (;;)
	{
		data = next_allocated_region(in_handle.handle(), data.second, in_size, se.ec);
		if (se.ec)
		{
			se.operation = operation_t::iocontrol;
			return;
		}

		copy_range(in_handle.handle(), out_handle.handle(), data.first, data.second - data.first, se);
		if (se) return;
		// There's a possible time-of-check-time-of-use race here.
		// The source file may have grown during the copy operation, in which
		// case data.second may exceed the initial size
		if (data.second >= in_size) return;
	}
}

#else
// Generic/linux implementation

namespace {

struct copy_range_mode
{
	bool use_fallback = false;
};

ssize_t copy_range_fallback(int const fd_in, int const fd_out, off_t in_offset
	, std::int64_t len, storage_error& se)
{
	char buffer[16384];
	ssize_t total_copied = 0;
	while (len > 0)
	{
		ssize_t num_read = ::pread(fd_in, buffer
			, std::size_t(std::min(len, std::int64_t(sizeof(buffer)))), in_offset);
		if (num_read == 0) return total_copied;
		if (num_read < 0)
		{
			se.operation = operation_t::file_read;
			se.ec.assign(errno, system_category());
			return -1;
		}
		len -= num_read;
		int buf_offset = 0;
		while (num_read > 0)
		{
			auto const ret = ::pwrite(fd_out, buffer + buf_offset
				, std::size_t(num_read - buf_offset), in_offset);
			if (ret <= 0)
			{
				se.operation = operation_t::file_write;
				se.ec.assign(errno, system_category());
				return -1;
			}
			buf_offset += ret;
			num_read -= ret;
			in_offset += ret;
			total_copied += ret;
		}
	}
	return total_copied;
}

ssize_t copy_range(int const fd_in, int const fd_out, off_t in_offset
	, std::int64_t len, copy_range_mode* const m, storage_error& se)
{
#if TORRENT_HAS_COPY_FILE_RANGE
	if (m->use_fallback)
		return copy_range_fallback(fd_in, fd_out, in_offset, len, se);

	ssize_t total_copied = 0;
	off_t out_offset = in_offset;
	ssize_t ret = 0;
	do
	{
		ret = ::copy_file_range(fd_in, &in_offset
			, fd_out, &out_offset, std::size_t(len), 0);
		if (ret < 0)
		{
			int const err = errno;
			if (err == EXDEV || err == ENOTSUP)
			{
				m->use_fallback = true;
				return copy_range_fallback(fd_in, fd_out, in_offset, len, se);
			}
			se.operation = operation_t::file_copy;
			se.ec.assign(err, system_category());
			return -1;
		}

		len -= ret;
		total_copied += ret;
	} while (len > 0 && ret > 0);
	return total_copied;
#else
	TORRENT_UNUSED(m);
	return copy_range_fallback(fd_in, fd_out, in_offset, len, se);
#endif
}

} // anonymous namespace

void copy_file(std::string const& inf, std::string const& newf, storage_error& se)
{
	se.ec.clear();
	native_path_string f1 = convert_to_native_path_string(inf);
	native_path_string f2 = convert_to_native_path_string(newf);

	int read_flags = O_RDONLY;
#ifdef O_CLOEXEC
	read_flags |= O_CLOEXEC;
#endif
	aux::file_descriptor const infd = ::open(f1.c_str(), read_flags);
	if (infd.fd() < 0)
	{
		se.operation = operation_t::file_stat;
		se.ec.assign(errno, system_category());
		return;
	}

	struct stat in_stat;
	if (::fstat(infd.fd(), &in_stat) != 0)
	{
		se.operation = operation_t::file_stat;
		se.ec.assign(errno, system_category());
		return;
	}

	bool const input_is_sparse = in_stat.st_size > off_t(in_stat.st_blocks) * 512;

	// if the source file is not sparse we'll end up copying every byte anyway,
	// there's no point in passing O_TRUNC. However, in order to preserve sparse
	// regions, we *do* need to truncate the output file.
	int write_flags = O_RDWR | O_CREAT | (input_is_sparse ? O_TRUNC : 0);
#ifdef O_CLOEXEC
	write_flags |= O_CLOEXEC;
#endif
	aux::file_descriptor const outfd = ::open(f2.c_str(), write_flags, in_stat.st_mode);
	if (outfd.fd() < 0)
	{
		se.operation = operation_t::file_open;
		se.ec.assign(errno, system_category());
		return;
	}

#if TORRENT_HAS_COPYFILE
	if (!input_is_sparse)
	{
		// the the file isn't sparse use the system copy function (which
		// expands sparse regions)
		// this only works on 10.5
		copyfile_state_t state = copyfile_state_alloc();
		if (fcopyfile(infd.fd(), outfd.fd(), state, COPYFILE_ALL) < 0)
		{
			se.operation = operation_t::file_copy;
			se.ec.assign(errno, system_category());
		}
		copyfile_state_free(state);
		return;
	}
#endif

	if (::ftruncate(outfd.fd(), in_stat.st_size) < 0)
	{
		se.operation = operation_t::file_truncate;
		se.ec.assign(errno, system_category());
		return;
	}

#ifdef SEEK_HOLE
	if (input_is_sparse)
	{
		copy_range_mode m;
		ssize_t ret = 0;
		off_t data_start = 0;
		off_t data_end = 0;
		for (;;)
		{
			data_start = ::lseek(infd.fd(), data_end, SEEK_DATA);
			if (data_start == off_t(-1))
			{
				int const err = errno;
				// if we SEEK_DATA while the file location is past the last
				// non-sparse region (i.e. the file has been truncated without
				// filled in, the end of the file may be a sparse region). In
				// this case there's nothing left to copy, and we're done
				if (err == ENXIO) return;
				// if SEEK_DATA is not supported, fall back to plain copy
				if (err == ENOTSUP) break;
				se.operation = operation_t::file_seek;
				se.ec.assign(err, system_category());
				return;
			}

			data_end = ::lseek(infd.fd(), data_start, SEEK_HOLE);
			if (data_end == off_t(-1))
			{
				int const err = errno;
				if (err == ENOTSUP) break;
				se.operation = operation_t::file_seek;
				se.ec.assign(err, system_category());
				return;
			}

			ret = copy_range(infd.fd(), outfd.fd(), data_start, data_end - data_start, &m, se);
			if (ret <= 0) return;
			if (data_end == in_stat.st_size) return;
		}
	}
#endif

	copy_range_mode m;
	copy_range(infd.fd(), outfd.fd(), 0, in_stat.st_size, &m, se);
}

#endif // TORRENT_WINDOWS

}
}

