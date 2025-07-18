// generated by tools/gen_header.py

#ifndef LIBTORRENT_SETTINGS_H
#define LIBTORRENT_SETTINGS_H

// tags for session wide settings
enum settings_tags_t {
	SET_USER_AGENT = 0x200, // char const*
	SET_ANNOUNCE_IP, // char const*
	SET_HANDSHAKE_CLIENT_VERSION, // char const*
	SET_OUTGOING_INTERFACES, // char const*
	SET_LISTEN_INTERFACES, // char const*
	SET_PROXY_HOSTNAME, // char const*
	SET_PROXY_USERNAME, // char const*
	SET_PROXY_PASSWORD, // char const*
	SET_I2P_HOSTNAME, // char const*
	SET_PEER_FINGERPRINT, // char const*
	SET_DHT_BOOTSTRAP_NODES, // char const*
	SET_WEBTORRENT_STUN_SERVER, // char const*
	SET_ALLOW_MULTIPLE_CONNECTIONS_PER_IP, // int (0 or 1)
	SET_SEND_REDUNDANT_HAVE, // int (0 or 1)
	SET_USE_DHT_AS_FALLBACK, // int (0 or 1)
	SET_UPNP_IGNORE_NONROUTERS, // int (0 or 1)
	SET_USE_PAROLE_MODE, // int (0 or 1)
	SET_AUTO_MANAGE_PREFER_SEEDS, // int (0 or 1)
	SET_DONT_COUNT_SLOW_TORRENTS, // int (0 or 1)
	SET_CLOSE_REDUNDANT_CONNECTIONS, // int (0 or 1)
	SET_PRIORITIZE_PARTIAL_PIECES, // int (0 or 1)
	SET_RATE_LIMIT_IP_OVERHEAD, // int (0 or 1)
	SET_ANNOUNCE_TO_ALL_TIERS, // int (0 or 1)
	SET_ANNOUNCE_TO_ALL_TRACKERS, // int (0 or 1)
	SET_PREFER_UDP_TRACKERS, // int (0 or 1)
	SET_DISABLE_HASH_CHECKS, // int (0 or 1)
	SET_ALLOW_I2P_MIXED, // int (0 or 1)
	SET_NO_ATIME_STORAGE, // int (0 or 1)
	SET_INCOMING_STARTS_QUEUED_TORRENTS, // int (0 or 1)
	SET_REPORT_TRUE_DOWNLOADED, // int (0 or 1)
	SET_STRICT_END_GAME_MODE, // int (0 or 1)
	SET_ENABLE_OUTGOING_UTP, // int (0 or 1)
	SET_ENABLE_INCOMING_UTP, // int (0 or 1)
	SET_ENABLE_OUTGOING_TCP, // int (0 or 1)
	SET_ENABLE_INCOMING_TCP, // int (0 or 1)
	SET_NO_RECHECK_INCOMPLETE_RESUME, // int (0 or 1)
	SET_ANONYMOUS_MODE, // int (0 or 1)
	SET_REPORT_WEB_SEED_DOWNLOADS, // int (0 or 1)
	SET_SEEDING_OUTGOING_CONNECTIONS, // int (0 or 1)
	SET_NO_CONNECT_PRIVILEGED_PORTS, // int (0 or 1)
	SET_SMOOTH_CONNECTS, // int (0 or 1)
	SET_ALWAYS_SEND_USER_AGENT, // int (0 or 1)
	SET_APPLY_IP_FILTER_TO_TRACKERS, // int (0 or 1)
	SET_BAN_WEB_SEEDS, // int (0 or 1)
	SET_SUPPORT_SHARE_MODE, // int (0 or 1)
	SET_REPORT_REDUNDANT_BYTES, // int (0 or 1)
	SET_LISTEN_SYSTEM_PORT_FALLBACK, // int (0 or 1)
	SET_ANNOUNCE_CRYPTO_SUPPORT, // int (0 or 1)
	SET_ENABLE_UPNP, // int (0 or 1)
	SET_ENABLE_NATPMP, // int (0 or 1)
	SET_ENABLE_LSD, // int (0 or 1)
	SET_ENABLE_DHT, // int (0 or 1)
	SET_PREFER_RC4, // int (0 or 1)
	SET_PROXY_HOSTNAMES, // int (0 or 1)
	SET_PROXY_PEER_CONNECTIONS, // int (0 or 1)
	SET_AUTO_SEQUENTIAL, // int (0 or 1)
	SET_PROXY_TRACKER_CONNECTIONS, // int (0 or 1)
	SET_ENABLE_IP_NOTIFIER, // int (0 or 1)
	SET_DHT_PREFER_VERIFIED_NODE_IDS, // int (0 or 1)
	SET_DHT_RESTRICT_ROUTING_IPS, // int (0 or 1)
	SET_DHT_RESTRICT_SEARCH_IPS, // int (0 or 1)
	SET_DHT_EXTENDED_ROUTING_TABLE, // int (0 or 1)
	SET_DHT_AGGRESSIVE_LOOKUPS, // int (0 or 1)
	SET_DHT_PRIVACY_LOOKUPS, // int (0 or 1)
	SET_DHT_ENFORCE_NODE_ID, // int (0 or 1)
	SET_DHT_IGNORE_DARK_INTERNET, // int (0 or 1)
	SET_DHT_READ_ONLY, // int (0 or 1)
	SET_PIECE_EXTENT_AFFINITY, // int (0 or 1)
	SET_VALIDATE_HTTPS_TRACKERS, // int (0 or 1)
	SET_SSRF_MITIGATION, // int (0 or 1)
	SET_ALLOW_IDNA, // int (0 or 1)
	SET_ENABLE_SET_FILE_VALID_DATA, // int (0 or 1)
	SET_SOCKS5_UDP_SEND_LOCAL_EP, // int (0 or 1)
	SET_TRACKER_COMPLETION_TIMEOUT, // int
	SET_TRACKER_RECEIVE_TIMEOUT, // int
	SET_STOP_TRACKER_TIMEOUT, // int
	SET_TRACKER_MAXIMUM_RESPONSE_LENGTH, // int
	SET_PIECE_TIMEOUT, // int
	SET_REQUEST_TIMEOUT, // int
	SET_REQUEST_QUEUE_TIME, // int
	SET_MAX_ALLOWED_IN_REQUEST_QUEUE, // int
	SET_MAX_OUT_REQUEST_QUEUE, // int
	SET_WHOLE_PIECES_THRESHOLD, // int
	SET_PEER_TIMEOUT, // int
	SET_URLSEED_TIMEOUT, // int
	SET_URLSEED_PIPELINE_SIZE, // int
	SET_URLSEED_WAIT_RETRY, // int
	SET_FILE_POOL_SIZE, // int
	SET_MAX_FAILCOUNT, // int
	SET_MIN_RECONNECT_TIME, // int
	SET_PEER_CONNECT_TIMEOUT, // int
	SET_CONNECTION_SPEED, // int
	SET_INACTIVITY_TIMEOUT, // int
	SET_UNCHOKE_INTERVAL, // int
	SET_OPTIMISTIC_UNCHOKE_INTERVAL, // int
	SET_NUM_WANT, // int
	SET_INITIAL_PICKER_THRESHOLD, // int
	SET_ALLOWED_FAST_SET_SIZE, // int
	SET_SUGGEST_MODE, // int
	SET_MAX_QUEUED_DISK_BYTES, // int
	SET_HANDSHAKE_TIMEOUT, // int
	SET_SEND_BUFFER_LOW_WATERMARK, // int
	SET_SEND_BUFFER_WATERMARK, // int
	SET_SEND_BUFFER_WATERMARK_FACTOR, // int
	SET_CHOKING_ALGORITHM, // int
	SET_SEED_CHOKING_ALGORITHM, // int
	SET_DISK_IO_WRITE_MODE, // int
	SET_DISK_IO_READ_MODE, // int
	SET_OUTGOING_PORT, // int
	SET_NUM_OUTGOING_PORTS, // int
	SET_PEER_DSCP, // int
	SET_PEER_TOS, // int
	SET_ACTIVE_DOWNLOADS, // int
	SET_ACTIVE_SEEDS, // int
	SET_ACTIVE_CHECKING, // int
	SET_ACTIVE_DHT_LIMIT, // int
	SET_ACTIVE_TRACKER_LIMIT, // int
	SET_ACTIVE_LSD_LIMIT, // int
	SET_ACTIVE_LIMIT, // int
	SET_AUTO_MANAGE_INTERVAL, // int
	SET_SEED_TIME_LIMIT, // int
	SET_AUTO_SCRAPE_INTERVAL, // int
	SET_AUTO_SCRAPE_MIN_INTERVAL, // int
	SET_MAX_PEERLIST_SIZE, // int
	SET_MAX_PAUSED_PEERLIST_SIZE, // int
	SET_MIN_ANNOUNCE_INTERVAL, // int
	SET_AUTO_MANAGE_STARTUP, // int
	SET_SEEDING_PIECE_QUOTA, // int
	SET_MAX_REJECTS, // int
	SET_RECV_SOCKET_BUFFER_SIZE, // int
	SET_SEND_SOCKET_BUFFER_SIZE, // int
	SET_MAX_PEER_RECV_BUFFER_SIZE, // int
	SET_OPTIMISTIC_DISK_RETRY, // int
	SET_MAX_SUGGEST_PIECES, // int
	SET_LOCAL_SERVICE_ANNOUNCE_INTERVAL, // int
	SET_DHT_ANNOUNCE_INTERVAL, // int
	SET_UDP_TRACKER_TOKEN_EXPIRY, // int
	SET_NUM_OPTIMISTIC_UNCHOKE_SLOTS, // int
	SET_MAX_PEX_PEERS, // int
	SET_TICK_INTERVAL, // int
	SET_SHARE_MODE_TARGET, // int
	SET_UPLOAD_RATE_LIMIT, // int
	SET_DOWNLOAD_RATE_LIMIT, // int
	SET_DHT_UPLOAD_RATE_LIMIT, // int
	SET_UNCHOKE_SLOTS_LIMIT, // int
	SET_CONNECTIONS_LIMIT, // int
	SET_CONNECTIONS_SLACK, // int
	SET_UTP_TARGET_DELAY, // int
	SET_UTP_GAIN_FACTOR, // int
	SET_UTP_MIN_TIMEOUT, // int
	SET_UTP_SYN_RESENDS, // int
	SET_UTP_FIN_RESENDS, // int
	SET_UTP_NUM_RESENDS, // int
	SET_UTP_CONNECT_TIMEOUT, // int
	SET_UTP_LOSS_MULTIPLIER, // int
	SET_MIXED_MODE_ALGORITHM, // int
	SET_LISTEN_QUEUE_SIZE, // int
	SET_TORRENT_CONNECT_BOOST, // int
	SET_ALERT_QUEUE_SIZE, // int
	SET_MAX_METADATA_SIZE, // int
	SET_HASHING_THREADS, // int
	SET_CHECKING_MEM_USAGE, // int
	SET_PREDICTIVE_PIECE_ANNOUNCE, // int
	SET_AIO_THREADS, // int
	SET_TRACKER_BACKOFF, // int
	SET_SHARE_RATIO_LIMIT, // int
	SET_SEED_TIME_RATIO_LIMIT, // int
	SET_PEER_TURNOVER, // int
	SET_PEER_TURNOVER_CUTOFF, // int
	SET_PEER_TURNOVER_INTERVAL, // int
	SET_CONNECT_SEED_EVERY_N_DOWNLOAD, // int
	SET_MAX_HTTP_RECV_BUFFER_SIZE, // int
	SET_MAX_RETRY_PORT_BIND, // int
	SET_ALERT_MASK, // int
	SET_OUT_ENC_POLICY, // int
	SET_IN_ENC_POLICY, // int
	SET_ALLOWED_ENC_LEVEL, // int
	SET_INACTIVE_DOWN_RATE, // int
	SET_INACTIVE_UP_RATE, // int
	SET_PROXY_TYPE, // int
	SET_PROXY_PORT, // int
	SET_I2P_PORT, // int
	SET_URLSEED_MAX_REQUEST_BYTES, // int
	SET_WEB_SEED_NAME_LOOKUP_RETRY, // int
	SET_CLOSE_FILE_INTERVAL, // int
	SET_UTP_CWND_REDUCE_TIMER, // int
	SET_MAX_WEB_SEED_CONNECTIONS, // int
	SET_RESOLVER_CACHE_TIMEOUT, // int
	SET_SEND_NOT_SENT_LOW_WATERMARK, // int
	SET_RATE_CHOKER_INITIAL_THRESHOLD, // int
	SET_UPNP_LEASE_DURATION, // int
	SET_MAX_CONCURRENT_HTTP_ANNOUNCES, // int
	SET_DHT_MAX_PEERS_REPLY, // int
	SET_DHT_SEARCH_BRANCHING, // int
	SET_DHT_MAX_FAIL_COUNT, // int
	SET_DHT_MAX_TORRENTS, // int
	SET_DHT_MAX_DHT_ITEMS, // int
	SET_DHT_MAX_PEERS, // int
	SET_DHT_MAX_TORRENT_SEARCH_REPLY, // int
	SET_DHT_BLOCK_TIMEOUT, // int
	SET_DHT_BLOCK_RATELIMIT, // int
	SET_DHT_ITEM_LIFETIME, // int
	SET_DHT_SAMPLE_INFOHASHES_INTERVAL, // int
	SET_DHT_MAX_INFOHASHES_SAMPLE_COUNT, // int
	SET_MAX_PIECE_COUNT, // int
	SET_METADATA_TOKEN_LIMIT, // int
	SET_DISK_WRITE_MODE, // int
	SET_MMAP_FILE_SIZE_CUTOFF, // int
	SET_I2P_INBOUND_QUANTITY, // int
	SET_I2P_OUTBOUND_QUANTITY, // int
	SET_I2P_INBOUND_LENGTH, // int
	SET_I2P_OUTBOUND_LENGTH, // int
	SET_ANNOUNCE_PORT, // int
	SET_I2P_INBOUND_LENGTH_VARIANCE, // int
	SET_I2P_OUTBOUND_LENGTH_VARIANCE, // int
	SET_MIN_WEBSOCKET_ANNOUNCE_INTERVAL, // int
	SET_WEBTORRENT_CONNECTION_TIMEOUT, // int
};

#endif // LIBTORRENT_SETTINGS_H
