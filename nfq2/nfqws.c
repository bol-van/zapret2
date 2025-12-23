#define _GNU_SOURCE

#include "nfqws.h"
#include "sec.h"
#include "desync.h"
#include "helpers.h"
#include "checksum.h"
#include "params.h"
#include "protocol.h"
#include "hostlist.h"
#include "ipset.h"
#include "gzip.h"
#include "pools.h"
#include "lua.h"
#include "crypto/aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <syslog.h>
#include <grp.h>

#ifdef __CYGWIN__
#include "win.h"
#endif

#ifdef USE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef __linux__
#include <libnetfilter_queue/libnetfilter_queue.h>
#define NF_DROP 0
#define NF_ACCEPT 1
#endif

#define MAX_CONFIG_FILE_SIZE 16384

struct params_s params;
static bool bReload = false;
#ifdef __CYGWIN__
bool bQuit = false;
#endif

static void onhup(int sig)
{
	printf("HUP received ! Lists will be reloaded.\n");
	bReload = true;
}
static void ReloadCheck()
{
	if (bReload)
	{
		ResetAllHostlistsModTime();
		if (!LoadAllHostLists())
		{
			DLOG_ERR("hostlists load failed. this is fatal.\n");
			exit(1);
		}
		ResetAllIpsetModTime();
		if (!LoadAllIpsets())
		{
			DLOG_ERR("ipset load failed. this is fatal.\n");
			exit(1);
		}
		bReload = false;
	}
}

static void onusr1(int sig)
{
	printf("\nCONNTRACK DUMP\n");
	ConntrackPoolDump(&params.conntrack);
	printf("\n");
}
static void onusr2(int sig)
{
	printf("\nHOSTFAIL POOL DUMP\n");

	struct desync_profile_list *dpl;
	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		printf("\nDESYNC profile %u (%s)\n", dpl->dp.n, PROFILE_NAME(&dpl->dp));
		HostFailPoolDump(dpl->dp.hostlist_auto_fail_counters);
	}
	printf("\nIPCACHE\n");
	ipcachePrint(&params.ipcache);
	printf("\n");
}

static void pre_desync(void)
{
	signal(SIGHUP, onhup);
	signal(SIGUSR1, onusr1);
	signal(SIGUSR2, onusr2);
}


static uint8_t processPacketData(uint32_t *mark, const char *ifin, const char *ifout, const uint8_t *data_pkt, size_t len_pkt, uint8_t *mod_pkt, size_t *len_mod_pkt)
{
#ifdef __linux__
	if (*mark & params.desync_fwmark)
	{
		DLOG("ignoring generated packet\n");
		return VERDICT_PASS;
	}
#endif
	return dpi_desync_packet(*mark, ifin, ifout, data_pkt, len_pkt, mod_pkt, len_mod_pkt);
}


static bool test_list_files()
{
	struct hostlist_file *hfile;
	struct ipset_file *ifile;

	LIST_FOREACH(hfile, &params.hostlists, next)
		if (hfile->filename && !file_open_test(hfile->filename, O_RDONLY))
		{
			DLOG_PERROR("file_open_test");
			DLOG_ERR("cannot access hostlist file '%s'\n", hfile->filename);
			return false;
		}
	LIST_FOREACH(ifile, &params.ipsets, next)
		if (ifile->filename && !file_open_test(ifile->filename, O_RDONLY))
		{
			DLOG_PERROR("file_open_test");
			DLOG_ERR("cannot access ipset file '%s'\n", ifile->filename);
			return false;
		}
	return true;
}


#ifdef __linux__
static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *cookie)
{
	int id, ilen;
	size_t len;
	struct nfqnl_msg_packet_hdr *ph;
	uint8_t *data;
	uint32_t ifidx_out, ifidx_in;
	char ifout[IFNAMSIZ], ifin[IFNAMSIZ];
	uint8_t mod[RECONSTRUCT_MAX_SIZE];
	size_t modlen;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ph ? ntohl(ph->packet_id) : 0;

	uint32_t mark = nfq_get_nfmark(nfa);
	ilen = nfq_get_payload(nfa, &data);

	ifidx_out = nfq_get_outdev(nfa);
	*ifout = 0;
	if (ifidx_out) if_indextoname(ifidx_out, ifout);

	ifidx_in = nfq_get_indev(nfa);
	*ifin = 0;
	if (ifidx_in) if_indextoname(ifidx_in, ifin);

	DLOG("\npacket: id=%d len=%d mark=%08X ifin=%s(%u) ifout=%s(%u)\n", id, ilen, mark, ifin, ifidx_in, ifout, ifidx_out);

	if (ilen >= 0)
	{
		len = ilen;
		modlen = sizeof(mod);
		// there's no space to grow packet in recv blob from nfqueue. it can contain multiple packets with no extra buffer length for modifications.
		// to support increased sizes use separate mod buffer
		// this is not a problem because only LUA code can trigger VERDICT_MODIFY (and postnat workaround too, once a connection if first packet is dropped)
		// in case of VERIDCT_MODIFY packet is always reconstructed from dissect, so no difference where to save the data => no performance loss
		uint8_t verdict = processPacketData(&mark, ifin, ifout, data, len, mod, &modlen);
		switch (verdict & VERDICT_MASK)
		{
		case VERDICT_MODIFY:
			DLOG("packet: id=%d pass modified. len %zu => %zu\n", id, len, modlen);
			return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, (uint32_t)modlen, mod);
		case VERDICT_DROP:
			DLOG("packet: id=%d drop\n", id);
			return nfq_set_verdict2(qh, id, NF_DROP, mark, 0, NULL);
		}
	}
	DLOG("packet: id=%d pass unmodified\n", id);
	return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
}
static void nfq_deinit(struct nfq_handle **h, struct nfq_q_handle **qh)
{
	if (*qh)
	{
		DLOG_CONDUP("unbinding from queue %u\n", params.qnum);
		nfq_destroy_queue(*qh);
		*qh = NULL;
	}
	if (*h)
	{
		DLOG_CONDUP("closing nfq library handle\n");
		nfq_close(*h);
		*h = NULL;
	}
}
static bool nfq_init(struct nfq_handle **h, struct nfq_q_handle **qh)
{
	nfq_deinit(h, qh);

	DLOG_CONDUP("opening nfq library handle\n");
	*h = nfq_open();
	if (!*h) {
		DLOG_PERROR("nfq_open()");
		goto exiterr;
	}

	DLOG_CONDUP("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(*h, AF_INET) < 0) {
		DLOG_PERROR("nfq_unbind_pf()");
		goto exiterr;
	}

	DLOG_CONDUP("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(*h, AF_INET) < 0) {
		DLOG_PERROR("nfq_bind_pf()");
		goto exiterr;
	}

	DLOG_CONDUP("binding this socket to queue '%u'\n", params.qnum);
	*qh = nfq_create_queue(*h, params.qnum, &nfq_cb, &params);
	if (!*qh) {
		DLOG_PERROR("nfq_create_queue()");
		goto exiterr;
	}

	DLOG_CONDUP("setting copy_packet mode\n");
	if (nfq_set_mode(*qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		DLOG_PERROR("can't set packet_copy mode");
		goto exiterr;
	}
	if (nfq_set_queue_maxlen(*qh, Q_MAXLEN) < 0) {
		DLOG_PERROR("can't set queue maxlen");
		goto exiterr;
	}
	// accept packets if they cant be handled
	if (nfq_set_queue_flags(*qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN))
	{
		DLOG_ERR("can't set queue flags. its OK on linux <3.6\n");
		// dot not fail. not supported on old linuxes <3.6 
	}

	int yes = 1, fd = nfq_fd(*h);

#if defined SOL_NETLINK && defined NETLINK_NO_ENOBUFS
	if (setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &yes, sizeof(yes)) == -1)
		DLOG_PERROR("setsockopt(NETLINK_NO_ENOBUFS)");
#endif

	return true;
exiterr:
	nfq_deinit(h, qh);
	return false;
}

static void notify_ready(void)
{
#ifdef USE_SYSTEMD
	int r = sd_notify(0, "READY=1");
	if (r < 0)
		DLOG_ERR("sd_notify: %s\n", strerror(-r));
#endif
}

static int nfq_main(void)
{
	uint8_t buf[RECONSTRUCT_MAX_SIZE] __attribute__((aligned));
	struct nfq_handle *h = NULL;
	struct nfq_q_handle *qh = NULL;
	int res, fd, e;
	ssize_t rd;
	FILE *Fpid = NULL;

	if (*params.pidfile && !(Fpid = fopen(params.pidfile, "w")))
	{
		DLOG_PERROR("create pidfile");
		return 1;
	}

	if (params.droproot && !droproot(params.uid, params.user, params.gid, params.gid_count) || !dropcaps())
		goto err;
	print_id();
	if (params.droproot && !test_list_files())
		goto err;
	if (!lua_test_init_script_files())
		goto err;

	sec_harden();

	DLOG_CONDUP("initializing raw sockets bind-fix4=%u bind-fix6=%u\n", params.bind_fix4, params.bind_fix6);
	if (!rawsend_preinit(params.bind_fix4, params.bind_fix6))
		goto err;

	if (!lua_init())
		goto err;

	if (!nfq_init(&h, &qh))
		goto err;

#ifdef HAS_FILTER_SSID
	if (params.filter_ssid_present)
	{
		if (!wlan_info_init())
		{
			DLOG_ERR("cannot initialize wlan info capture\n");
			goto err;
		}
		DLOG("wlan info capture initialized\n");
	}
#endif

	if (params.daemon) daemonize();

	if (Fpid)
	{
		if (fprintf(Fpid, "%d", getpid()) <= 0)
		{
			DLOG_PERROR("write pidfile");
			goto err;
		}
		fclose(Fpid);
		Fpid = NULL;
	}

	pre_desync();
	notify_ready();

	fd = nfq_fd(h);
	do
	{
		while ((rd = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			ReloadCheck();
			lua_do_gc();
#ifdef HAS_FILTER_SSID
			if (params.filter_ssid_present)
				if (!wlan_info_get_rate_limited())
					DLOG_ERR("cannot get wlan info\n");
#endif
			if (rd)
			{
				int r = nfq_handle_packet(h, (char *)buf, (int)rd);
				if (r) DLOG_ERR("nfq_handle_packet error %d\n", r);
			}
			else
				DLOG("recv from nfq returned 0 !\n");
		}
		e = errno;
		DLOG_ERR("recv: recv=%zd errno %d\n", rd, e);
		errno = e;
		DLOG_PERROR("recv");
		// do not fail on ENOBUFS
	} while (e == ENOBUFS);

	res=0;
ex:
	nfq_deinit(&h, &qh);
	lua_shutdown();
#ifdef HAS_FILTER_SSID
	wlan_info_deinit();
#endif
	return res;
err:
	if (Fpid) fclose(Fpid);
	res=1;
	goto ex;
}

#elif defined(BSD)

static int dvt_main(void)
{
	uint8_t buf[RECONSTRUCT_MAX_SIZE] __attribute__((aligned));
	struct sockaddr_storage sa_from;
	int fd[2] = { -1,-1 }; // 4,6
	int i, r, res = 1, fdct = 1, fdmax;
	unsigned int id = 0;
	socklen_t socklen;
	ssize_t rd, wr;
	fd_set fdset;
	FILE *Fpid = NULL;

	if (*params.pidfile && !(Fpid = fopen(params.pidfile, "w")))
	{
		DLOG_PERROR("create pidfile");
		return 1;
	}

	{
		struct sockaddr_in bp4;
		bp4.sin_family = AF_INET;
		bp4.sin_port = htons(params.port);
		bp4.sin_addr.s_addr = INADDR_ANY;

		DLOG_CONDUP("creating divert4 socket\n");
		fd[0] = socket_divert(AF_INET);
		if (fd[0] == -1) {
			DLOG_PERROR("socket (DIVERT4)");
			goto exiterr;
		}
		DLOG_CONDUP("binding divert4 socket\n");
		if (bind(fd[0], (struct sockaddr*)&bp4, sizeof(bp4)) < 0)
		{
			DLOG_PERROR("bind (DIVERT4)");
			goto exiterr;
		}
	}


#ifdef __OpenBSD__
	{
		// in OpenBSD must use separate divert sockets for ipv4 and ipv6
		struct sockaddr_in6 bp6;
		memset(&bp6, 0, sizeof(bp6));
		bp6.sin6_family = AF_INET6;
		bp6.sin6_port = htons(params.port);

		DLOG_CONDUP("creating divert6 socket\n");
		fd[1] = socket_divert(AF_INET6);
		if (fd[1] == -1) {
			DLOG_PERROR("socket (DIVERT6)");
			goto exiterr;
		}
		DLOG_CONDUP("binding divert6 socket\n");
		if (bind(fd[1], (struct sockaddr*)&bp6, sizeof(bp6)) < 0)
		{
			DLOG_PERROR("bind (DIVERT6)");
			goto exiterr;
		}
		fdct++;
	}
#endif
	fdmax = (fd[0] > fd[1] ? fd[0] : fd[1]) + 1;

	DLOG_CONDUP("initializing raw sockets\n");
	if (!rawsend_preinit(false, false))
		goto exiterr;


	if (params.droproot && !droproot(params.uid, params.user, params.gid, params.gid_count))
		goto exiterr;
	print_id();
	if (params.droproot && !test_list_files())
		goto exiterr;
	if (!lua_test_init_script_files())
		goto exiterr;

	if (!lua_init())
		goto exiterr;

	if (params.daemon) daemonize();

	if (Fpid)
	{
		if (fprintf(Fpid, "%d", getpid()) <= 0)
		{
			DLOG_PERROR("write pidfile");
			goto exiterr;
		}
		fclose(Fpid);
		Fpid = NULL;
	}

	pre_desync();

	for (;;)
	{
		FD_ZERO(&fdset);
		for (i = 0; i < fdct; i++) FD_SET(fd[i], &fdset);
		r = select(fdmax, &fdset, NULL, NULL, NULL);
		if (r == -1)
		{
			if (errno == EINTR)
			{
				// a signal received
				continue;
			}
			DLOG_PERROR("select");
			goto exiterr;
		}
		for (i = 0; i < fdct; i++)
		{
			if (FD_ISSET(fd[i], &fdset))
			{
				socklen = sizeof(sa_from);
				rd = recvfrom(fd[i], buf, sizeof(buf), 0, (struct sockaddr*)&sa_from, &socklen);
				if (rd < 0)
				{
					DLOG_PERROR("recvfrom");
					goto exiterr;
				}
				else if (rd > 0)
				{
					uint32_t mark = 0;
					uint8_t verdict;
					size_t modlen, len = rd;
					const char *ifin, *ifout;

					ReloadCheck();
					lua_do_gc();

					// in any BSD addr of incoming packet is set to the first addr of the interface. addr of outgoing packet is set to zero
					bool bIncoming = sa_has_addr((struct sockaddr*)&sa_from);
					ifin = bIncoming ? "unknown" : "";
					ifout = bIncoming ? "" : "unknown";
#ifdef __FreeBSD__
					// FreeBSD passes ifname of incoming interface in 8 bytes after sin_addr
					// it always sets family to AF_INET despite of ip version
					char ifname[9];
					if (bIncoming && sa_from.ss_family==AF_INET)
					{
						const char *p = ((char*)&((struct sockaddr_in *)&sa_from)->sin_addr)+sizeof(struct in_addr);
						if (*p)
						{
							memcpy(ifname, p, 8);
							ifname[8] = 0;
							ifin = ifname;
						}
					}
#endif

					DLOG("\npacket: id=%u len=%zu ifin=%s ifout=%s\n", id, len, ifin, ifout);
					modlen = sizeof(buf);
					verdict = processPacketData(&mark, NULL, NULL, buf, len, buf, &modlen);
					switch (verdict & VERDICT_MASK)
					{
					case VERDICT_PASS:
					case VERDICT_MODIFY:
						if ((verdict & VERDICT_MASK) == VERDICT_PASS)
						{
							DLOG("packet: id=%u reinject unmodified\n", id);
							modlen = len;
						}
						else
							DLOG("packet: id=%u reinject modified len %zu => %zu\n", id, len, modlen);
						wr = sendto(fd[i], buf, modlen, 0, (struct sockaddr*)&sa_from, socklen);
						if (wr < 0)
							DLOG_PERROR("reinject sendto");
						else if (wr != modlen)
							DLOG_ERR("reinject sendto: not all data was reinjected. received %zu, sent %zd\n", len, wr);
						break;
					default:
						DLOG("packet: id=%u drop\n", id);
					}
					id++;
				}
				else
				{
					DLOG("unexpected zero size recvfrom\n");
				}
			}
		}
	}

	res = 0;
exiterr:
	if (Fpid) fclose(Fpid);
	if (fd[0] != -1) close(fd[0]);
	if (fd[1] != -1) close(fd[1]);
	lua_shutdown();
	return res;
}


#elif defined (__CYGWIN__)

static int win_main()
{
	size_t len, modlen;
	unsigned int id;
	uint8_t verdict;
	bool bOutbound;
	uint8_t packet[RECONSTRUCT_MAX_SIZE];
	uint32_t mark;
	WINDIVERT_ADDRESS wa;
	char ifname[IFNAMSIZ];
	int res=0;

	if (params.daemon) daemonize();

	if (*params.pidfile && !writepid(params.pidfile))
	{
		DLOG_ERR("could not write pidfile");
		return ERROR_TOO_MANY_OPEN_FILES; // code 4 = The system cannot open the file
	}

	if (!win_dark_init(&params.ssid_filter, &params.nlm_filter))
	{
		DLOG_ERR("win_dark_init failed. win32 error %u (0x%08X)\n", w_win32_error, w_win32_error);
		res=w_win32_error; goto ex;
	}

	pre_desync();

	for (;;)
	{
		if (!logical_net_filter_match())
		{
			DLOG_CONDUP("logical network is not present. waiting it to appear.\n");
			do
			{
				if (bQuit)
				{
					DLOG("QUIT requested\n");
					goto ex;
				}
				usleep(500000);
			} while (!logical_net_filter_match());
			DLOG_CONDUP("logical network now present\n");
		}

		if (!windivert_init(params.windivert_filter))
		{
			res=w_win32_error; goto ex;
		}

		if (!win_sandbox())
		{
			res=w_win32_error;
			DLOG_ERR("Cannot init Windows sandbox\n");
			goto ex;
		}

		// init LUA only here because of possible sandbox. no LUA code with high privs
		if (!params.L && !lua_init())
		{
			res=ERROR_INVALID_PARAMETER; goto ex;
		}

		DLOG_CONDUP("windivert initialized. capture is started.\n");

		for (id = 0;; id++)
		{
			len = sizeof(packet);
			if (!windivert_recv(packet, &len, &wa))
			{
				if (errno == ENOBUFS)
				{
					DLOG("windivert: ignoring too large packet\n");
					continue; // too large packet
				}
				else if (errno == ENODEV)
				{
					DLOG_CONDUP("logical network disappeared. deinitializing windivert.\n");
					rawsend_cleanup();
					break;
				}
				else if (errno == EINTR)
				{
					DLOG("QUIT requested\n");
					goto ex;
				}
				DLOG_ERR("windivert: recv failed. errno %d\n", errno);
				res=w_win32_error;
				goto ex;
			}

			ReloadCheck();
			lua_do_gc();

			*ifname = 0;
			snprintf(ifname, sizeof(ifname), "%u.%u", wa.Network.IfIdx, wa.Network.SubIfIdx);
			DLOG("\npacket: id=%u len=%zu %s IPv6=%u IPChecksum=%u TCPChecksum=%u UDPChecksum=%u IfIdx=%u.%u\n", id, len, wa.Outbound ? "outbound" : "inbound", wa.IPv6, wa.IPChecksum, wa.TCPChecksum, wa.UDPChecksum, wa.Network.IfIdx, wa.Network.SubIfIdx);
			if (wa.Impostor)
			{
				DLOG("windivert: passing impostor packet\n");
				verdict = VERDICT_PASS;
			}
			else if (wa.Loopback)
			{
				DLOG("windivert: passing loopback packet\n");
				verdict = VERDICT_PASS;
			}
			else
			{
				mark = 0;
				// pseudo interface id IfIdx.SubIfIdx
				modlen = sizeof(packet);
				verdict = processPacketData(&mark, wa.Outbound ? "" : ifname, wa.Outbound ? ifname : "", packet, len, packet, &modlen);
			}
			switch (verdict & VERDICT_MASK)
			{
			case VERDICT_PASS:
				DLOG("packet: id=%u reinject unmodified\n", id);
				if (!windivert_send(packet, len, &wa))
					DLOG_ERR("windivert: reinject of packet id=%u failed\n", id);
				break;
			case VERDICT_MODIFY:
				DLOG("packet: id=%u reinject modified len %zu => %zu\n", id, len, modlen);
				if (!windivert_send(packet, modlen, &wa))
					DLOG_ERR("windivert: reinject of packet id=%u failed\n", id);
				break;
			default:
				DLOG("packet: id=%u drop\n", id);
			}
		}
	}
ex:
	win_dark_deinit();
	lua_shutdown();
	return res;
}

#endif // multiple OS divert handlers




static void exit_clean(int code)
{
	cleanup_params(&params);

	exit(code);
}


static bool is_hexstring(const char *filename)
{
	return filename[0] == '0' && filename[1] == 'x';
}
static bool parse_filespec(const char **filename, unsigned long long *ofs)
{
	*ofs = 0;
	if (**filename == '+')
	{
		(*filename)++;
		if (sscanf(*filename, "%llu", ofs) != 1)
		{
			DLOG("offset read error: %s\n", *filename);
			return false;
		}
		while (**filename && **filename != '@') (*filename)++;
		if (**filename == '@') (*filename)++;
	}
	else if (**filename == '@')
		(*filename)++;
	return true;
}

static void load_file_or_exit(const char *filename, void *buf, size_t *size)
{
	unsigned long long ofs;

	// 0xaabbcc
	// filename
	// @filename
	// +123@filename

	if (is_hexstring(filename))
	{
		if (!parse_hex_str(filename + 2, buf, size) || !*size)
		{
			DLOG_ERR("invalid hex string: %s\n", filename + 2);
			exit_clean(1);
		}
		DLOG("read %zu bytes from hex string\n", *size);
	}
	else
	{
		if (!parse_filespec(&filename, &ofs))
			exit_clean(1);
		if (!load_file(filename, ofs, buf, size))
		{
			DLOG_ERR("could not read '%s'\n", filename);
			exit_clean(1);
		}
		DLOG("read %zu bytes from '%s'. offset=%zu\n", *size, filename, ofs);
	}
}

static char* item_name(char **str)
{
	char *s,*p;
	size_t l;

	l = (s = strchr(*str,':')) ? s-*str : strlen(*str);
	if (!(p = malloc(l+1)))
	{
		DLOG_ERR("out of memory\n");
		return NULL;
	}
	memcpy(p,*str,l);
	p[l]=0;
	if (!is_identifier(p))
	{
		DLOG_ERR("bad identifier '%s'\n",p);
		free(p);
		return NULL;
	}
	*str = s ? s+1 : *str+l;
	return p;
}

static struct blob_item *load_blob_to_collection(const char *filename, struct blob_collection_head *blobs, size_t max_size, size_t size_reserve)
{
	struct blob_item *blob = blob_collection_add(blobs);
	uint8_t *p;
	char *name;

	if (!(name = item_name((char**)&filename)))
		exit_clean(1);

	if (!is_hexstring(filename))
	{
		const char *fn = filename;
		unsigned long long ofs;
		off_t fsize;

		if (!parse_filespec(&fn, &ofs))
		{
			free(name);
			exit_clean(1);
		}
		if (!file_size(fn,&fsize))
		{
			free(name);
			DLOG_ERR("cannot access file '%s'\n",fn);
			exit_clean(1);
		}
		if (fsize)
		{
			if (ofs >= fsize)
			{
				free(name);
				DLOG_ERR("offset %llu is beyond file size %llu\n", ofs, (uint64_t)fsize);
				exit_clean(1);
			}
			max_size = fsize - ofs;
		}
	}

	if (blob_collection_search_name(blobs,name))
	{
		DLOG_ERR("duplicate blob name '%s'\n",name);
		free(name);
		exit_clean(1);
	}
	if (!blob || (!(blob->data = malloc(max_size + size_reserve))))
	{
		free(name);
		DLOG_ERR("out of memory\n");
		exit_clean(1);
	}
	blob->size = max_size;
	blob->name = name;
	load_file_or_exit(filename, blob->data, &blob->size);

	p = realloc(blob->data, blob->size + size_reserve);
	if (!p)
	{
		DLOG_ERR("out of memory\n");
		exit_clean(1);
	}
	blob->data = p;

	blob->size_buf = blob->size + size_reserve;
	return blob;
}
static struct blob_item *load_const_blob_to_collection(const char *name, const void *data, size_t sz, struct blob_collection_head *blobs, size_t size_reserve)
{
	if (blob_collection_search_name(blobs,name))
	{
		DLOG_ERR("duplicate blob name '%s'\n",name);
		exit_clean(1);
	}
	struct blob_item *blob = blob_collection_add(blobs);
	if (!blob || (!(blob->data = malloc(sz + size_reserve))) || !(blob->name = strdup(name)))
	{
		DLOG_ERR("out of memory\n");
		exit_clean(1);
	}
	blob->size = sz;
	blob->size_buf = sz + size_reserve;
	memcpy(blob->data, data, sz);
	return blob;
}




static bool parse_uid(const char *opt, uid_t *uid, gid_t *gid, int *gid_count, int max_gids)
{
	unsigned int u;
	char c, *p, *e;

	*gid_count = 0;
	if ((e = strchr(optarg, ':'))) *e++ = 0;
	if (sscanf(opt, "%u", &u) != 1) return false;
	*uid = (uid_t)u;
	for (p = e; p; )
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}
		if (p)
		{
			if (sscanf(p, "%u", &u) != 1) return false;
			if (*gid_count >= max_gids) return false;
			gid[(*gid_count)++] = (gid_t)u;
		}
		if (e) *e++ = c;
		p = e;
	}
	return true;
}

static bool parse_l7_list(char *opt, uint64_t *l7)
{
	char *e, *p, c;
	t_l7proto proto;

	for (p = opt, *l7 = 0; p; )
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}

		if ((proto=l7proto_from_name(p))==L7_INVALID)
			return false;
		else if (proto==L7_ALL)
		{
			*l7 = 0;
			break;
		}
		else
			*l7 |= 1<<proto;

		if (e) *e++ = c;
		p = e;
	}
	return true;
}
static bool parse_l7p_list(char *opt, uint64_t *l7p)
{
	char *e, *p, c;
	t_l7payload payload;

	for (p = opt, *l7p = 0; p; )
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}

		if ((payload=l7payload_from_name(p))==L7P_INVALID)
			return false;
		else if (payload==L7P_ALL)
		{
			*l7p = 0;
			break;
		}
		else
			*l7p |= 1<<payload;

		if (e) *e++ = c;
		p = e;
	}
	return true;
}

static bool parse_pf_list(char *opt, struct port_filters_head *pfl)
{
	char *e, *p, c;
	port_filter pf;
	bool b;

	for (p = opt; p; )
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}

		b = pf_parse(p, &pf) && port_filter_add(pfl, &pf);
		if (e) *e++ = c;
		if (!b) return false;

		p = e;
	}
	return true;
}

bool lua_call_param_add(char *opt, struct str2_list_head *args)
{
	char c,*p;
	struct str2_list *arg;

	if ((p = strchr(opt,'=')))
	{
		c = *p; *p = 0;
	}
	if (!is_identifier(opt) || !(arg=str2list_add(args)))
	{
		if (p) *p = c;
		return false;
	}
	arg->str1 = strdup(opt);
	if (p)
	{
		arg->str2 = strdup(p+1);
		*p = c;
		if (!arg->str2) return false;
	}
	return !!arg->str1;
}

struct func_list *parse_lua_call(char *opt, struct func_list_head *flist)
{
	char *name, *e, *p, c;
	bool b,last;
	struct func_list *f = NULL;

	if (!(name = item_name(&opt)))
		return false;

	if (!is_identifier(name) || !(f=funclist_add_tail(flist,name)))
		goto err;

	for (p = opt; p && *p; )
	{
		for(e=p; *e && *e!=':'; e++)
		{
			if (e[0]=='\\' && e[1]==':')
				memmove(e,e+1,strlen(e)); // swallow escape symbol
		}

		last = !*e;
		c = *e;
		*e = 0;
		b = lua_call_param_add(p, &f->args);
		if (!last) *e++ = c;
		if (!b) goto err;

		p = e;
	}
	free(name);
	return f;
err:
	free(name);
	return NULL;

}

static bool wf_make_l3(char *opt, bool *ipv4, bool *ipv6)
{
	char *e, *p, c;

	for (p = opt, *ipv4 = *ipv6 = false; p; )
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}

		if (!strcmp(p, "ipv4"))
			*ipv4 = true;
		else if (!strcmp(p, "ipv6"))
			*ipv6 = true;
		else return false;

		if (e) *e++ = c;
		p = e;
	}
	return true;
}

static bool parse_domain_list(char *opt, hostlist_pool **pp)
{
	char *e, *p, c;

	for (p = opt; p; )
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}

		if (*p && !AppendHostlistItem(pp, p)) return false;

		if (e) *e++ = c;
		p = e;
	}
	return true;
}

static bool parse_ip_list(char *opt, ipset *pp)
{
	char *e, *p, c;

	for (p = opt; p; )
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}

		if (*p && !AppendIpsetItem(pp, p)) return false;

		if (e) *e++ = c;
		p = e;
	}
	return true;
}

static bool parse_strlist(char *opt, struct str_list_head *list)
{
	char *e, *p = optarg;
	while (p)
	{
		e = strchr(p, ',');
		if (e) *e++ = 0;
		if (*p && !strlist_add(list, p))
			return false;
		p = e;
	}
	return true;
}


static void BlobDebug()
{
	struct blob_item *blob;
	LIST_FOREACH(blob, &params.blobs, next)
	{
		DLOG("blob '%s' : size=%zu alloc=%zu\n",blob->name,blob->size,blob->size_buf);
	}
}

static void LuaDesyncDebug(struct desync_profile *dp, const char *entity)
{
	if (params.debug)
	{
		struct func_list *func;
		struct str2_list *arg;
		int n,i;
		LIST_FOREACH(func, &dp->lua_desync, next)
		{
			DLOG("%s %u (%s) lua %s(",entity,dp->n,PROFILE_NAME(dp),func->func);
			n=0;
			LIST_FOREACH(arg, &func->args, next)
			{
				if (n) DLOG(",");
				DLOG(arg->str2 ? "%s=\"%s\"" : "%s=\"\"", arg->str1, arg->str2);
				n++;
			}
			DLOG(" range_in=%c%u%c%c%u range_out=%c%u%c%c%u payload_type=",
				func->range_in.from.mode,func->range_in.from.pos,
				func->range_in.upper_cutoff ? '<' : '-',
				func->range_in.to.mode,func->range_in.to.pos,
				func->range_out.from.mode,func->range_out.from.pos,
				func->range_out.upper_cutoff ? '<' : '-',
				func->range_out.to.mode,func->range_out.to.pos);
			if (func->payload_type)
			{
				for(i=0;i<L7P_LAST;i++)
					if (func->payload_type & (1<<i))
						DLOG(" %s", l7payload_str(i));
			}
			else
				DLOG(" all");
			DLOG(")\n");
		}
	}
}


#ifdef __CYGWIN__
static bool wf_make_pf(char *opt, const char *l4, const char *portname, char *buf, size_t len)
{
	char *e, *p, c, s1[64];
	port_filter pf;
	int n;

	if (len < 3) return false;

	for (n = 0, p = opt, *buf = '(', buf[1] = 0; p; n++)
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}
		if (!pf_parse(p, &pf)) return false;

		if (pf.from == pf.to)
			snprintf(s1, sizeof(s1), "(%s.%s %s %u)", l4, portname, pf.neg ? "!=" : "==", pf.from);
		else
			snprintf(s1, sizeof(s1), "(%s.%s %s %u %s %s.%s %s %u)", l4, portname, pf.neg ? "<" : ">=", pf.from, pf.neg ? "or" : "and", l4, portname, pf.neg ? ">" : "<=", pf.to);
		if (n) strncat(buf, " or ", len - strlen(buf) - 1);
		strncat(buf, s1, len - strlen(buf) - 1);

		if (e) *e++ = c;
		p = e;
	}
	strncat(buf, ")", len - strlen(buf) - 1);
	return true;
}

#define DIVERT_NO_LOCALNETSv4_DST "(" \
                   "(ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and " \
                   "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and " \
                   "(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and " \
                   "(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and " \
                   "(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255))"
#define DIVERT_NO_LOCALNETSv4_SRC "(" \
                   "(ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and " \
                   "(ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and " \
                   "(ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and " \
                   "(ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and " \
                   "(ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255))"

#define DIVERT_NO_LOCALNETSv6_DST "(" \
                   "(ipv6.DstAddr > ::1) and " \
                   "(ipv6.DstAddr < 2001::0 or ipv6.DstAddr >= 2001:1::0) and " \
                   "(ipv6.DstAddr < fc00::0 or ipv6.DstAddr >= fe00::0) and " \
                   "(ipv6.DstAddr < fe80::0 or ipv6.DstAddr >= fec0::0) and " \
                   "(ipv6.DstAddr < ff00::0 or ipv6.DstAddr >= ffff::0))"
#define DIVERT_NO_LOCALNETSv6_SRC "(" \
                   "(ipv6.SrcAddr > ::1) and " \
                   "(ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr >= 2001:1::0) and " \
                   "(ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr >= fe00::0) and " \
                   "(ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr >= fec0::0) and " \
                   "(ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr >= ffff::0))"

#define DIVERT_NO_LOCALNETS_SRC "(" DIVERT_NO_LOCALNETSv4_SRC " or " DIVERT_NO_LOCALNETSv6_SRC ")"
#define DIVERT_NO_LOCALNETS_DST "(" DIVERT_NO_LOCALNETSv4_DST " or " DIVERT_NO_LOCALNETSv6_DST ")"

#define DIVERT_TCP_NOT_EMPTY "(!tcp or tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength>0)"
#define DIVERT_TCP_ALWAYS "(tcp.Syn or tcp.Rst or tcp.Fin)"

// HTTP/1.? 30(2|7)
#define DIVERT_HTTP_REDIRECT "tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545450 and tcp.Payload16[2]==0x2F31 and tcp.Payload[6]==0x2E and tcp.Payload16[4]==0x2033 and tcp.Payload[10]==0x30 and (tcp.Payload[11]==0x32 or tcp.Payload[11]==0x37)"

#define DIVERT_PROLOG "!impostor and !loopback"

static bool wf_make_filter(
	char *wf, size_t len,
	unsigned int IfIdx, unsigned int SubIfIdx,
	bool ipv4, bool ipv6,
	bool bTcpEmpty,
	const char *pf_tcp_src_out, const char *pf_tcp_dst_out,
	const char *pf_tcp_src_in, const char *pf_tcp_dst_in,
	const char *pf_udp_src_in, const char *pf_udp_dst_out,
	const struct str_list_head *wf_raw_part,
	bool bFilterOutLAN)
{
	struct str_list *wfpart;
	bool bHaveTCP = *pf_tcp_src_in || *pf_tcp_dst_out;

	snprintf(wf, len, "%s", DIVERT_PROLOG);
	if (IfIdx)
		snprintf(wf + strlen(wf), len - strlen(wf), " and ifIdx=%u and subIfIdx=%u", IfIdx, SubIfIdx);
	if (ipv4 ^ ipv6)
		snprintf(wf + strlen(wf), len - strlen(wf), " and %s", ipv4 ? "ip" : "ipv6");
	if (bHaveTCP && !bTcpEmpty)
		snprintf(wf + strlen(wf), len - strlen(wf), " and\n" DIVERT_TCP_NOT_EMPTY);
	snprintf(wf + strlen(wf), len - strlen(wf), " and\n(\n false"); 

	if (bHaveTCP)
	{
//		may be required by orchestrators - always redirect
//		if (dp_list_have_autohostlist(&params.desync_profiles))

		snprintf(wf + strlen(wf), len - strlen(wf), " or\n " DIVERT_HTTP_REDIRECT);
	}

	if (!LIST_EMPTY(wf_raw_part))
	{
		LIST_FOREACH(wfpart, wf_raw_part, next)
		{
			snprintf(wf + strlen(wf), len - strlen(wf), " or\n (\n%s\n )", wfpart->str);
		}
	}

	if (*pf_tcp_dst_out)
	{
		snprintf(wf + strlen(wf), len - strlen(wf), " or\n outbound and %s", pf_tcp_dst_out);
		// always redirect opposite syn,fin,rst for conntrack
		snprintf(wf + strlen(wf), len - strlen(wf), " or\n inbound and " DIVERT_TCP_ALWAYS " and %s", pf_tcp_src_out);
	}
	if (*pf_tcp_src_in)
	{
		snprintf(wf + strlen(wf), len - strlen(wf), " or\n inbound and %s", pf_tcp_src_in);
		// always redirect opposite syn,fin,rst for conntrack
		snprintf(wf + strlen(wf), len - strlen(wf), " or\n outbound and " DIVERT_TCP_ALWAYS " and %s", pf_tcp_dst_in);
	}
	if (*pf_udp_dst_out) snprintf(wf + strlen(wf), len - strlen(wf), " or\n outbound and %s", pf_udp_dst_out);
	if (*pf_udp_src_in) snprintf(wf + strlen(wf), len - strlen(wf), " or\n inbound and %s", pf_udp_src_in);

	snprintf(wf + strlen(wf), len - strlen(wf), "\n)");

	if (bFilterOutLAN)
		snprintf(wf + strlen(wf), len - strlen(wf), "\nand\n(\n outbound and %s\n or\n inbound and %s\n)\n",
			ipv4 ? ipv6 ? DIVERT_NO_LOCALNETS_DST : DIVERT_NO_LOCALNETSv4_DST : DIVERT_NO_LOCALNETSv6_DST,
			ipv4 ? ipv6 ? DIVERT_NO_LOCALNETS_SRC : DIVERT_NO_LOCALNETSv4_SRC : DIVERT_NO_LOCALNETSv6_SRC);

	return true;
}

static unsigned int hash_jen(const void *data, unsigned int len)
{
	unsigned int hash;
	HASH_JEN(data, len, hash);
	return hash;
}

#endif


static void exithelp(void)
{
	char all_payloads[1024], all_protos[512];

	*all_payloads=0;
	for (t_l7payload pl=0 ; pl<L7P_LAST; pl++)
	{
		if (pl) strncat(all_payloads, " ", sizeof(all_payloads)-1-1);
		strncat(all_payloads, l7payload_str(pl), sizeof(all_payloads)-strlen(all_payloads)-1);
	}
	*all_protos=0;
	for (t_l7proto pr=0 ; pr<L7_LAST; pr++)
	{
		if (pr) strncat(all_protos, " ", sizeof(all_protos)-1-1);
		strncat(all_protos, l7proto_str(pr), sizeof(all_protos)-strlen(all_protos)-1);
	}

	printf(
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
		" @<config_file>|$<config_file>\t\t\t\t; read file for options. must be the only argument. other options are ignored.\n\n"
#endif
#ifdef __ANDROID__
		" --debug=0|1|syslog|android|@<filename>\n"
#else
		" --debug=0|1|syslog|@<filename>\n"
#endif
		" --version\t\t\t\t\t\t; print version and exit\n"
		" --dry-run\t\t\t\t\t\t; verify parameters and exit with code 0 if successful\n"
		" --comment=any_text\n"
#ifdef __linux__
		" --qnum=<nfqueue_number>\n"
#elif defined(BSD)
		" --port=<port>\t\t\t\t\t\t; divert port\n"
#endif
		" --daemon\t\t\t\t\t\t; daemonize\n"
		" --pidfile=<filename>\t\t\t\t\t; write pid to file\n"
#ifndef __CYGWIN__
		" --user=<username>\t\t\t\t\t; drop root privs\n"
		" --uid=uid[:gid1,gid2,...]\t\t\t\t; drop root privs\n"
#endif
#ifdef __linux__
		" --bind-fix4\t\t\t\t\t\t; apply outgoing interface selection fix for generated ipv4 packets\n"
		" --bind-fix6\t\t\t\t\t\t; apply outgoing interface selection fix for generated ipv6 packets\n"
		" --fwmark=<int|0xHEX>\t\t\t\t\t; override fwmark for generated packets. default = 0x%08X (%u)\n"
#elif defined(SO_USER_COOKIE)
		" --sockarg=<int|0xHEX>\t\t\t\t\t; override sockarg (SO_USER_COOKIE) for generated packets. default = 0x%08X (%u)\n"
#endif
		" --ctrack-timeouts=S:E:F[:U]\t\t\t\t; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u\n"
		" --ctrack-disable=[0|1]\t\t\t\t\t; 1 or no argument disables conntrack\n"
		" --server=[0|1]\t\t\t\t\t\t; change multiple aspects of src/dst ip/port handling for incoming connections\n"
		" --ipcache-lifetime=<int>\t\t\t\t; time in seconds to keep cached hop count and domain name (default %u). 0 = no expiration\n"
		" --ipcache-hostname=[0|1]\t\t\t\t; 1 or no argument enables ip->hostname caching\n"
		" --reasm-disable=[proto[,proto]]\t\t\t; disable reasm for these L7 payloads : tls_client_hello quic_initial . if no argument - disable all reasm.\n"
#ifdef __CYGWIN__
		"\nWINDIVERT FILTER:\n"
		" --wf-iface=<int>[.<int>]\t\t\t\t; numeric network interface and subinterface indexes\n"
		" --wf-l3=ipv4|ipv6\t\t\t\t\t; L3 protocol filter. multiple comma separated values allowed.\n"
		" --wf-tcp-in=[~]port1[-port2]\t\t\t\t; TCP in port filter. ~ means negation. multiple comma separated values allowed.\n"
		" --wf-udp-in=[~]port1[-port2]\t\t\t\t; UDP in port filter. ~ means negation. multiple comma separated values allowed.\n"
		" --wf-tcp-out=[~]port1[-port2]\t\t\t\t; TCP out port filter. ~ means negation. multiple comma separated values allowed.\n"
		" --wf-udp-out=[~]port1[-port2]\t\t\t\t; UDP out port filter. ~ means negation. multiple comma separated values allowed.\n"
		" --wf-tcp-empty=[0|1]\t\t\t\t\t; enable processing of empty tcp packets without flags SYN,RST,FIN (default : 0)\n"
		" --wf-raw-part=<filter>|@<filename>\t\t\t; partial raw windivert filter string or filename\n"
		" --wf-filter-lan=0|1\t\t\t\t\t; add excluding filter for non-global IP (default : 1)\n"
		" --wf-raw=<filter>|@<filename>\t\t\t\t; full raw windivert filter string or filename. replaces --wf-tcp,--wf-udp,--wf-raw-part\n"
		" --wf-save=<filename>\t\t\t\t\t; save windivert filter string to a file and exit\n"
		"\nLOGICAL NETWORK FILTER:\n"
		" --ssid-filter=ssid1[,ssid2,ssid3,...]\t\t\t; enable winws2 only if any of specified wifi SSIDs connected\n"
		" --nlm-filter=net1[,net2,net3,...]\t\t\t; enable winws2 only if any of specified NLM network is connected. names and GUIDs are accepted.\n"
		" --nlm-list[=all]\t\t\t\t\t; list Network List Manager (NLM) networks. connected only or all.\n"
#endif
		"\nDESYNC ENGINE INIT:\n"
		" --writeable[=<dir_name>]\t\t\t\t; create writeable dir for LUA scripts and pass it in WRITEABLE env variable (only one dir possible)\n"
		" --blob=<item_name>:[+ofs]@<filename>|0xHEX\t\t; load blob to LUA var <item_name>\n"
		" --lua-init=@<filename>|<lua_text>\t\t\t; load LUA program from a file or string. if multiple parameters present order of execution is preserved.\n"
		" --lua-gc=<int>\t\t\t\t\t\t; forced garbage collection every N sec. default %u sec. triggers only when a packet arrives. 0 = disable.\n"
		"\nMULTI-STRATEGY:\n"
		" --new\t\t\t\t\t\t\t; begin new profile\n"
		" --skip\t\t\t\t\t\t\t; do not use this profile\n"
		" --name=<name>\t\t\t\t\t\t; set profile name\n"
		" --template[=<name>]\t\t\t\t\t; use this profile as template (must be named or will be useless)\n"
		" --cookie[=<string>]\t\t\t\t\t; pass this profile-bound string to LUA\n"
		" --import=<name>\t\t\t\t\t; populate current profile with template data\n"
		" --filter-l3=ipv4|ipv6\t\t\t\t\t; L3 protocol filter. multiple comma separated values allowed.\n"
		" --filter-tcp=[~]port1[-port2]|*\t\t\t; TCP port filter. ~ means negation. setting tcp and not setting udp filter denies udp. comma separated list allowed.\n"
		" --filter-udp=[~]port1[-port2]|*\t\t\t; UDP port filter. ~ means negation. setting udp and not setting tcp filter denies tcp. comma separated list allowed.\n"
		" --filter-l7=proto[,proto]\t\t\t\t; L6-L7 protocol filter : %s\n"
#ifdef HAS_FILTER_SSID
		" --filter-ssid=ssid1[,ssid2,ssid3,...]\t\t\t; per profile wifi SSID filter\n"
#endif
		" --ipset=<filename>\t\t\t\t\t; ipset include filter (one ip/CIDR per line, ipv4 and ipv6 accepted, gzip supported, multiple ipsets allowed)\n"
		" --ipset-ip=<ip_list>\t\t\t\t\t; comma separated fixed subnet list\n"
		" --ipset-exclude=<filename>\t\t\t\t; ipset exclude filter (one ip/CIDR per line, ipv4 and ipv6 accepted, gzip supported, multiple ipsets allowed)\n"
		" --ipset-exclude-ip=<ip_list>\t\t\t\t; comma separated fixed subnet list\n"
		" --hostlist=<filename>\t\t\t\t\t; apply dpi desync only to the listed hosts (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)\n"
		" --hostlist-domains=<domain_list>\t\t\t; comma separated fixed domain list\n"
		" --hostlist-exclude=<filename>\t\t\t\t; do not apply dpi desync to the listed hosts (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)\n"
		" --hostlist-exclude-domains=<domain_list>\t\t; comma separated fixed domain list\n"
		" --hostlist-auto=<filename>\t\t\t\t; detect DPI blocks and build hostlist automatically\n"
		" --hostlist-auto-fail-threshold=<int>\t\t\t; how many failed attempts cause hostname to be added to auto hostlist (default : %d)\n"
		" --hostlist-auto-fail-time=<int>\t\t\t; all failed attemps must be within these seconds (default : %d)\n"
		" --hostlist-auto-retrans-threshold=<int>\t\t; how many request retransmissions cause attempt to fail (default : %d)\n"
		" --hostlist-auto-retrans-maxseq=<int>\t\t\t; count retransmissions only within this relative sequence (default : %u)\n"
		" --hostlist-auto-retrans-reset=[0|1]\t\t\t; send RST to retransmitter to break long wait (default: 1)\n"
		" --hostlist-auto-incoming-maxseq=<int>\t\t\t; treat tcp connection as successful if incoming relative sequence exceedes this threshold (default : %u)\n"
		" --hostlist-auto-udp-out=<int>\t\t\t\t; udp failure condition : sent at least `udp_out` packets (default : %u)\n"
		" --hostlist-auto-udp-in=<int>\t\t\t\t; udp failure condition : received not more than `udp_in` packets (default : %u)\n"
		" --hostlist-auto-debug=<logfile>\t\t\t; debug auto hostlist positives (global parameter)\n"
		"\nLUA PACKET PASS MODE:\n"
		" --payload=type[,type]\t\t\t\t\t; set payload types following LUA functions should process : %s\n"
		" --out-range=[(n|a|d|s|p)<int>](-|<)[(n|a|d|s|p)<int>]\t; set outgoing packet range for following LUA functions. '-' - include end pos, '<' - not include. prefix meaning : n - packet number, d - data packet number, s - relative sequence, p - data position relative sequence, b - byte count, x - never, a - always\n"
		" --in-range=[(n|a|d|s|p)<int>](-|<)[(n|a|d|s|p)<int>]\t; set incoming packet range for following LUA functions. '-' - include end pos, '<' - not include. prefix meaning : n - packet number, d - data packet number, s - relative sequence, p - data position relative sequence, b - byte count, x - never, a - always\n"
		"\nLUA DESYNC ACTION:\n"
		" --lua-desync=<functon>[:param1=val1[:param2=val2]]\t; call LUA function when packet received\n",
#if defined(__linux__) || defined(SO_USER_COOKIE)
		DPI_DESYNC_FWMARK_DEFAULT,DPI_DESYNC_FWMARK_DEFAULT,
#endif
		CTRACK_T_SYN, CTRACK_T_EST, CTRACK_T_FIN, CTRACK_T_UDP,
		IPCACHE_LIFETIME,
		LUA_GC_INTERVAL,
		all_protos,
		HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT, HOSTLIST_AUTO_FAIL_TIME_DEFAULT,
		HOSTLIST_AUTO_RETRANS_THRESHOLD_DEFAULT,
		HOSTLIST_AUTO_RETRANS_MAXSEQ, HOSTLIST_AUTO_INCOMING_MAXSEQ,
		HOSTLIST_AUTO_UDP_OUT, HOSTLIST_AUTO_UDP_IN,
		all_payloads
	);
	exit(1);
}
static void exithelp_clean(void)
{
	cleanup_params(&params);
	exithelp();
}

#if !defined( __OpenBSD__) && !defined(__ANDROID__)
// no static to not allow optimizer to inline this func (save stack)
void config_from_file(const char *filename)
{
	// config from a file
	char buf[MAX_CONFIG_FILE_SIZE];
	buf[0] = 'x';	// fake argv[0]
	buf[1] = ' ';
	size_t bufsize = sizeof(buf) - 3;
	if (!load_file(filename, 0, buf + 2, &bufsize))
	{
		DLOG_ERR("could not load config file '%s'\n", filename);
		exit_clean(1);
	}
	buf[bufsize + 2] = 0;
	// wordexp fails if it sees \t \n \r between args
	replace_char(buf, '\n', ' ');
	replace_char(buf, '\r', ' ');
	replace_char(buf, '\t', ' ');
	if (wordexp(buf, &params.wexp, WRDE_NOCMD))
	{
		DLOG_ERR("failed to split command line options from file '%s'\n", filename);
		exit_clean(1);
	}
}
#endif

static void check_dp(const struct desync_profile *dp)
{
}

static void ApplyDefaultBlobs(struct blob_collection_head *blobs)
{
	load_const_blob_to_collection("fake_default_tls",fake_tls_clienthello_default,sizeof(fake_tls_clienthello_default),blobs,BLOB_EXTRA_BYTES);
	load_const_blob_to_collection("fake_default_http",fake_http_request_default,strlen(fake_http_request_default),blobs,0);

	uint8_t buf[620];
	memset(buf,0,sizeof(buf));
	buf[0]=0x40;
	load_const_blob_to_collection("fake_default_quic",buf,620,blobs,0);
}

enum opt_indices {
	IDX_DEBUG,
	IDX_DRY_RUN,
	IDX_VERSION,
	IDX_COMMENT,
#ifdef __linux__
	IDX_QNUM,
	IDX_BIND_FIX4,
	IDX_BIND_FIX6,
#elif defined(BSD)
	IDX_PORT,
#endif
	IDX_DAEMON,
	IDX_PIDFILE,
#ifndef __CYGWIN__
	IDX_USER,
	IDX_UID,
#endif
	IDX_CTRACK_TIMEOUTS,
	IDX_CTRACK_DISABLE,
	IDX_SERVER,
	IDX_IPCACHE_LIFETIME,
	IDX_IPCACHE_HOSTNAME,
	IDX_REASM_DISABLE,
#ifdef __linux__
	IDX_FWMARK,
#elif defined(SO_USER_COOKIE)
	IDX_SOCKARG,
#endif

	IDX_WRITEABLE,

	IDX_BLOB,
	IDX_LUA_INIT,
	IDX_LUA_GC,

	IDX_HOSTLIST,
	IDX_HOSTLIST_DOMAINS,
	IDX_HOSTLIST_EXCLUDE,
	IDX_HOSTLIST_EXCLUDE_DOMAINS,
	IDX_HOSTLIST_AUTO,
	IDX_HOSTLIST_AUTO_FAIL_THRESHOLD,
	IDX_HOSTLIST_AUTO_FAIL_TIME,
	IDX_HOSTLIST_AUTO_RETRANS_THRESHOLD,
	IDX_HOSTLIST_AUTO_RETRANS_MAXSEQ,
	IDX_HOSTLIST_AUTO_RETRANS_RESET,
	IDX_HOSTLIST_AUTO_INCOMING_MAXSEQ,
	IDX_HOSTLIST_AUTO_UDP_IN,
	IDX_HOSTLIST_AUTO_UDP_OUT,
	IDX_HOSTLIST_AUTO_DEBUG,
	IDX_NEW,
	IDX_SKIP,
	IDX_NAME,
	IDX_TEMPLATE,
	IDX_IMPORT,
	IDX_COOKIE,
	IDX_FILTER_L3,
	IDX_FILTER_TCP,
	IDX_FILTER_UDP,
	IDX_FILTER_L7,
#ifdef HAS_FILTER_SSID
	IDX_FILTER_SSID,
#endif
	IDX_IPSET,
	IDX_IPSET_IP,
	IDX_IPSET_EXCLUDE,
	IDX_IPSET_EXCLUDE_IP,

	IDX_PAYLOAD,
	IDX_IN_RANGE,
	IDX_OUT_RANGE,
	IDX_LUA_DESYNC,

#ifdef __CYGWIN__
	IDX_WF_IFACE,
	IDX_WF_L3,
	IDX_WF_TCP_IN,
	IDX_WF_TCP_OUT,
	IDX_WF_UDP_IN,
	IDX_WF_UDP_OUT,
	IDX_WF_TCP_EMPTY,
	IDX_WF_RAW,
	IDX_WF_RAW_PART,
	IDX_WF_FILTER_LAN,
	IDX_WF_SAVE,
	IDX_SSID_FILTER,
	IDX_NLM_FILTER,
	IDX_NLM_LIST,
#endif
	IDX_LAST
};

static const struct option long_options[] = {
	[IDX_DEBUG] = {"debug", optional_argument, 0, 0},
	[IDX_DRY_RUN] = {"dry-run", no_argument, 0, 0},
	[IDX_VERSION] = {"version", no_argument, 0, 0},
	[IDX_COMMENT] = {"comment", optional_argument, 0, 0},
#ifdef __linux__
	[IDX_QNUM] = {"qnum", required_argument, 0, 0},
	[IDX_BIND_FIX4] = {"bind-fix4", no_argument, 0, 0},
	[IDX_BIND_FIX6] = {"bind-fix6", no_argument, 0, 0},
#elif defined(BSD)
	[IDX_PORT] = {"port", required_argument, 0, 0},
#endif
	[IDX_DAEMON] = {"daemon", no_argument, 0, 0},
	[IDX_PIDFILE] = {"pidfile", required_argument, 0, 0},
#ifndef __CYGWIN__
	[IDX_USER] = {"user", required_argument, 0, 0},
	[IDX_UID] = {"uid", required_argument, 0, 0},
#endif
	[IDX_CTRACK_TIMEOUTS] = {"ctrack-timeouts", required_argument, 0, 0},
	[IDX_CTRACK_DISABLE] = {"ctrack-disable", optional_argument, 0, 0},
	[IDX_SERVER] = {"server", optional_argument, 0, 0},
	[IDX_IPCACHE_LIFETIME] = {"ipcache-lifetime", required_argument, 0, 0},
	[IDX_IPCACHE_HOSTNAME] = {"ipcache-hostname", optional_argument, 0, 0},
	[IDX_REASM_DISABLE] = {"reasm-disable", optional_argument, 0, 0},
#ifdef __linux__
	[IDX_FWMARK] = {"fwmark", required_argument, 0, 0},
#elif defined(SO_USER_COOKIE)
	[IDX_SOCKARG] = {"sockarg", required_argument, 0, 0},
#endif
	[IDX_WRITEABLE] = {"writeable", optional_argument, 0, 0},
	[IDX_BLOB] = {"blob", required_argument, 0, 0},
	[IDX_LUA_INIT] = {"lua-init", required_argument, 0, 0},
	[IDX_LUA_GC] = {"lua-gc", required_argument, 0, 0},
	[IDX_HOSTLIST] = {"hostlist", required_argument, 0, 0},
	[IDX_HOSTLIST_DOMAINS] = {"hostlist-domains", required_argument, 0, 0},
	[IDX_HOSTLIST_EXCLUDE] = {"hostlist-exclude", required_argument, 0, 0},
	[IDX_HOSTLIST_EXCLUDE_DOMAINS] = {"hostlist-exclude-domains", required_argument, 0, 0},
	[IDX_HOSTLIST_AUTO] = {"hostlist-auto", required_argument, 0, 0},
	[IDX_HOSTLIST_AUTO_FAIL_THRESHOLD] = {"hostlist-auto-fail-threshold", required_argument, 0, 0},
	[IDX_HOSTLIST_AUTO_FAIL_TIME] = {"hostlist-auto-fail-time", required_argument, 0, 0},
	[IDX_HOSTLIST_AUTO_RETRANS_THRESHOLD] = {"hostlist-auto-retrans-threshold", required_argument, 0, 0},
	[IDX_HOSTLIST_AUTO_RETRANS_MAXSEQ] = {"hostlist-auto-retrans-maxseq", required_argument, 0, 0},
	[IDX_HOSTLIST_AUTO_RETRANS_RESET] = {"hostlist-auto-retrans-reset", optional_argument, 0, 0},
	[IDX_HOSTLIST_AUTO_INCOMING_MAXSEQ] = {"hostlist-auto-incoming-maxseq", required_argument, 0, 0},
	[IDX_HOSTLIST_AUTO_UDP_IN] = {"hostlist-auto-udp-in", required_argument, 0, 0},
	[IDX_HOSTLIST_AUTO_UDP_OUT] = {"hostlist-auto-udp-out", required_argument, 0, 0},
	[IDX_HOSTLIST_AUTO_DEBUG] = {"hostlist-auto-debug", required_argument, 0, 0},
	[IDX_NEW] = {"new", no_argument, 0, 0},
	[IDX_SKIP] = {"skip", no_argument, 0, 0},
	[IDX_NAME] = {"name", required_argument, 0, 0},
	[IDX_TEMPLATE] = {"template", optional_argument, 0, 0},
	[IDX_IMPORT] = {"import", required_argument, 0, 0},
	[IDX_COOKIE] = {"cookie", required_argument, 0, 0},
	[IDX_FILTER_L3] = {"filter-l3", required_argument, 0, 0},
	[IDX_FILTER_TCP] = {"filter-tcp", required_argument, 0, 0},
	[IDX_FILTER_UDP] = {"filter-udp", required_argument, 0, 0},
	[IDX_FILTER_L7] = {"filter-l7", required_argument, 0, 0},
#ifdef HAS_FILTER_SSID
	[IDX_FILTER_SSID] = {"filter-ssid", required_argument, 0, 0},
#endif
	[IDX_IPSET] = {"ipset", required_argument, 0, 0},
	[IDX_IPSET_IP] = {"ipset-ip", required_argument, 0, 0},
	[IDX_IPSET_EXCLUDE] = {"ipset-exclude", required_argument, 0, 0},
	[IDX_IPSET_EXCLUDE_IP] = {"ipset-exclude-ip", required_argument, 0, 0},

	[IDX_PAYLOAD] = {"payload", required_argument, 0, 0},
	[IDX_IN_RANGE] = {"in-range", required_argument, 0, 0},
	[IDX_OUT_RANGE] = {"out-range", required_argument, 0, 0},
	[IDX_LUA_DESYNC] = {"lua-desync", required_argument, 0, 0},

#ifdef __CYGWIN__
	[IDX_WF_IFACE] = {"wf-iface", required_argument, 0, 0},
	[IDX_WF_L3] = {"wf-l3", required_argument, 0, 0},
	[IDX_WF_TCP_IN] = {"wf-tcp-in", required_argument, 0, 0},
	[IDX_WF_TCP_OUT] = {"wf-tcp-out", required_argument, 0, 0},
	[IDX_WF_UDP_IN] = {"wf-udp-in", required_argument, 0, 0},
	[IDX_WF_UDP_OUT] = {"wf-udp-out", required_argument, 0, 0},
	[IDX_WF_TCP_EMPTY] = {"wf-tcp-empty", optional_argument, 0, 0},
	[IDX_WF_RAW] = {"wf-raw", required_argument, 0, 0},
	[IDX_WF_RAW_PART] = {"wf-raw-part", required_argument, 0, 0},
	[IDX_WF_FILTER_LAN] = {"wf-filter-lan", required_argument, 0, 0},
	[IDX_WF_SAVE] = {"wf-save", required_argument, 0, 0},
	[IDX_SSID_FILTER] = {"ssid-filter", required_argument, 0, 0},
	[IDX_NLM_FILTER] = {"nlm-filter", required_argument, 0, 0},
	[IDX_NLM_LIST] = {"nlm-list", optional_argument, 0, 0},
#endif
	[IDX_LAST] = {NULL, 0, NULL, 0},
};


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#if defined(ZAPRET_GH_VER) || defined (ZAPRET_GH_HASH)
#ifdef __ANDROID__
#define MAKE_VER(s,size) snprintf(s,size,"github android version %s (%s) lua_compat_ver %u", TOSTRING(ZAPRET_GH_VER), TOSTRING(ZAPRET_GH_HASH), LUA_COMPAT_VER)
#else
#define MAKE_VER(s,size) snprintf(s,size,"github version %s (%s) lua_compat_ver %u", TOSTRING(ZAPRET_GH_VER), TOSTRING(ZAPRET_GH_HASH), LUA_COMPAT_VER)
#endif
#else
#ifdef __ANDROID__
#define MAKE_VER(s,size) snprintf(s,size,"self-built android version %s %s lua_compat_ver %u", __DATE__, __TIME__, LUA_COMPAT_VER)
#else
#define MAKE_VER(s,size) snprintf(s,size,"self-built version %s %s lua_compat_ver %u", __DATE__, __TIME__, LUA_COMPAT_VER)
#endif
#endif

int main(int argc, char **argv)
{
#ifdef __CYGWIN__
	if (service_run(argc, argv))
	{
		// we were running as service. now exit.
		return 0;
	}
#endif
	int result, v;
	int option_index = 0;
	bool bSkip = false, bDry = false, bTemplate;
	struct hostlist_file *anon_hl = NULL, *anon_hl_exclude = NULL;
	struct ipset_file *anon_ips = NULL, *anon_ips_exclude = NULL;
	uint64_t payload_type=0;
	struct packet_range range_in = PACKET_RANGE_NEVER, range_out = PACKET_RANGE_ALWAYS;
#ifdef __CYGWIN__
	char wf_save_file[256]="";
	bool wf_ipv4 = true, wf_ipv6 = true, wf_filter_lan = true, wf_tcp_empty = false;
	unsigned int IfIdx = 0, SubIfIdx = 0;
	unsigned int hash_wf_tcp_in = 0, hash_wf_udp_in = 0, hash_wf_tcp_out = 0, hash_wf_udp_out = 0, hash_wf_raw = 0, hash_wf_raw_part = 0, hash_ssid_filter = 0, hash_nlm_filter = 0;
#endif

	if (argc < 2) exithelp();

	srandom(time(NULL));
	aes_init_keygen_tables(); // required for aes
	mask_from_preflen6_prepare();
	set_env_exedir(argv[0]);
	set_console_io_buffering();
#ifdef __CYGWIN__
	prepare_low_appdata();
#endif

	init_params(&params);

	MAKE_VER(params.verstr, sizeof(params.verstr));
	printf("%s\n\n",params.verstr);

	ApplyDefaultBlobs(&params.blobs);

	struct desync_profile_list *dpl;
	struct desync_profile *dp;
	unsigned int desync_profile_count = 0, desync_template_count = 0;

	bTemplate = false;
	if (!(dpl = dp_list_add(&params.desync_profiles)))
	{
		DLOG_ERR("desync_profile_add: out of memory\n");
		exit_clean(1);
	}
	dp = &dpl->dp;
	dp->n = ++desync_profile_count;

#if !defined( __OpenBSD__) && !defined(__ANDROID__)
	if (argc >= 2 && (argv[1][0] == '@' || argv[1][0] == '$'))
	{
		config_from_file(argv[1] + 1);
		argv = params.wexp.we_wordv;
		argc = params.wexp.we_wordc;
	}
#endif

#ifdef __CYGWIN__
	params.windivert_filter = malloc(WINDIVERT_MAX);
	if (!params.windivert_filter)
	{
		DLOG_ERR("out of memory\n");
		exit_clean(1);
	}
	char **wdbufs[] =
		{&params.wf_pf_tcp_src_in, &params.wf_pf_tcp_dst_in, &params.wf_pf_udp_src_in, &params.wf_pf_udp_dst_in,
		&params.wf_pf_tcp_src_out, &params.wf_pf_tcp_dst_out, &params.wf_pf_udp_src_out, &params.wf_pf_udp_dst_out};
	for (v=0 ; v<(sizeof(wdbufs)/sizeof(*wdbufs)) ; v++)
	{
		if (!(*wdbufs[v] = malloc(WINDIVERT_PORTFILTER_MAX)))
		{
			DLOG_ERR("out of memory\n");
			exit_clean(1);
		}
		**wdbufs[v] = 0;
	}
#endif

	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v)
		{
			if (bDry)
				exit_clean(1);
			else
				exithelp_clean();
		}
		switch (option_index)
		{
		case IDX_DEBUG:
			if (optarg)
			{
				if (*optarg == '@')
				{
					strncpy(params.debug_logfile, optarg + 1, sizeof(params.debug_logfile));
					params.debug_logfile[sizeof(params.debug_logfile) - 1] = 0;
					FILE *F = fopen(params.debug_logfile, "wt");
					if (!F)
					{
						fprintf(stderr, "cannot create %s\n", params.debug_logfile);
						exit_clean(1);
					}
					fclose(F);
					params.debug = true;
					params.debug_target = LOG_TARGET_FILE;
				}
				else if (!strcmp(optarg, "syslog"))
				{
					params.debug = true;
					params.debug_target = LOG_TARGET_SYSLOG;
					openlog(progname, LOG_PID, LOG_USER);
				}
#ifdef __ANDROID__
				else if (!strcmp(optarg, "android"))
				{
					if (!params.debug) params.debug = 1;
					params.debug_target = LOG_TARGET_ANDROID;
				}
#endif
				else if (optarg[0] >= '0' && optarg[0] <= '1')
				{
					params.debug = atoi(optarg);
					params.debug_target = LOG_TARGET_CONSOLE;
				}
				else
				{
					fprintf(stderr, "invalid debug mode : %s\n", optarg);
					exit_clean(1);
				}
			}
			else
			{
				params.debug = true;
				params.debug_target = LOG_TARGET_CONSOLE;
			}
			break;
		case IDX_DRY_RUN:
			bDry = true;
			break;
		case IDX_VERSION:
			exit_clean(0);
			break;
		case IDX_COMMENT:
			break;
#ifdef __linux__
		case IDX_QNUM:
			params.qnum = atoi(optarg);
			if (params.qnum < 0 || params.qnum>65535)
			{
				DLOG_ERR("bad qnum\n");
				exit_clean(1);
			}
			break;
		case IDX_BIND_FIX4:
			params.bind_fix4 = true;
			break;
		case IDX_BIND_FIX6:
			params.bind_fix6 = true;
			break;
#elif defined(BSD)
		case IDX_PORT:
		{
			int i = atoi(optarg);
			if (i <= 0 || i > 65535)
			{
				DLOG_ERR("bad port number\n");
				exit_clean(1);
			}
			params.port = (uint16_t)i;
		}
		break;
#endif
		case IDX_DAEMON:
			params.daemon = true;
			break;
		case IDX_PIDFILE:
			snprintf(params.pidfile, sizeof(params.pidfile), "%s", optarg);
			break;
#ifndef __CYGWIN__
		case IDX_USER:
		{
			free(params.user); params.user = NULL;
			struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				DLOG_ERR("non-existent username supplied\n");
				exit_clean(1);
			}
			params.uid = pwd->pw_uid;
			params.gid[0] = pwd->pw_gid;
			params.gid_count = 1;
			if (!(params.user = strdup(optarg)))
			{
				DLOG_ERR("strdup: out of memory\n");
				exit_clean(1);
			}
			params.droproot = true;
			break;
		}
		case IDX_UID:
			free(params.user); params.user = NULL;
			if (!parse_uid(optarg, &params.uid, params.gid, &params.gid_count, MAX_GIDS))
			{
				DLOG_ERR("--uid should be : uid[:gid,gid,...]\n");
				exit_clean(1);
			}
			if (!params.gid_count)
			{
				params.gid[0] = 0x7FFFFFFF;
				params.gid_count = 1;
			}
			params.droproot = true;
			break;
#endif
		case IDX_CTRACK_TIMEOUTS:
			if (sscanf(optarg, "%u:%u:%u:%u", &params.ctrack_t_syn, &params.ctrack_t_est, &params.ctrack_t_fin, &params.ctrack_t_udp) < 3)
			{
				DLOG_ERR("invalid ctrack-timeouts value\n");
				exit_clean(1);
			}
			break;
		case IDX_CTRACK_DISABLE:
			params.ctrack_disable = !optarg || atoi(optarg);
			break;
		case IDX_SERVER:
			params.server = !optarg || atoi(optarg);
			break;
		case IDX_IPCACHE_LIFETIME:
			if (sscanf(optarg, "%u", &params.ipcache_lifetime) != 1)
			{
				DLOG_ERR("invalid ipcache-lifetime value\n");
				exit_clean(1);
			}
			break;
		case IDX_IPCACHE_HOSTNAME:
			params.cache_hostname = !optarg || atoi(optarg);
			break;
		case IDX_REASM_DISABLE:
			if (optarg)
			{
				if (!parse_l7p_list(optarg, &params.reasm_payload_disable))
				{
					DLOG_ERR("Invalid l7 protocol list : %s\n", optarg);
					exit_clean(1);
				}
			}
			else
				params.reasm_payload_disable = 0xFFFFFFFFFFFFFFFF;
			break;
#if defined(__linux__)
		case IDX_FWMARK:
#elif defined(SO_USER_COOKIE)
		case IDX_SOCKARG:
#endif
#if defined(__linux__) || defined(SO_USER_COOKIE)
			params.desync_fwmark = 0;
			if (sscanf(optarg, "0x%X", &params.desync_fwmark) <= 0) sscanf(optarg, "%u", &params.desync_fwmark);
			if (!params.desync_fwmark)
			{
				DLOG_ERR("fwmark/sockarg should be decimal or 0xHEX and should not be zero\n");
				exit_clean(1);
			}
			break;
#endif
		case IDX_WRITEABLE:
			params.writeable_dir_enable = true;
			if (optarg)
			{
				strncpy(params.writeable_dir, optarg, sizeof(params.writeable_dir));
				params.writeable_dir[sizeof(params.writeable_dir) - 1] = 0;
			}
			else
				*params.writeable_dir = 0;
			break;

		case IDX_BLOB:
			load_blob_to_collection(optarg, &params.blobs, MAX_BLOB_SIZE, BLOB_EXTRA_BYTES);
			break;

		case IDX_LUA_INIT:
			if (!strlist_add_tail(&params.lua_init_scripts, optarg))
			{
				DLOG_ERR("out of memory\n");
				exit_clean(1);
			}
			break;
		case IDX_LUA_GC:
			params.lua_gc = atoi(optarg);
			break;
		case IDX_HOSTLIST:
			if (bSkip) break;
			if (!RegisterHostlist(dp, false, optarg))
			{
				DLOG_ERR("failed to register hostlist '%s'\n", optarg);
				exit_clean(1);
			}
			break;
		case IDX_HOSTLIST_DOMAINS:
			if (bSkip) break;
			if (!anon_hl && !(anon_hl = RegisterHostlist(dp, false, NULL)))
			{
				DLOG_ERR("failed to register anonymous hostlist\n");
				exit_clean(1);
			}
			if (!parse_domain_list(optarg, &anon_hl->hostlist))
			{
				DLOG_ERR("failed to add domains to anonymous hostlist\n");
				exit_clean(1);
			}
			break;
		case IDX_HOSTLIST_EXCLUDE:
			if (bSkip) break;
			if (!RegisterHostlist(dp, true, optarg))
			{
				DLOG_ERR("failed to register hostlist '%s'\n", optarg);
				exit_clean(1);
			}
			break;
		case IDX_HOSTLIST_EXCLUDE_DOMAINS:
			if (bSkip) break;
			if (!anon_hl_exclude && !(anon_hl_exclude = RegisterHostlist(dp, true, NULL)))
			{
				DLOG_ERR("failed to register anonymous hostlist\n");
				exit_clean(1);
			}
			if (!parse_domain_list(optarg, &anon_hl_exclude->hostlist))
			{
				DLOG_ERR("failed to add domains to anonymous hostlist\n");
				exit_clean(1);
			}
			break;
		case IDX_HOSTLIST_AUTO:
			if (bSkip) break;
			if (dp->hostlist_auto)
			{
				DLOG_ERR("only one auto hostlist per profile is supported\n");
				exit_clean(1);
			}
			{
				FILE *F = fopen(optarg, "a+b");
				if (!F)
				{
					DLOG_ERR("cannot create %s\n", optarg);
					exit_clean(1);
				}
				bool bGzip = is_gzip(F);
				fclose(F);
				if (bGzip)
				{
					DLOG_ERR("gzipped auto hostlists are not supported\n");
					exit_clean(1);
				}
			}
			if (!(dp->hostlist_auto = RegisterHostlist(dp, false, optarg)))
			{
				DLOG_ERR("failed to register hostlist '%s'\n", optarg);
				exit_clean(1);
			}
			break;
		case IDX_HOSTLIST_AUTO_FAIL_THRESHOLD:
			dp->hostlist_auto_fail_threshold = (uint8_t)atoi(optarg);
			if (dp->hostlist_auto_fail_threshold < 1 || dp->hostlist_auto_fail_threshold>20)
			{
				DLOG_ERR("auto hostlist fail threshold must be within 1..20\n");
				exit_clean(1);
			}
			break;
		case IDX_HOSTLIST_AUTO_FAIL_TIME:
			dp->hostlist_auto_fail_time = (uint8_t)atoi(optarg);
			if (dp->hostlist_auto_fail_time < 1)
			{
				DLOG_ERR("auto hostlist fail time is not valid\n");
				exit_clean(1);
			}
			break;
		case IDX_HOSTLIST_AUTO_RETRANS_THRESHOLD:
			dp->hostlist_auto_retrans_threshold = (uint8_t)atoi(optarg);
			if (dp->hostlist_auto_retrans_threshold < 2 || dp->hostlist_auto_retrans_threshold>10)
			{
				DLOG_ERR("auto hostlist fail threshold must be within 2..10\n");
				exit_clean(1);
			}
			break;
		case IDX_HOSTLIST_AUTO_RETRANS_MAXSEQ:
			dp->hostlist_auto_retrans_maxseq = (uint32_t)atoi(optarg);
			break;
		case IDX_HOSTLIST_AUTO_INCOMING_MAXSEQ:
			dp->hostlist_auto_incoming_maxseq = (uint32_t)atoi(optarg);
			break;
		case IDX_HOSTLIST_AUTO_RETRANS_RESET:
			dp->hostlist_auto_retrans_reset = !optarg || !!atoi(optarg);
			break;
		case IDX_HOSTLIST_AUTO_UDP_OUT:
			dp->hostlist_auto_udp_out = atoi(optarg);
			break;
		case IDX_HOSTLIST_AUTO_UDP_IN:
			dp->hostlist_auto_udp_in = atoi(optarg);
			break;
		case IDX_HOSTLIST_AUTO_DEBUG:
		{
			FILE *F = fopen(optarg, "a+t");
			if (!F)
			{
				DLOG_ERR("cannot create %s\n", optarg);
				exit_clean(1);
			}
			fclose(F);
			strncpy(params.hostlist_auto_debuglog, optarg, sizeof(params.hostlist_auto_debuglog));
			params.hostlist_auto_debuglog[sizeof(params.hostlist_auto_debuglog) - 1] = '\0';
		}
		break;

		case IDX_NEW:
			if (bSkip)
			{
				dp_clear(dp);
				dp_init(dp);
				dp->n = desync_profile_count;
				bSkip = false;
			}
			else
			{
				check_dp(dp);
				if (bTemplate)
				{
					if (dp->name && dp_list_search_name(&params.desync_templates, dp->name))
					{
						DLOG_ERR("template '%s' already present\n", dp->name);
						exit_clean(1);
					}
					dpl->dp.n = ++desync_template_count;
					dp_list_move(&params.desync_templates, dpl);
				}
				else
				{
					desync_profile_count++;
				}
				if (!(dpl = dp_list_add(&params.desync_profiles)))
				{
					DLOG_ERR("desync_profile_add: out of memory\n");
					exit_clean(1);
				}
				dp = &dpl->dp;
				dp->n = desync_profile_count;
			}
			anon_hl = anon_hl_exclude = NULL;
			anon_ips = anon_ips_exclude = NULL;
			payload_type = 0;
			range_in = PACKET_RANGE_NEVER;
			range_out = PACKET_RANGE_ALWAYS;

			bTemplate = false;
			break;
		case IDX_SKIP:
			bSkip = true;
			break;
		case IDX_TEMPLATE:
			bTemplate = true;
		case IDX_NAME:
			if (optarg)
			{
				free(dp->name);
				if (!(dp->name = strdup(optarg)))
				{
					DLOG_ERR("out of memory\n");
					exit_clean(1);
				}
			}
			break;
		case IDX_COOKIE:
			free(dp->cookie);
			if (!(dp->cookie = strdup(optarg)))
			{
				DLOG_ERR("out of memory\n");
				exit_clean(1);
			}
			break;
		case IDX_IMPORT:
			{
				struct desync_profile_list *tpl = dp_list_search_name(&params.desync_templates, optarg);
				if (!tpl)
				{
					DLOG_ERR("template '%s' not found\n", optarg);
					exit_clean(1);
				}
				if (!dp_list_copy(dp, &tpl->dp))
				{
					DLOG_ERR("could not copy template\n");
					exit_clean(1);
				}
				dp->n = desync_profile_count;
				free(dp->name_tpl);
				if (tpl->dp.name && !(dp->name_tpl = strdup(tpl->dp.name)))
				{
					DLOG_ERR("out of memory\n");
					exit_clean(1);
				}
				dp->n_tpl = tpl->dp.n;
			}
			break;

		case IDX_FILTER_L3:
			if (!wf_make_l3(optarg, &dp->filter_ipv4, &dp->filter_ipv6))
			{
				DLOG_ERR("bad value for --filter-l3\n");
				exit_clean(1);
			}
			break;
		case IDX_FILTER_TCP:
			if (!parse_pf_list(optarg, &dp->pf_tcp))
			{
				DLOG_ERR("Invalid port filter : %s\n", optarg);
				exit_clean(1);
			}
			// deny tcp if not set
			if (!port_filters_deny_if_empty(&dp->pf_udp))
				exit_clean(1);
			break;
		case IDX_FILTER_UDP:
			if (!parse_pf_list(optarg, &dp->pf_udp))
			{
				DLOG_ERR("Invalid port filter : %s\n", optarg);
				exit_clean(1);
			}
			// deny tcp if not set
			if (!port_filters_deny_if_empty(&dp->pf_tcp))
				exit_clean(1);
			break;
		case IDX_FILTER_L7:
			if (!parse_l7_list(optarg, &dp->filter_l7))
			{
				DLOG_ERR("Invalid l7 filter : %s\n", optarg);
				exit_clean(1);
			}
			break;
#ifdef HAS_FILTER_SSID
		case IDX_FILTER_SSID:
			if (!parse_strlist(optarg, &dp->filter_ssid))
			{
				DLOG_ERR("strlist_add failed\n");
				exit_clean(1);
			}
			params.filter_ssid_present = true;
			break;
#endif
		case IDX_IPSET:
			if (bSkip) break;
			if (!RegisterIpset(dp, false, optarg))
			{
				DLOG_ERR("failed to register ipset '%s'\n", optarg);
				exit_clean(1);
			}
			break;
		case IDX_IPSET_IP:
			if (bSkip) break;
			if (!anon_ips && !(anon_ips = RegisterIpset(dp, false, NULL)))
			{
				DLOG_ERR("failed to register anonymous ipset\n");
				exit_clean(1);
			}
			if (!parse_ip_list(optarg, &anon_ips->ipset))
			{
				DLOG_ERR("failed to add subnets to anonymous ipset\n");
				exit_clean(1);
			}
			break;
		case IDX_IPSET_EXCLUDE:
			if (bSkip) break;
			if (!RegisterIpset(dp, true, optarg))
			{
				DLOG_ERR("failed to register ipset '%s'\n", optarg);
				exit_clean(1);
			}
			break;
		case IDX_IPSET_EXCLUDE_IP:
			if (bSkip) break;
			if (!anon_ips_exclude && !(anon_ips_exclude = RegisterIpset(dp, true, NULL)))
			{
				DLOG_ERR("failed to register anonymous ipset\n");
				exit_clean(1);
			}
			if (!parse_ip_list(optarg, &anon_ips_exclude->ipset))
			{
				DLOG_ERR("failed to add subnets to anonymous ipset\n");
				exit_clean(1);
			}
			break;

		case IDX_PAYLOAD:
			if (!parse_l7p_list(optarg, &payload_type))
			{
				DLOG_ERR("Invalid payload filter : %s\n", optarg);
				exit_clean(1);
			}
			break;
		case IDX_OUT_RANGE:
			if (!packet_range_parse(optarg, &range_out))
			{
				DLOG_ERR("invalid packet range value : %s\n",optarg);
				exit_clean(1);
			}
			break;
		case IDX_IN_RANGE:
			if (!packet_range_parse(optarg, &range_in))
			{
				DLOG_ERR("invalid packet range value : %s\n",optarg);
				exit_clean(1);
			}
			break;

		case IDX_LUA_DESYNC:
			{
				struct func_list *f;
				if (!(f=parse_lua_call(optarg, &dp->lua_desync)))
				{
					DLOG_ERR("invalid lua function call : %s\n", optarg);
					exit_clean(1);
				}
				f->payload_type = payload_type;
				f->range_in = range_in;
				f->range_out = range_out;
			}
			break;

#ifdef __CYGWIN__
		case IDX_WF_IFACE:
			if (!sscanf(optarg, "%u.%u", &IfIdx, &SubIfIdx))
			{
				DLOG_ERR("bad value for --wf-iface\n");
				exit_clean(1);
			}
			break;
		case IDX_WF_L3:
			if (!wf_make_l3(optarg, &wf_ipv4, &wf_ipv6))
			{
				DLOG_ERR("bad value for --wf-l3\n");
				exit_clean(1);
			}
			break;
		case IDX_WF_TCP_IN:
			hash_wf_tcp_in = hash_jen(optarg, strlen(optarg));
			if (!wf_make_pf(optarg, "tcp", "SrcPort", params.wf_pf_tcp_src_in, WINDIVERT_PORTFILTER_MAX) ||
				!wf_make_pf(optarg, "tcp", "DstPort", params.wf_pf_tcp_dst_in, WINDIVERT_PORTFILTER_MAX))
			{
				DLOG_ERR("bad value for --wf-tcp-in\n");
				exit_clean(1);
			}
			break;
		case IDX_WF_TCP_OUT:
			hash_wf_tcp_out = hash_jen(optarg, strlen(optarg));
			if (!wf_make_pf(optarg, "tcp", "SrcPort", params.wf_pf_tcp_src_out, WINDIVERT_PORTFILTER_MAX) ||
				!wf_make_pf(optarg, "tcp", "DstPort", params.wf_pf_tcp_dst_out, WINDIVERT_PORTFILTER_MAX))
			{
				DLOG_ERR("bad value for --wf-tcp-out\n");
				exit_clean(1);
			}
			break;
		case IDX_WF_UDP_IN:
			hash_wf_udp_in = hash_jen(optarg, strlen(optarg));
			if (!wf_make_pf(optarg, "udp", "SrcPort", params.wf_pf_udp_src_in, WINDIVERT_PORTFILTER_MAX) ||
				!wf_make_pf(optarg, "udp", "DstPort", params.wf_pf_udp_dst_in, WINDIVERT_PORTFILTER_MAX))
			{
				DLOG_ERR("bad value for --wf-udp-in\n");
				exit_clean(1);
			}
			break;
		case IDX_WF_UDP_OUT:
			hash_wf_udp_out = hash_jen(optarg, strlen(optarg));
			if (!wf_make_pf(optarg, "udp", "SrcPort", params.wf_pf_udp_src_out, WINDIVERT_PORTFILTER_MAX) ||
				!wf_make_pf(optarg, "udp", "DstPort", params.wf_pf_udp_dst_out, WINDIVERT_PORTFILTER_MAX))
			{
				DLOG_ERR("bad value for --wf-udp-out\n");
				exit_clean(1);
			}
			break;
		case IDX_WF_RAW:
			hash_wf_raw = hash_jen(optarg, strlen(optarg));
			if (optarg[0] == '@')
			{
				size_t sz = WINDIVERT_MAX-1;
				load_file_or_exit(optarg, params.windivert_filter, &sz);
				params.windivert_filter[sz] = 0;
			}
			else
			{
				strncpy(params.windivert_filter, optarg, WINDIVERT_MAX);
				params.windivert_filter[WINDIVERT_MAX - 1] = '\0';
			}
			break;
		case IDX_WF_TCP_EMPTY:
			wf_tcp_empty = !optarg || atoi(optarg);
			break;
		case IDX_WF_RAW_PART:
			hash_wf_raw_part ^= hash_jen(optarg, strlen(optarg));
			{
				char *wfpart = malloc(WINDIVERT_MAX);
				if (!wfpart)
				{
					DLOG_ERR("out of memory\n");
					exit_clean(1);
				}
				if (optarg[0] == '@')
				{
					size_t sz = WINDIVERT_MAX - 1;
					load_file_or_exit(optarg, wfpart, &sz);
					wfpart[sz] = 0;
				}
				else
				{
					strncpy(wfpart, optarg, WINDIVERT_MAX);
					wfpart[WINDIVERT_MAX - 1] = '\0';
				}
				if (!strlist_add(&params.wf_raw_part, wfpart))
				{
					free(wfpart);
					DLOG_ERR("out of memory\n");
					exit_clean(1);
				}
				free(wfpart);
			}
			break;
		case IDX_WF_FILTER_LAN:
			wf_filter_lan = !!atoi(optarg);
			break;
		case IDX_WF_SAVE:
			strncpy(wf_save_file, optarg, sizeof(wf_save_file));
			wf_save_file[sizeof(wf_save_file) - 1] = '\0';
			break;
		case IDX_SSID_FILTER:
			hash_ssid_filter = hash_jen(optarg, strlen(optarg));
			if (!parse_strlist(optarg, &params.ssid_filter))
			{
				DLOG_ERR("strlist_add failed\n");
				exit_clean(1);
			}
			break;
		case IDX_NLM_FILTER:
			hash_nlm_filter = hash_jen(optarg, strlen(optarg));
			if (!parse_strlist(optarg, &params.nlm_filter))
			{
				DLOG_ERR("strlist_add failed\n");
				exit_clean(1);
			}
			break;
		case IDX_NLM_LIST:
			if (!nlm_list(optarg && !strcmp(optarg, "all")))
			{
				DLOG_ERR("could not get list of NLM networks\n");
				exit_clean(1);
			}
			exit_clean(0);

#endif
		}
	}
	if (bSkip)
	{
		LIST_REMOVE(dpl, next);
		dp_entry_destroy(dpl);
		desync_profile_count--;
	}
	else
	{
		check_dp(dp);
		if (bTemplate)
		{
			if (dp->name && dp_list_search_name(&params.desync_templates, dp->name))
			{
				DLOG_ERR("template '%s' already present\n", dp->name);
				exit_clean(1);
			}
			dpl->dp.n = ++desync_template_count;
			dp_list_move(&params.desync_templates, dpl);
			desync_profile_count--;
		}
	}

	// do not need args from file anymore
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
	cleanup_args(&params);
#endif
	argv = NULL; argc = 0;

#ifdef __linux__
	if (params.qnum < 0)
	{
		DLOG_ERR("Need queue number (--qnum)\n");
		exit_clean(1);
	}
#elif defined(BSD)
	if (!params.port)
	{
		DLOG_ERR("Need divert port (--port)\n");
		exit_clean(1);
	}
#endif

	DLOG("adding low-priority default empty desync profile\n");
	// add default empty profile
	if (!(dpl = dp_list_add(&params.desync_profiles)) || !(dpl->dp.name=strdup("no_action")))
	{
		DLOG_ERR("desync_profile_add: out of memory\n");
		exit_clean(1);
	}

	DLOG_CONDUP("we have %u user defined desync profile(s) and default low priority profile 0\n", desync_profile_count);
	DLOG_CONDUP("we have %u user defined desync template(s)\n", desync_template_count);

	if (params.writeable_dir_enable)
	{
		if (!make_writeable_dir())
		{
			DLOG_ERR("could not make writeable dir for LUA\n");
			exit_clean(1);
		}
		DLOG("LUA writeable dir : %s\n", getenv("WRITEABLE"));
	}
#ifndef __CYGWIN__
	if (params.droproot)
#endif
	{
		if (params.debug_target == LOG_TARGET_FILE && !ensure_file_access(params.debug_logfile))
			DLOG_ERR("could not make '%s' accessible. log file may not be writable after privilege drop\n", params.debug_logfile);
		if (*params.hostlist_auto_debuglog && !ensure_file_access(params.hostlist_auto_debuglog))
			DLOG_ERR("could not make '%s' accessible. auto hostlist debug log may not be writable after privilege drop\n", params.hostlist_auto_debuglog);
	}
	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		dp = &dpl->dp;

		if (params.server && dp->hostlist_auto)
		{
			DLOG_ERR("autohostlists not supported in server mode\n");
			exit_clean(1);
		}

#ifndef __CYGWIN__
		if (params.droproot)
#endif
		{
			if (dp->hostlist_auto && !ensure_file_access(dp->hostlist_auto->filename))
				DLOG_ERR("could not make '%s' accessible. auto hostlist file may not be writable after privilege drop\n", dp->hostlist_auto->filename);

		}
		LuaDesyncDebug(dp,"profile");
	}
	LIST_FOREACH(dpl, &params.desync_templates, next)
	{
		dp = &dpl->dp;
		LuaDesyncDebug(dp,"template");
	}

	if (!test_list_files())
		exit_clean(1);
	if (!lua_test_init_script_files())
		exit_clean(1);

	if (!LoadAllHostLists())
	{
		DLOG_ERR("hostlists load failed\n");
		exit_clean(1);
	}
	if (!LoadAllIpsets())
	{
		DLOG_ERR("ipset load failed\n");
		exit_clean(1);
	}

	DLOG("\nlists summary:\n");
	HostlistsDebug();
	IpsetsDebug();
	DLOG("\nblobs summary:\n");
	BlobDebug();
	DLOG("\n");

	// not required anymore. free memory
	dp_list_destroy(&params.desync_templates);

#ifdef __CYGWIN__
	if (!*params.windivert_filter)
	{
		if (!*params.wf_pf_tcp_src_in && !*params.wf_pf_udp_src_in && !*params.wf_pf_tcp_src_out && !*params.wf_pf_udp_src_out && LIST_EMPTY(&params.wf_raw_part))
		{
			DLOG_ERR("windivert filter : must specify port or/and partial raw filter\n");
			exit_clean(1);
		}
		// exchange src/dst ports in server mode
		bool b = params.server ?
			wf_make_filter(params.windivert_filter, WINDIVERT_MAX, IfIdx, SubIfIdx, wf_ipv4, wf_ipv6,
				wf_tcp_empty,
				params.wf_pf_tcp_dst_out, params.wf_pf_tcp_src_out,
				params.wf_pf_tcp_dst_in, params.wf_pf_tcp_src_in,
				params.wf_pf_udp_dst_in, params.wf_pf_udp_src_out,
				&params.wf_raw_part, wf_filter_lan) :
			wf_make_filter(params.windivert_filter, WINDIVERT_MAX, IfIdx, SubIfIdx, wf_ipv4, wf_ipv6,
				wf_tcp_empty,
				params.wf_pf_tcp_src_out, params.wf_pf_tcp_dst_out,
				params.wf_pf_tcp_src_in, params.wf_pf_tcp_dst_in,
				params.wf_pf_udp_src_in, params.wf_pf_udp_dst_out,
				&params.wf_raw_part, wf_filter_lan);
		cleanup_windivert_portfilters(&params);
		if (!b)
		{
			DLOG_ERR("windivert filter : could not make filter\n");
			exit_clean(1);
		}
		// free unneeded extra memory
		char *p = realloc(params.windivert_filter, strlen(params.windivert_filter)+1);
		if (p) params.windivert_filter=p;
	}
	DLOG("windivert filter size: %zu\nwindivert filter:\n%s\n", strlen(params.windivert_filter), params.windivert_filter);
	if (*wf_save_file)
	{
		if (save_file(wf_save_file, params.windivert_filter, strlen(params.windivert_filter)))
		{
			DLOG_ERR("windivert filter: raw filter saved to %s\n", wf_save_file);
			exit_clean(0);
		}
		else
		{
			DLOG_ERR("windivert filter: could not save raw filter to %s\n", wf_save_file);
			exit_clean(1);
		}
	}
	HANDLE hMutexArg;
	{
		char mutex_name[128];
		snprintf(mutex_name, sizeof(mutex_name), "Global\\winws2_arg_%u_%u_%u_%u_%u_%u_%u_%u_%u_%u", hash_wf_tcp_in, hash_wf_udp_in, hash_wf_tcp_out, hash_wf_udp_out, hash_wf_raw, hash_wf_raw_part, hash_ssid_filter, hash_nlm_filter, IfIdx, SubIfIdx, wf_ipv4, wf_ipv6);

		hMutexArg = CreateMutexA(NULL, TRUE, mutex_name);
		if (hMutexArg && GetLastError() == ERROR_ALREADY_EXISTS)
		{
			CloseHandle(hMutexArg);	hMutexArg = NULL;
			DLOG_ERR("A copy of winws2 is already running with the same filter\n");
			goto exiterr;
		}
	}
#endif

	if (bDry)
	{
#ifndef __CYGWIN__
		if (params.droproot)
		{
			if (!droproot(params.uid, params.user, params.gid, params.gid_count))
				exit_clean(1);
#ifdef __linux__
			if (!dropcaps())
				exit_clean(1);
#endif
			print_id();
			if (!test_list_files() || !lua_test_init_script_files())
				exit_clean(1);
		}
#endif
		DLOG_CONDUP("command line parameters verified\n");
		exit_clean(0);
	}

	if (params.ctrack_disable)
		DLOG_CONDUP("conntrack disabled ! some functions will not work. make sure it's what you want.\n");
	else
	{
		DLOG("initializing conntrack with timeouts tcp=%u:%u:%u udp=%u\n", params.ctrack_t_syn, params.ctrack_t_est, params.ctrack_t_fin, params.ctrack_t_udp);
		ConntrackPoolInit(&params.conntrack, 10, params.ctrack_t_syn, params.ctrack_t_est, params.ctrack_t_fin, params.ctrack_t_udp);
	}
	DLOG("ipcache lifetime %us\n", params.ipcache_lifetime);

#ifdef __linux__
	result = nfq_main();
#elif defined(BSD)
	result = dvt_main();
#elif defined(__CYGWIN__)
	result = win_main();
#else
#error unsupported OS
#endif
ex:
	rawsend_cleanup();
	cleanup_params(&params);
#ifdef __CYGWIN__
	if (hMutexArg)
	{
		ReleaseMutex(hMutexArg);
		CloseHandle(hMutexArg);
	}
#endif
	return result;
exiterr:
	result = 1;
	goto ex;
}
