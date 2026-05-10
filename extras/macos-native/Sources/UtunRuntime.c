#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sys_domain.h>

#ifndef UTUN_OPT_IFNAME
#define UTUN_OPT_IFNAME 2
#endif

#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif

#define MAX_SESSIONS 512
#define MAX_PACKET_SIZE 65536
#define UTUN_HEADER_SIZE 4
#define SESSION_IDLE_TIMEOUT 120
#define UDP_IPFRAG_FIRST_PAYLOAD 16

static volatile sig_atomic_t keep_running = 1;

struct relay_counters
{
	unsigned long long packets_read;
	unsigned long long udp_out;
	unsigned long long udp_in;
	unsigned long long unsupported;
	unsigned long long malformed;
	unsigned long long relay_errors;
};

struct udp_session
{
	int fd;
	uint32_t local_ip;
	uint32_t remote_ip;
	uint16_t local_port;
	uint16_t remote_port;
	time_t last_seen;
};

static uint16_t next_ip_id = 1;

static void handle_signal(int signal_number)
{
	(void)signal_number;
	keep_running = 0;
}

static int open_utun(char *ifname, size_t ifname_len)
{
	int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd < 0)
	{
		fprintf(stderr, "utun socket failed: %s\n", strerror(errno));
		return -1;
	}

	struct ctl_info info;
	memset(&info, 0, sizeof(info));
	snprintf(info.ctl_name, sizeof(info.ctl_name), "%s", "com.apple.net.utun_control");
	if (ioctl(fd, CTLIOCGINFO, &info) < 0)
	{
		fprintf(stderr, "utun control lookup failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	struct sockaddr_ctl address;
	memset(&address, 0, sizeof(address));
	address.sc_len = sizeof(address);
	address.sc_family = AF_SYSTEM;
	address.ss_sysaddr = AF_SYS_CONTROL;
	address.sc_id = info.ctl_id;
	address.sc_unit = 0;

	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
		fprintf(stderr, "utun connect failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	socklen_t len = (socklen_t)ifname_len;
	if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &len) < 0)
	{
		fprintf(stderr, "utun interface name lookup failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static uint16_t read_be16(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static void write_be16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)(v & 0xff);
}

static void write_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)((v >> 16) & 0xff);
	p[2] = (unsigned char)((v >> 8) & 0xff);
	p[3] = (unsigned char)(v & 0xff);
}

static uint16_t checksum16(const unsigned char *data, size_t len)
{
	uint32_t sum = 0;
	for (size_t i = 0; i + 1 < len; i += 2)
		sum += ((uint16_t)data[i] << 8) | data[i + 1];
	if (len & 1)
		sum += (uint16_t)data[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static const unsigned char *ip_packet_from_utun(const unsigned char *packet, ssize_t len, size_t *ip_len)
{
	if (len <= 0)
		return NULL;
	if ((packet[0] >> 4) == 4)
	{
		*ip_len = (size_t)len;
		return packet;
	}
	if (len > UTUN_HEADER_SIZE && (packet[UTUN_HEADER_SIZE] >> 4) == 4)
	{
		*ip_len = (size_t)len - UTUN_HEADER_SIZE;
		return packet + UTUN_HEADER_SIZE;
	}
	return NULL;
}

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int bind_socket_to_interface(int fd, const char *ifname)
{
	if (!ifname || !*ifname)
		return 0;
	unsigned int ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return -1;
	return setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &ifindex, sizeof(ifindex));
}

static int open_raw_ip_socket(const char *egress_interface)
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0)
		return -1;
	int on = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		close(fd);
		return -1;
	}
	if (bind_socket_to_interface(fd, egress_interface) < 0)
	{
		fprintf(stderr, "warning: could not bind raw udp socket to %s: %s\n", egress_interface ? egress_interface : "", strerror(errno));
	}
	return fd;
}

static int send_raw_ipv4(int raw_fd, const unsigned char *packet, size_t len, uint32_t remote_ip)
{
	struct sockaddr_in remote;
	memset(&remote, 0, sizeof(remote));
	remote.sin_len = sizeof(remote);
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = remote_ip;
	ssize_t sent = sendto(raw_fd, packet, len, 0, (struct sockaddr *)&remote, sizeof(remote));
	return sent == (ssize_t)len ? 0 : -1;
}

static int send_ip_fragment(int raw_fd, const unsigned char *ip, size_t ihl, uint16_t total_len, size_t payload_offset, size_t payload_len, uint16_t ip_id, int more_fragments)
{
	unsigned char fragment[MAX_PACKET_SIZE];
	size_t fragment_len = ihl + payload_len;
	if (fragment_len > sizeof(fragment))
		return -1;

	memcpy(fragment, ip, ihl);
	memcpy(fragment + ihl, ip + ihl + payload_offset, payload_len);
	write_be16(fragment + 2, (uint16_t)fragment_len);
	write_be16(fragment + 4, ip_id);
	uint16_t fragment_offset = (uint16_t)(payload_offset / 8);
	uint16_t flags_offset = (uint16_t)(fragment_offset | (more_fragments ? 0x2000 : 0));
	write_be16(fragment + 6, flags_offset);
	fragment[10] = 0;
	fragment[11] = 0;
	write_be16(fragment + 10, checksum16(fragment, ihl));

	uint32_t remote_ip;
	memcpy(&remote_ip, ip + 16, sizeof(remote_ip));
	(void)total_len;
	return send_raw_ipv4(raw_fd, fragment, fragment_len, remote_ip);
}

static int send_udp_ipfrag_packet(int raw_fd, const unsigned char *ip, size_t ihl, uint16_t total_len)
{
	if (raw_fd < 0 || total_len <= ihl)
		return -1;

	size_t payload_len = total_len - ihl;
	uint16_t ip_id = read_be16(ip + 4);
	if (ip_id == 0)
		ip_id = next_ip_id++;

	if (payload_len <= UDP_IPFRAG_FIRST_PAYLOAD)
		return send_ip_fragment(raw_fd, ip, ihl, total_len, 0, payload_len, ip_id, 0);

	size_t first_payload_len = UDP_IPFRAG_FIRST_PAYLOAD;
	size_t second_payload_len = payload_len - first_payload_len;
	if (send_ip_fragment(raw_fd, ip, ihl, total_len, 0, first_payload_len, ip_id, 1) < 0)
		return -1;
	return send_ip_fragment(raw_fd, ip, ihl, total_len, first_payload_len, second_payload_len, ip_id, 0);
}

static struct udp_session *find_session(struct udp_session *sessions, uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port)
{
	for (size_t i = 0; i < MAX_SESSIONS; i++)
	{
		struct udp_session *session = &sessions[i];
		if (session->fd >= 0 &&
		    session->local_ip == local_ip &&
		    session->local_port == local_port &&
		    session->remote_ip == remote_ip &&
		    session->remote_port == remote_port)
			return session;
	}
	return NULL;
}

static struct udp_session *oldest_or_free_session(struct udp_session *sessions)
{
	size_t selected = 0;
	for (size_t i = 0; i < MAX_SESSIONS; i++)
	{
		if (sessions[i].fd < 0)
			return &sessions[i];
		if (sessions[i].last_seen < sessions[selected].last_seen)
			selected = i;
	}
	close(sessions[selected].fd);
	sessions[selected].fd = -1;
	return &sessions[selected];
}

static struct udp_session *get_session(
	struct udp_session *sessions,
	uint32_t local_ip,
	uint16_t local_port,
	uint32_t remote_ip,
	uint16_t remote_port,
	const char *egress_interface)
{
	struct udp_session *session = find_session(sessions, local_ip, local_port, remote_ip, remote_port);
	if (session)
	{
		session->last_seen = time(NULL);
		return session;
	}

	session = oldest_or_free_session(sessions);
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return NULL;
	if (bind_socket_to_interface(fd, egress_interface) < 0)
	{
		fprintf(stderr, "warning: could not bind udp relay socket to %s: %s\n", egress_interface ? egress_interface : "", strerror(errno));
	}
	set_nonblocking(fd);

	struct sockaddr_in remote;
	memset(&remote, 0, sizeof(remote));
	remote.sin_len = sizeof(remote);
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = remote_ip;
	remote.sin_port = htons(remote_port);
	if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0)
	{
		close(fd);
		return NULL;
	}

	session->fd = fd;
	session->local_ip = local_ip;
	session->local_port = local_port;
	session->remote_ip = remote_ip;
	session->remote_port = remote_port;
	session->last_seen = time(NULL);
	return session;
}

static void expire_sessions(struct udp_session *sessions)
{
	time_t now = time(NULL);
	for (size_t i = 0; i < MAX_SESSIONS; i++)
	{
		if (sessions[i].fd >= 0 && now - sessions[i].last_seen > SESSION_IDLE_TIMEOUT)
		{
			close(sessions[i].fd);
			sessions[i].fd = -1;
		}
	}
}

static size_t active_session_count(const struct udp_session *sessions)
{
	size_t count = 0;
	for (size_t i = 0; i < MAX_SESSIONS; i++)
	{
		if (sessions[i].fd >= 0)
			count++;
	}
	return count;
}

static int handle_outbound_packet(
	struct udp_session *sessions,
	int raw_fd,
	const unsigned char *packet,
	size_t len,
	const char *egress_interface,
	struct relay_counters *counters)
{
	size_t ip_len = 0;
	const unsigned char *ip = ip_packet_from_utun(packet, (ssize_t)len, &ip_len);
	if (!ip)
	{
		counters->unsupported++;
		return 0;
	}
	if (ip_len < 28 || (ip[0] >> 4) != 4)
	{
		counters->malformed++;
		return 0;
	}
	size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
	if (ihl < 20 || ip_len < ihl + 8 || ip[9] != IPPROTO_UDP)
	{
		counters->unsupported++;
		return 0;
	}
	uint16_t total_len = read_be16(ip + 2);
	if (total_len < ihl + 8 || total_len > ip_len)
	{
		counters->malformed++;
		return 0;
	}

	const unsigned char *udp = ip + ihl;
	uint16_t udp_len = read_be16(udp + 4);
	if (udp_len < 8 || ihl + udp_len > total_len)
	{
		counters->malformed++;
		return 0;
	}

	uint32_t local_ip;
	uint32_t remote_ip;
	memcpy(&local_ip, ip + 12, sizeof(local_ip));
	memcpy(&remote_ip, ip + 16, sizeof(remote_ip));
	uint16_t local_port = read_be16(udp);
	uint16_t remote_port = read_be16(udp + 2);
	const unsigned char *payload = udp + 8;
	size_t payload_len = udp_len - 8;

	if (raw_fd >= 0)
	{
		if (send_udp_ipfrag_packet(raw_fd, ip, ihl, total_len) == 0)
		{
			counters->udp_out++;
			return 0;
		}
		// Some macOS/provider combinations reject crafted raw fragments. Fall back
		// to the socket relay so Discord media does not hard-fail during testing.
	}

	struct udp_session *session = get_session(sessions, local_ip, local_port, remote_ip, remote_port, egress_interface);
	if (!session)
	{
		counters->relay_errors++;
		return -1;
	}

	ssize_t sent = send(session->fd, payload, payload_len, 0);
	if (sent < 0 && errno != EWOULDBLOCK && errno != EAGAIN)
	{
		counters->relay_errors++;
		return -1;
	}
	counters->udp_out++;
	return 0;
}

static int write_response_packet(int utun_fd, const struct udp_session *session, const unsigned char *payload, size_t payload_len)
{
	unsigned char packet[MAX_PACKET_SIZE];
	size_t ip_len = 20 + 8 + payload_len;
	if (ip_len + UTUN_HEADER_SIZE > sizeof(packet))
		return -1;

	memset(packet, 0, UTUN_HEADER_SIZE + ip_len);
	write_be32(packet, AF_INET);
	unsigned char *ip = packet + UTUN_HEADER_SIZE;
	ip[0] = 0x45;
	ip[1] = 0;
	write_be16(ip + 2, (uint16_t)ip_len);
	write_be16(ip + 4, 0);
	write_be16(ip + 6, 0);
	ip[8] = 64;
	ip[9] = IPPROTO_UDP;
	memcpy(ip + 12, &session->remote_ip, sizeof(session->remote_ip));
	memcpy(ip + 16, &session->local_ip, sizeof(session->local_ip));
	write_be16(ip + 10, checksum16(ip, 20));

	unsigned char *udp = ip + 20;
	write_be16(udp, session->remote_port);
	write_be16(udp + 2, session->local_port);
	write_be16(udp + 4, (uint16_t)(8 + payload_len));
	write_be16(udp + 6, 0);
	memcpy(udp + 8, payload, payload_len);

	return write(utun_fd, packet, UTUN_HEADER_SIZE + ip_len) < 0 ? -1 : 0;
}

static void handle_session_reads(int utun_fd, struct udp_session *sessions, fd_set *readfds, struct relay_counters *counters)
{
	unsigned char buffer[MAX_PACKET_SIZE];
	for (size_t i = 0; i < MAX_SESSIONS; i++)
	{
		struct udp_session *session = &sessions[i];
		if (session->fd < 0 || !FD_ISSET(session->fd, readfds))
			continue;
		for (;;)
		{
			ssize_t n = recv(session->fd, buffer, sizeof(buffer), 0);
			if (n < 0)
			{
				if (errno == EWOULDBLOCK || errno == EAGAIN)
					break;
				counters->relay_errors++;
				close(session->fd);
				session->fd = -1;
				break;
			}
			if (n == 0)
				break;
			session->last_seen = time(NULL);
			if (write_response_packet(utun_fd, session, buffer, (size_t)n) == 0)
				counters->udp_in++;
			else
				counters->relay_errors++;
		}
	}
}

static void write_text_file(const char *path, const char *text)
{
	if (!path || !text)
		return;

	FILE *file = fopen(path, "w");
	if (!file)
		return;
	fputs(text, file);
	fclose(file);
}

static void write_state(const char *path, const char *ifname, const char *egress_interface, const struct relay_counters *counters, size_t sessions, const char *relay_mode)
{
	if (!path)
		return;

	FILE *file = fopen(path, "w");
	if (!file)
		return;

	fprintf(file, "runtime=running\n");
	fprintf(file, "interface=%s\n", ifname);
	fprintf(file, "egress_interface=%s\n", egress_interface && *egress_interface ? egress_interface : "default");
	fprintf(file, "packets_read=%llu\n", counters->packets_read);
	fprintf(file, "udp_out=%llu\n", counters->udp_out);
	fprintf(file, "udp_in=%llu\n", counters->udp_in);
	fprintf(file, "unsupported=%llu\n", counters->unsupported);
	fprintf(file, "malformed=%llu\n", counters->malformed);
	fprintf(file, "relay_errors=%llu\n", counters->relay_errors);
	fprintf(file, "packet_drops=%llu\n", counters->malformed + counters->relay_errors);
	fprintf(file, "active_sessions=%zu\n", sessions);
	fprintf(file, "updated_at=%lld\n", (long long)time(NULL));
	fprintf(file, "relay=udp_relay_active\n");
	fprintf(file, "relay_mode=%s\n", relay_mode ? relay_mode : "socket-forward");
	fclose(file);
}

int main(int argc, char **argv)
{
	const char *pid_file = NULL;
	const char *state_file = NULL;
	const char *egress_interface = NULL;

	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--pid-file") == 0 && i + 1 < argc)
			pid_file = argv[++i];
		else if (strcmp(argv[i], "--state-file") == 0 && i + 1 < argc)
			state_file = argv[++i];
		else if (strcmp(argv[i], "--egress-interface") == 0 && i + 1 < argc)
			egress_interface = argv[++i];
	}

	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);

	char ifname[64];
	int fd = open_utun(ifname, sizeof(ifname));
	if (fd < 0)
		return 1;
	int raw_fd = open_raw_ip_socket(egress_interface);
	if (raw_fd < 0)
	{
		fprintf(stderr, "warning: raw UDP ipfrag socket unavailable, falling back to socket relay: %s\n", strerror(errno));
	}
	const char *relay_mode = raw_fd >= 0 ? "raw-ipfrag" : "socket-forward";

	if (pid_file)
	{
		char pid_text[64];
		snprintf(pid_text, sizeof(pid_text), "%d\n", getpid());
		write_text_file(pid_file, pid_text);
	}

	struct udp_session sessions[MAX_SESSIONS];
	for (size_t i = 0; i < MAX_SESSIONS; i++)
		sessions[i].fd = -1;
	struct relay_counters counters;
	memset(&counters, 0, sizeof(counters));
	write_state(state_file, ifname, egress_interface, &counters, active_session_count(sessions), relay_mode);
	printf("utun runtime started: %s\n", ifname);
	printf("udp relay mode: %s\n", relay_mode);
	fflush(stdout);

	while (keep_running)
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		int maxfd = fd;
		for (size_t i = 0; i < MAX_SESSIONS; i++)
		{
			if (sessions[i].fd >= 0)
			{
				FD_SET(sessions[i].fd, &readfds);
				if (sessions[i].fd > maxfd)
					maxfd = sessions[i].fd;
			}
		}
		struct timeval timeout;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		int ready = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
		if (ready < 0)
		{
			if (errno == EINTR)
				continue;
			fprintf(stderr, "select failed: %s\n", strerror(errno));
			break;
		}
		if (ready == 0)
		{
			expire_sessions(sessions);
			write_state(state_file, ifname, egress_interface, &counters, active_session_count(sessions), relay_mode);
			continue;
		}
		if (FD_ISSET(fd, &readfds))
		{
			unsigned char packet[MAX_PACKET_SIZE];
			ssize_t n = read(fd, packet, sizeof(packet));
			if (n < 0)
			{
				if (errno == EINTR)
					continue;
				fprintf(stderr, "utun read failed: %s\n", strerror(errno));
				break;
			}
			if (n > 0)
			{
				counters.packets_read++;
				handle_outbound_packet(sessions, raw_fd, packet, (size_t)n, egress_interface, &counters);
			}
		}
		if (raw_fd < 0)
			handle_session_reads(fd, sessions, &readfds, &counters);
		if ((counters.packets_read + counters.udp_in + counters.relay_errors) % 100 == 0)
			write_state(state_file, ifname, egress_interface, &counters, active_session_count(sessions), relay_mode);
	}

	write_text_file(state_file, "runtime=stopped\n");
	if (pid_file)
		unlink(pid_file);
	for (size_t i = 0; i < MAX_SESSIONS; i++)
	{
		if (sessions[i].fd >= 0)
			close(sessions[i].fd);
	}
	if (raw_fd >= 0)
		close(raw_fd);
	close(fd);
	return 0;
}
