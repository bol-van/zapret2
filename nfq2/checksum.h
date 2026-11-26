#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#define __FAVOR_BSD
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// icmp 4 and 6 are basically compatible although checksums are calculated differently
// do not use version specific structs
struct icmp46
{
	uint8_t	icmp_type, icmp_code;
	uint16_t icmp_cksum;
	union
	{
		uint32_t data32;
		uint16_t data16[2];
		uint8_t data8[4];
	} data;
};

uint16_t ip4_compute_csum(const void *buff, size_t len);
void ip4_fix_checksum(struct ip *ip);

void tcp4_fix_checksum(struct tcphdr *tcp,size_t len, const struct in_addr *src_addr, const struct in_addr *dest_addr);
void tcp6_fix_checksum(struct tcphdr *tcp,size_t len, const struct in6_addr *src_addr, const struct in6_addr *dest_addr);
void tcp_fix_checksum(struct tcphdr *tcp,size_t len,const struct ip *ip,const struct ip6_hdr *ip6hdr);

void udp4_fix_checksum(struct udphdr *udp,size_t len, const struct in_addr *src_addr, const struct in_addr *dest_addr);
void udp6_fix_checksum(struct udphdr *udp,size_t len, const struct in6_addr *src_addr, const struct in6_addr *dest_addr);
void udp_fix_checksum(struct udphdr *udp,size_t len,const struct ip *ip,const struct ip6_hdr *ip6hdr);

void icmp4_fix_checksum(struct icmp46 *icmp, size_t len);
void icmp6_fix_checksum(struct icmp46 *icmp, size_t len, const struct ip6_hdr *ip6hdr);
void icmp_fix_checksum(struct icmp46 *icmp, size_t len, const struct ip6_hdr *ip6hdr);
