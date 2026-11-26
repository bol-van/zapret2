#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "helpers.h"

typedef enum {
	L7_ALL=0,
	L7_UNKNOWN,
	L7_KNOWN,
	L7_HTTP,
	L7_TLS,
	L7_DTLS,
	L7_QUIC,
	L7_WIREGUARD,
	L7_DHT,
	L7_DISCORD,
	L7_STUN,
	L7_XMPP,
	L7_DNS,
	L7_MTPROTO,
	L7_BT,
	L7_UTP_BT,
	L7_LAST, L7_INVALID=L7_LAST, L7_NONE=L7_LAST
} t_l7proto;
const char *l7proto_str(t_l7proto l7);
t_l7proto l7proto_from_name(const char *name);
bool l7_proto_match(t_l7proto l7proto, uint64_t filter_l7);

typedef enum {
	L7P_ALL=0,
	L7P_UNKNOWN,
	L7P_EMPTY,
	L7P_KNOWN,
	L7P_IPV4,
	L7P_IPV6,
	L7P_ICMP,
	L7P_HTTP_REQ,
	L7P_HTTP_REPLY,
	L7P_TLS_CLIENT_HELLO,
	L7P_TLS_SERVER_HELLO,
	L7P_DTLS_CLIENT_HELLO,
	L7P_DTLS_SERVER_HELLO,
	L7P_QUIC_INITIAL,
	L7P_WIREGUARD_INITIATION,
	L7P_WIREGUARD_RESPONSE,
	L7P_WIREGUARD_COOKIE,
	L7P_WIREGUARD_KEEPALIVE,
	L7P_WIREGUARD_DATA,
	L7P_DHT,
	L7P_DISCORD_IP_DISCOVERY,
	L7P_STUN,
	L7P_XMPP_STREAM,
	L7P_XMPP_STARTTLS,
	L7P_XMPP_PROCEED,
	L7P_XMPP_FEATURES,
	L7P_DNS_QUERY,
	L7P_DNS_RESPONSE,
	L7P_MTPROTO_INITIAL,
	L7P_BT_HANDSHAKE,
	L7P_UTP_BT_HANDSHAKE,
	L7P_LAST, L7P_INVALID=L7P_LAST, L7P_NONE=L7P_LAST
} t_l7payload;
t_l7payload l7payload_from_name(const char *name);
const char *l7payload_str(t_l7payload l7);
bool l7_payload_match(t_l7payload l7payload, uint64_t filter_l7p);
bool l7_payload_str_list(uint64_t l7p, char *buf, size_t size);

typedef enum {
	PM_ABS=0,
	PM_HOST,
	PM_HOST_END,
	PM_HOST_SLD,
	PM_HOST_MIDSLD,
	PM_HOST_ENDSLD,
	PM_HTTP_METHOD,
	PM_EXT_LEN,
	PM_SNI_EXT,
	PM_LAST, PM_INVALID=PM_LAST
} t_marker;
struct proto_pos
{
	int16_t pos;
	t_marker marker;
};
#define PROTO_POS_EMPTY(sp) ((sp)->marker==PM_ABS && (sp)->pos==0)
const char *posmarker_name(t_marker posmarker);
t_marker posmarker_from_name(const char *name);
bool posmarker_parse(const char *s, struct proto_pos *m);
bool posmarker_list_parse(const char *s, struct proto_pos *m, int *mct);

#define POS_NOT_FOUND ((ssize_t)-1)
ssize_t AnyProtoPos(t_marker posmarker, int16_t pos, const uint8_t *data, size_t sz);
ssize_t HttpPos(t_marker posmarker, int16_t pos, const uint8_t *data, size_t sz);
ssize_t TLSPos(t_marker posmarker, int16_t pos, const uint8_t *data, size_t sz);
ssize_t ResolvePos(const uint8_t *data, size_t sz, t_l7payload l7payload, const struct proto_pos *sp);
void ResolveMultiPos(const uint8_t *data, size_t sz, t_l7payload l7payload, const struct proto_pos *marker, int marker_count, ssize_t *pos, int *pos_count);

bool IsHttp(const uint8_t *data, size_t len);
bool HttpFindHost(uint8_t **pHost,uint8_t *buf,size_t bs);
// header must be passed like this : "\nHost:"
bool HttpExtractHeader(const uint8_t *data, size_t len, const char *header, char *buf, size_t len_buf);
bool HttpExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host);
bool IsHttpReply(const uint8_t *data, size_t len);
// must be pre-checked by IsHttpReply
int HttpReplyCode(const uint8_t *data);
// must be pre-checked by IsHttpReply
bool HttpReplyLooksLikeDPIRedirect(const uint8_t *data, size_t len, const char *host, bool host_is_ip);


const char *TLSVersionStr(uint16_t tlsver);
uint16_t TLSRecordDataLen(const uint8_t *data);
size_t TLSRecordLen(const uint8_t *data);
bool IsTLSRecordFull(const uint8_t *data, size_t len);
bool IsTLSHandshakeHello(const uint8_t *data, size_t len, uint8_t type, bool bPartialIsOK);
bool IsTLSHandshakeClientHello(const uint8_t *data, size_t len, bool bPartialIsOK);
bool IsTLSHandshakeServerHello(const uint8_t *data, size_t len, bool bPartialIsOK);
bool IsTLSHello(const uint8_t *data, size_t len, uint8_t type, bool bPartialIsOK);
bool IsTLSClientHello(const uint8_t *data, size_t len, bool bPartialIsOK);
bool IsTLSServerHello(const uint8_t *data, size_t len, bool bPartialIsOK);
bool IsTLSClientHelloPartial(const uint8_t *data, size_t len);
bool IsTLSServerHelloPartial(const uint8_t *data, size_t len);
size_t TLSHandshakeLen(const uint8_t *data);
size_t TLSHandshakeDataLen(const uint8_t *data);
bool IsTLSHandshakeFull(const uint8_t *data, size_t len);
bool TLSAdvanceToHostInSNI(const uint8_t **ext, size_t *elen, size_t *slen);
bool TLSFindExtLen(const uint8_t *data, size_t len, size_t *off);
bool TLSFindExtLenOffsetInHandshake(const uint8_t *data, size_t len, size_t *off);
bool TLSFindExt(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK);
bool TLSFindExtInHandshake(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK);
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK);
bool TLSHelloExtractHostFromHandshake(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK);

struct fake_tls_mod
{
	char sni[256];
	uint32_t mod;
};
#define FAKE_TLS_MOD_RND		0x01
#define FAKE_TLS_MOD_RND_SNI		0x02
#define FAKE_TLS_MOD_SNI		0x04
#define FAKE_TLS_MOD_DUP_SID		0x08
#define FAKE_TLS_MOD_PADENCAP		0x10

bool TLSMod_parse_list(const char *modlist, struct fake_tls_mod *tls_mod);
bool TLSMod(const struct fake_tls_mod *tls_mod, const uint8_t *payload, size_t payload_len, uint8_t *fake_tls, size_t *fake_tls_size, size_t fake_tls_buf_size);

bool IsXMPPStream(const uint8_t *data, size_t len);
bool IsXMPPStartTLS(const uint8_t *data, size_t len);
bool IsXMPPProceedTLS(const uint8_t *data, size_t len);
bool IsXMPPFeatures(const uint8_t *data, size_t len);

bool IsDNSQuery(const uint8_t *data, size_t len);
bool IsDNSResponse(const uint8_t *data, size_t len);
bool IsWireguardHandshakeInitiation(const uint8_t *data, size_t len);
bool IsWireguardHandshakeResponse(const uint8_t *data, size_t len);
bool IsWireguardHandshakeCookie(const uint8_t *data, size_t len);
bool IsWireguardKeepalive(const uint8_t *data, size_t len);
bool IsWireguardData(const uint8_t *data, size_t len);
bool IsDht(const uint8_t *data, size_t len);
bool IsDiscordIpDiscoveryRequest(const uint8_t *data, size_t len);
bool IsStunMessage(const uint8_t *data, size_t len);
bool IsMTProto(const uint8_t *data, size_t len);
bool IsDTLS(const uint8_t *data, size_t len);
bool IsDTLSClientHello(const uint8_t *data, size_t len);
bool IsDTLSServerHello(const uint8_t *data, size_t len);
bool IsBTHandshake(const uint8_t *data, size_t len);
bool IsUTP_BTHandshake(const uint8_t *data, size_t len);

#define QUIC_MAX_CID_LENGTH  20
typedef struct quic_cid {
	uint8_t      len;
	uint8_t      cid[QUIC_MAX_CID_LENGTH];
} quic_cid_t;

bool IsQUICInitial(const uint8_t *data, size_t len);
bool IsQUICCryptoHello(const uint8_t *data, size_t len, size_t *hello_offset, size_t *hello_len);
bool QUICIsLongHeader(const uint8_t *data, size_t len);
uint32_t QUICExtractVersion(const uint8_t *data, size_t len);
uint8_t QUICDraftVersion(uint32_t version);
bool QUICExtractDCID(const uint8_t *data, size_t len, quic_cid_t *cid);

bool QUICDecryptInitial(const uint8_t *data, size_t data_len, uint8_t *clean, size_t *clean_len);
// returns true if crypto frames were found . bFull = true if crypto frame fragments have full coverage
bool QUICDefragCrypto(const uint8_t *clean,size_t clean_len, uint8_t *defrag,size_t *defrag_len, bool *bFull);
//bool QUICExtractHostFromInitial(const uint8_t *data, size_t data_len, char *host, size_t len_host, bool *bDecryptOK, bool *bIsCryptoHello);
