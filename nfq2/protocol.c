#define _GNU_SOURCE

#include "protocol.h"
#include "helpers.h"
#include "params.h"
#include "crypto/sha.h"
#include "crypto/aes-gcm.h"
#include "crypto/aes-ctr.h"

#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <string.h>

// find N level domain
static bool FindNLD(const uint8_t *dom, size_t dlen, int level, const uint8_t **p, size_t *len)
{
	int i;
	const uint8_t *p1,*p2;

	if (level<1) return false;
	for (i=1,p2=dom+dlen;i<level;i++)
	{
		for (p2--; p2>dom && *p2!='.'; p2--);
		if (p2<=dom) return false;
	}
	for (p1=p2-1 ; p1>dom && *p1!='.'; p1--);
	if (p1<dom) return false;
	if (*p1=='.') p1++;
	if (p) *p = p1;
	if (len) *len = p2-p1;
	return true;
}

static const char *l7proto_name[] = {
"all","unknown","known","http","tls","dtls","quic","wireguard","dht","discord","stun","xmpp","dns","mtproto","bt","utp_bt"
};
const char *l7proto_str(t_l7proto l7)
{
	if (l7>=L7_LAST) return NULL;
	return l7proto_name[l7];
}
t_l7proto l7proto_from_name(const char *name)
{
	int idx = str_index(l7proto_name,sizeof(l7proto_name)/sizeof(*l7proto_name),name);
	return idx<0 ? L7_INVALID : (t_l7proto)idx;
}
bool l7_proto_match(t_l7proto l7proto, uint64_t filter_l7)
{
	return (filter_l7==L7_ALL) || (filter_l7 & (1ULL<<l7proto)) || (filter_l7 & (1ULL<<L7_KNOWN)) && (l7proto>L7_KNOWN) && (l7proto<L7_LAST);
}

static const char *l7payload_name[] = {
 "all","unknown","empty","known",
 "ipv4","ipv6","icmp",
 "http_req","http_reply",
 "tls_client_hello","tls_server_hello",
 "dtls_client_hello","dtls_server_hello",
 "quic_initial",
 "wireguard_initiation","wireguard_response","wireguard_cookie","wireguard_keepalive","wireguard_data",
 "dht","discord_ip_discovery","stun",
 "xmpp_stream", "xmpp_starttls", "xmpp_proceed", "xmpp_features",
 "dns_query", "dns_response",
 "mtproto_initial",
 "bt_handshake", "utp_bt_handshake"
};
t_l7payload l7payload_from_name(const char *name)
{
	int idx = str_index(l7payload_name,sizeof(l7payload_name)/sizeof(*l7payload_name),name);
	return idx<0 ? L7P_INVALID : (t_l7payload)idx;
}
const char *l7payload_str(t_l7payload l7)
{
	if (l7>=L7P_LAST) return NULL;
	return l7payload_name[l7];
}
bool l7_payload_match(t_l7payload l7payload, uint64_t filter_l7p)
{
	return (filter_l7p==L7P_ALL) || (filter_l7p & (1ULL<<l7payload)) || (filter_l7p & (1ULL<<L7P_KNOWN)) && (l7payload>L7P_KNOWN) && (l7payload<L7P_LAST);
}
bool l7_payload_str_list(uint64_t l7p, char *buf, size_t size)
{
	char *p, *e;
	const char *pstr;
	size_t lstr;
	t_l7payload pl;

	if (!size) return false;
	if (l7p==L7P_ALL)
	{
		if (size<4) return false;
		memcpy(buf,"all",4);
		return true;
	}
	for(pl=0, p=buf, e=p+size, *buf=0 ; pl<L7P_LAST ; pl++)
	{
		if (l7p & (1ULL<<pl))
		{
			pstr = l7payload_str(pl);
			lstr = strlen(pstr);
			if ((p + (p!=buf) + lstr + 1) > e) return false;
			if (p!=buf) *p++=','; // not first
			memcpy(p,pstr,lstr);
			p[lstr]=0;
			p += lstr;
		}
	}
	return true;
}


static const char *posmarker_names[] = {"abs","host","endhost","sld","midsld","endsld","method","extlen","sniext"};
const char *posmarker_name(t_marker posmarker)
{
	if (posmarker>=PM_LAST) return NULL;
	return posmarker_names[posmarker];
}
t_marker posmarker_from_name(const char *name)
{
	int idx = str_index(posmarker_names,sizeof(posmarker_names)/sizeof(*posmarker_names),name);
	return idx<0 ? PM_INVALID : (t_marker)idx;
}
bool posmarker_parse(const char *s, struct proto_pos *m)
{
	if (parse_int16(s, &m->pos))
	{
		m->marker = PM_ABS;
		return true;
	}
	else
	{
		char c, sm[32];
		const char *p;
		bool b;

		for (p = s; *p && *p != '+' && *p != '-'; p++);
		if ((p-s)>=sizeof(sm)) return false;
		memcpy(sm,s,p-s);
		sm[p-s]=0;
		m->marker = posmarker_from_name(sm);
		if (m->marker==PM_INVALID) return false;
		if (*p)
			return parse_int16(p, &m->pos);
		else
			m->pos = 0;
	}
	return true;
}
bool posmarker_list_parse(const char *s, struct proto_pos *m, int *mct)
{
	const char *p, *e, *smm;
	int ct;
	char sm[32];

	if (!*s)
	{
		*mct = 0;
		return true;
	}
	for (p=s, ct=0; ct<*mct; ct++)
	{
		if ((e=strchr(p,',')))
		{
			if ((e-p)>=sizeof(sm)) return false;
			memcpy(sm,p,e-p);
			sm[e-p]=0;
			smm = sm;
		}
		else
			smm = p;
		if (!posmarker_parse(smm,m+ct)) return false;
		if (!e)
		{
			*mct = ct+1;
			return true;
		}
		p=e+1;
	}
	return false;
}

static ssize_t CheckPos(size_t sz, ssize_t offset)
{
	return (offset>=0 && offset<sz) ? offset : POS_NOT_FOUND;
}
ssize_t AnyProtoPos(t_marker posmarker, int16_t pos, const uint8_t *data, size_t sz)
{
	ssize_t offset;
	switch(posmarker)
	{
		case PM_ABS:
			offset = (pos<0) ? sz+pos : pos;
			return CheckPos(sz,offset);
		default:
			return POS_NOT_FOUND;
	}
}
static ssize_t HostPos(t_marker posmarker, int16_t pos, const uint8_t *data, size_t sz, size_t offset_host, size_t len_host)
{
	ssize_t offset;
	const uint8_t *p;
	size_t slen;

	switch(posmarker)
	{
		case PM_HOST:
			offset = offset_host+pos;
			break;
		case PM_HOST_END:
			offset = offset_host+len_host+pos;
			break;
		case PM_HOST_SLD:
		case PM_HOST_MIDSLD:
		case PM_HOST_ENDSLD:
			if (((offset_host+len_host)<=sz) && FindNLD(data+offset_host,len_host,2,&p,&slen))
			{
				offset = (posmarker==PM_HOST_SLD ? p-data : posmarker==PM_HOST_ENDSLD ? p-data+slen : slen==1 ? p+1-data : p+slen/2-data) + pos;
				break;
			}
		default:
			return POS_NOT_FOUND;
	}
	return CheckPos(sz,offset);
}
ssize_t ResolvePos(const uint8_t *data, size_t sz, t_l7payload l7payload, const struct proto_pos *sp)
{
	switch(l7payload)
	{
		case L7P_HTTP_REQ:
			return HttpPos(sp->marker, sp->pos, data, sz);
		case L7P_TLS_CLIENT_HELLO:
			return TLSPos(sp->marker, sp->pos, data, sz);
		default:
			return AnyProtoPos(sp->marker, sp->pos, data, sz);
	}
}
void ResolveMultiPos(const uint8_t *data, size_t sz, t_l7payload l7payload, const struct proto_pos *marker, int marker_count, ssize_t *pos, int *pos_count)
{
	int i,j;
	for(i=j=0;i<marker_count;i++)
	{
		pos[j] = ResolvePos(data,sz,l7payload,marker+i);
		if (pos[j]!=POS_NOT_FOUND) j++;
	}
	qsort_ssize_t(pos, j);
	j=unique_ssize_t(pos, j);
	*pos_count=j;
}


static const char *http_methods[] = { "GET ","POST ","HEAD ","OPTIONS ","PUT ","DELETE ","CONNECT ","TRACE ", "PATCH ", NULL };
static const char *HttpMethod(const uint8_t *data, size_t len)
{
	const char **method;
	size_t method_len;

	if (len>=4)
	{
		for (method = http_methods; *method; method++)
		{
			method_len = strlen(*method);
			if (method_len <= len && !memcmp(data, *method, method_len))
				return *method;
		}
	}
	return NULL;
}
bool IsHttp(const uint8_t *data, size_t len)
{
	if (!HttpMethod(data,len)) return false;
	// GET /uri HTTP/1.1
	// skip method
	for(; len && *data!=' ' && *data!='\t' && *data!='\r' && *data!='\n'; data++, len--);
	if (!len || *data!=' ' && *data!='\t') return false;
	for(; len && (*data==' '|| *data=='\t'); data++, len--);
	// skip URI
	for(; len && *data!=' ' && *data!='\t' && *data!='\r' && *data!='\n'; data++, len--);
	if (!len || *data!=' ' && *data!='\t') return false;
	for(; len && (*data==' '|| *data=='\t'); data++, len--);
	if (len<10 || *data=='\r' || *data=='\n')  return false;
	return !memcmp(data,"HTTP/1.",7);
}
static bool IsHostAt(const uint8_t *p)
{
	return \
		p[0]=='\n' &&
		(p[1]=='H' || p[1]=='h') &&
		(p[2]=='o' || p[2]=='O') &&
		(p[3]=='s' || p[3]=='S') &&
		(p[4]=='t' || p[4]=='T') &&
		p[5]==':';
}
static uint8_t *FindHostIn(uint8_t *buf, size_t bs)
{
	size_t pos;
	if (bs<6) return NULL;
	bs-=6;
	for(pos=0;pos<=bs;pos++)
		if (IsHostAt(buf+pos))
			return buf+pos;

	return NULL;
}
static const uint8_t *FindHostInConst(const uint8_t *buf, size_t bs)
{
	size_t pos;
	if (bs<6) return NULL;
	bs-=6;
	for(pos=0;pos<=bs;pos++)
		if (IsHostAt(buf+pos))
			return buf+pos;

	return NULL;
}
// pHost points to "Host: ..."
bool HttpFindHost(uint8_t **pHost,uint8_t *buf,size_t bs)
{
	if (!*pHost)
	{
		*pHost = FindHostIn(buf, bs);
		if (*pHost) (*pHost)++;
	}
	return *pHost;
}

bool IsHttpReply(const uint8_t *data, size_t len)
{
	// HTTP/1.x 200\r\n
	return len>14 && !memcmp(data,"HTTP/1.",7) && (data[7]=='0' || data[7]=='1') && data[8]==' ' &&
		data[9]>='0' && data[9]<='9' &&
		data[10]>='0' && data[10]<='9' &&
		data[11]>='0' && data[11]<='9';
}
int HttpReplyCode(const uint8_t *data)
{
	return (data[9]-'0')*100 + (data[10]-'0')*10 + (data[11]-'0');
}
bool HttpExtractHeader(const uint8_t *data, size_t len, const char *header, char *buf, size_t len_buf)
{
	const uint8_t *p, *s, *e = data + len;

	p = (uint8_t*)strncasestr((char*)data, header, len);
	if (!p) return false;
	p += strlen(header);
	while (p < e && (*p == ' ' || *p == '\t')) p++;
	s = p;
	while (s < e && (*s != '\r' && *s != '\n' && *s != ' ' && *s != '\t')) s++;
	if (s > p)
	{
		size_t slen = s - p;
		if (buf && len_buf)
		{
			if (slen >= len_buf) slen = len_buf - 1;
			for (size_t i = 0; i < slen; i++) buf[i] = tolower(p[i]);
			buf[slen] = 0;
		}
		return true;
	}
	return false;
}
bool HttpExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host)
{
	return HttpExtractHeader(data, len, "\nHost:", host, len_host);
}
// DPI redirects are global redirects to another domain
bool HttpReplyLooksLikeDPIRedirect(const uint8_t *data, size_t len, const char *host)
{
	char loc[256],*redirect_host, *p;
	int code;
	
	if (!host || !*host || !IsHttpReply(data, len)) return false;
	
	code = HttpReplyCode(data);
	
	if ((code!=302 && code!=307) || !HttpExtractHeader(data,len,"\nLocation:",loc,sizeof(loc))) return false;

	// something like : https://censor.net/badpage.php?reason=denied&source=RKN
		
	if (!strncmp(loc,"http://",7))
		redirect_host=loc+7;
	else if (!strncmp(loc,"https://",8))
		redirect_host=loc+8;
	else
		return false;
		
	// somethinkg like : censor.net/badpage.php?reason=denied&source=RKN
	
	for(p=redirect_host; *p && *p!='/' ; p++);
	*p=0;
	if (!*redirect_host) return false;

	// somethinkg like : censor.net
	
	// extract 2nd level domains
	const char *dhost, *drhost;
	if (!FindNLD((uint8_t*)redirect_host,strlen(redirect_host),2,(const uint8_t**)&drhost,NULL))
		return false;
	if (!FindNLD((uint8_t*)host,strlen(host),2,(const uint8_t**)&dhost,NULL))
		return true; // no SLD redirects to SLD

	// compare 2nd level domains		
	return strcasecmp(dhost, drhost)!=0;
}
ssize_t HttpPos(t_marker posmarker, int16_t pos, const uint8_t *data, size_t sz)
{
	const uint8_t *method, *host=NULL, *p;
	size_t offset_host,len_host;
	ssize_t offset;
	int i;
	
	switch(posmarker)
	{
		case PM_HTTP_METHOD:
			// recognize some tpws pre-applied hacks
			method=data;
			if (sz<12) break;
			if (*method=='\n' || *method=='\r') method++;
			if (*method=='\n' || *method=='\r') method++;
			// max length is PROPPATCH
			for (p=method,i=0; i<9 && *p>='A' && *p<='Z'; i++,p++);
			if (i<3 || *p!=' ') break;
			return CheckPos(sz,method-data+pos);
		case PM_HOST:
		case PM_HOST_END:
		case PM_HOST_SLD:
		case PM_HOST_MIDSLD:
		case PM_HOST_ENDSLD:
			if (HttpFindHost((uint8_t **)&host,(uint8_t*)data,sz) && (host-data+7)<sz)
			{
				host+=5;
				if (*host==' ' || *host=='\t') host++;
				offset_host = host-data;
				if (posmarker!=PM_HOST)
					for (len_host=0; (offset_host+len_host)<sz && data[offset_host+len_host]!='\r' && data[offset_host+len_host]!='\n'; len_host++);
				else
					len_host = 0;
				return HostPos(posmarker,pos,data,sz,offset_host,len_host);
			}
			break;
		default:
			return AnyProtoPos(posmarker,pos,data,sz);
	}
	return POS_NOT_FOUND;
}


const char *TLSVersionStr(uint16_t tlsver)
{
	switch(tlsver)
	{
		case 0x0300: return "SSL 3.0";
		case 0x0301: return "TLS 1.0";
		case 0x0302: return "TLS 1.1";
		case 0x0303: return "TLS 1.2";
		case 0x0304: return "TLS 1.3";
		default:
			// 0x0a0a, 0x1a1a, ..., 0xfafa
			return (((tlsver & 0x0F0F) == 0x0A0A) && ((tlsver>>12)==((tlsver>>4)&0xF))) ? "GREASE" : "UNKNOWN";
	}
}

size_t TLSHandshakeDataLen(const uint8_t *data)
{
	return pntoh24(data+1); // HandshakeProtocol length
}
size_t TLSHandshakeLen(const uint8_t *data)
{
	return TLSHandshakeDataLen(data)+4;
}
bool IsTLSHandshakeFull(const uint8_t *data, size_t len)
{
	return TLSHandshakeLen(data)<=len;
}
uint16_t TLSRecordDataLen(const uint8_t *data)
{
	return pntoh16(data + 3);
}
size_t TLSRecordLen(const uint8_t *data)
{
	return TLSRecordDataLen(data) + 5;
}
bool IsTLSRecordFull(const uint8_t *data, size_t len)
{
	return TLSRecordLen(data)<=len;
}
bool IsTLSHandshakeHello(const uint8_t *data, size_t len, uint8_t type, bool bPartialIsOK)
{
	return len >= 6 &&
		(type && data[0]==type || !type && (data[0]==0x01 || data[0]==0x02)) &&
		data[4]==0x03 && data[5] <= 0x03 &&
		(bPartialIsOK || IsTLSHandshakeFull(data,len));
}
bool IsTLSHandshakeClientHello(const uint8_t *data, size_t len, bool bPartialIsOK)
{
	return IsTLSHandshakeHello(data,len,0x01,bPartialIsOK);
}
bool IsTLSHandshakeServerHello(const uint8_t *data, size_t len, bool bPartialIsOK)
{
	return IsTLSHandshakeHello(data,len,0x02,bPartialIsOK);
}
bool IsTLSClientHelloPartial(const uint8_t *data, size_t len)
{
	return IsTLSClientHello(data,len,true);
}
bool IsTLSServerHelloPartial(const uint8_t *data, size_t len)
{
	return IsTLSServerHello(data,len,true);
}

bool IsTLSHello(const uint8_t *data, size_t len, uint8_t type, bool bPartialIsOK)
{
	return len >= 6 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03 && (bPartialIsOK || IsTLSRecordFull(data,len)) && IsTLSHandshakeHello(data+5,len-5,type,bPartialIsOK);
}
bool IsTLSClientHello(const uint8_t *data, size_t len, bool bPartialIsOK)
{
	return IsTLSHello(data,len,0x01,bPartialIsOK);
}
bool IsTLSServerHello(const uint8_t *data, size_t len, bool bPartialIsOK)
{
	return IsTLSHello(data,len,0x02,bPartialIsOK);
}


bool TLSFindExtLenOffsetInHandshake(const uint8_t *data, size_t len, size_t *off)
{
	// +0
	// u8	HandshakeType: ClientHello
	// u24	Length
	// u16	Version
	// c[32] random
	// u8	SessionIDLength
	//	<SessionID>

	// CLIENT
	// u16	CipherSuitesLength
	//	<CipherSuites>

	// SERVER
	// u16	CipherSuites

	// u8	CompressionMethodsLength
	//	<CompressionMethods>
	// u16	ExtensionsLength

	size_t l;

	l = 1 + 3 + 2 + 32;
	// SessionIDLength
	if (len < (l + 1)) return false;
	l += data[l] + 1;
	// CipherSuitesLength
	if (len < (l + 2)) return false;
	if (data[0]==0x01) // client hello ?
		l += pntoh16(data + l);
	l+=2;
	// CompressionMethodsLength
	if (len < (l + 1)) return false;
	if (data[0]==0x01) // client hello ?
		l += data[l];
	l++;
	// ExtensionsLength
	if (len < (l + 2)) return false;
	*off = l;
	return true;
}
bool TLSFindExtLen(const uint8_t *data, size_t len, size_t *off)
{
	if (len<5 || !TLSFindExtLenOffsetInHandshake(data+5,len-5,off))
		return false;
	*off+=5;
	return true;
}

// bPartialIsOK=true - accept partial packets not containing the whole TLS message
bool TLSFindExtInHandshake(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK)
{
	// +0
	// u8	HandshakeType: ClientHello
	// u24	Length
	// u16	Version
	// c[32] random
	// u8	SessionIDLength
	//	<SessionID>

	// CLIENT
	// u16	CipherSuitesLength
	//	<CipherSuites>

	// SERVER
	// u16	CipherSuites

	// u8	CompressionMethodsLength
	//	<CompressionMethods>
	// u16	ExtensionsLength

	size_t l;

	if (!bPartialIsOK && !IsTLSHandshakeFull(data,len)) return false;

	if (!TLSFindExtLenOffsetInHandshake(data,len,&l)) return false;

	data += l; len -= l;
	l = pntoh16(data);
	data += 2; len -= 2;
	
	if (bPartialIsOK)
	{
		if (len < l) l = len;
	}
	else
	{
		if (len < l) return false;
	}
	while (l >= 4)
	{
		uint16_t etype = pntoh16(data);
		size_t elen = pntoh16(data + 2);
		data += 4; l -= 4;
		if (l < elen) break;
		if (etype == type)
		{
			if (ext && len_ext)
			{
				*ext = data;
				*len_ext = elen;
			}
			return true;
		}
		data += elen; l -= elen;
	}

	return false;
}
bool TLSFindExt(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK)
{
	// +0
	// u8	ContentType: Handshake
	// u16	Version: TLS1.0
	// u16	Length
	size_t reclen;
	if (!IsTLSHello(data, len, 0, bPartialIsOK)) return false;
	reclen=TLSRecordLen(data);
	if (reclen<len) len=reclen; // correct len if it has more data than the first tls record has
	return TLSFindExtInHandshake(data + 5, len - 5, type, ext, len_ext, bPartialIsOK);
}
bool TLSAdvanceToHostInSNI(const uint8_t **ext, size_t *elen, size_t *slen)
{
	// u16	data+0 - name list length
	// u8	data+2 - server name type. 0=host_name
	// u16	data+3 - server name length
	if (*elen < 5 || (*ext)[2] != 0) return false;
	uint16_t nll = pntoh16(*ext);
	*slen = pntoh16(*ext + 3);
	if (nll<(*slen+3) || nll>(*elen-2)) return false;
	*ext += 5; *elen -= 5;
	return true;
}
static bool TLSExtractHostFromExt(const uint8_t *ext, size_t elen, char *host, size_t len_host)
{
	// u16	data+0 - name list length
	// u8	data+2 - server name type. 0=host_name
	// u16	data+3 - server name length
	size_t slen;
	if (!TLSAdvanceToHostInSNI(&ext,&elen,&slen))
		return false;
	if (host && len_host)
	{
		if (slen >= len_host) slen = len_host - 1;
		for (size_t i = 0; i < slen; i++) host[i] = tolower(ext[i]);
		host[slen] = 0;
	}
	return true;
}
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK)
{
	const uint8_t *ext;
	size_t elen;

	if (!TLSFindExt(data, len, 0, &ext, &elen, bPartialIsOK)) return false;
	return TLSExtractHostFromExt(ext, elen, host, len_host);
}
bool TLSHelloExtractHostFromHandshake(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK)
{
	const uint8_t *ext;
	size_t elen;

	if (!TLSFindExtInHandshake(data, len, 0, &ext, &elen, bPartialIsOK)) return false;
	return TLSExtractHostFromExt(ext, elen, host, len_host);
}

ssize_t TLSPos(t_marker posmarker, int16_t pos, const uint8_t *data, size_t sz)
{
	size_t elen;
	const uint8_t *ext, *p;
	size_t offset,len;

	switch(posmarker)
	{
		case PM_HOST:
		case PM_HOST_END:
		case PM_HOST_SLD:
		case PM_HOST_MIDSLD:
		case PM_HOST_ENDSLD:
		case PM_SNI_EXT:
			if (TLSFindExt(data,sz,0,&ext,&elen,true))
			{
				if (posmarker==PM_SNI_EXT)
				{
					return CheckPos(sz,ext-data+pos);
				}
				else
				{
					if (!TLSAdvanceToHostInSNI(&ext,&elen,&len))
						return POS_NOT_FOUND;
					offset = ext-data;
					return HostPos(posmarker,pos,data,sz,offset,len);
				}
			}
			return POS_NOT_FOUND;
		case PM_EXT_LEN:
			return TLSFindExtLen(data,sz,&offset) ? CheckPos(sz,offset+pos) : POS_NOT_FOUND;
		default:
			return AnyProtoPos(posmarker,pos,data,sz);
	}
}



bool TLSMod_parse_list(const char *modlist, struct fake_tls_mod *tls_mod)
{
	char opt[140], *val;
	const char *p, *e;
	size_t l;

	tls_mod->mod = 0;
	*tls_mod->sni = 0;
	for(p = modlist ; *p ;)
	{
		if (!(e = strchr(p, ',')))
			e = p + strlen(p);

		l = e - p;
		if (l >= sizeof(opt)) l=sizeof(opt)-1;
		memcpy(opt, p, l);
		opt[l] = 0;

		if ((val = strchr(opt, '=')))
			*val++=0;

		if (!strcmp(opt, "rnd"))
			tls_mod->mod |= FAKE_TLS_MOD_RND;
		else if (!strcmp(opt, "rndsni"))
			tls_mod->mod |= FAKE_TLS_MOD_RND_SNI;
		else if (!strcmp(opt, "dupsid"))
			tls_mod->mod |= FAKE_TLS_MOD_DUP_SID;
		else if (!strcmp(opt, "padencap"))
			tls_mod->mod |= FAKE_TLS_MOD_PADENCAP;
		else if (!strcmp(opt, "sni"))
		{
			tls_mod->mod |= FAKE_TLS_MOD_SNI;
			if (!val || !*val) return false;
			strncpy(tls_mod->sni, val, sizeof(tls_mod->sni) - 1);
			tls_mod->sni[sizeof(tls_mod->sni) - 1] = 0;
		}
		else if (strcmp(opt, "none"))
			return false;

		p = e + !!*e;
	}

	return true;
}

// payload is related to received tls client hello
// if options cannot be applied because of the base fake - it's fatal. you should provide valid fake tls with required extensions.
// if options cannot be applied because of the payload - it's non-fatal. some options may not be applied with warning.
bool TLSMod(const struct fake_tls_mod *tls_mod, const uint8_t *payload, size_t payload_len, uint8_t *fake_tls, size_t *fake_tls_size, size_t fake_tls_buf_size)
{
	const uint8_t *ext;
	size_t extlen,slen,extlen_offset=0,padlen_offset=0;

	if (!IsTLSClientHello(fake_tls, *fake_tls_size, false) || (*fake_tls_size < (44 + fake_tls[43]))) // has session id ?
	{
		DLOG_ERR("cannot apply tls mod. tls structure invalid\n");
		return false;
	}
	if (tls_mod->mod & (FAKE_TLS_MOD_RND_SNI | FAKE_TLS_MOD_SNI | FAKE_TLS_MOD_PADENCAP))
	{
		if (!TLSFindExtLen(fake_tls, *fake_tls_size, &extlen_offset))
		{
			DLOG_ERR("cannot apply tls mod. tls structure invalid\n");
			return false;
		}
		DLOG("tls extensions length offset : %zu\n", extlen_offset);
	}
	if (tls_mod->mod & (FAKE_TLS_MOD_RND_SNI | FAKE_TLS_MOD_SNI))
	{
		if (!TLSFindExt(fake_tls, *fake_tls_size, 0, &ext, &extlen, false))
		{
			DLOG_ERR("cannot apply tls mod. sni mod is set but tls does not have SNI\n");
			return false;
		}
		uint8_t *sniext = fake_tls + (ext - fake_tls);
		if (!TLSAdvanceToHostInSNI(&ext, &extlen, &slen))
		{
			DLOG_ERR("cannot apply tls mod. sni set but tls has invalid SNI structure\n");
			return false;
		}
		uint8_t *sni = fake_tls + (ext - fake_tls);
		if (tls_mod->mod & FAKE_TLS_MOD_SNI)
		{
			size_t slen_new = strlen(tls_mod->sni);
			ssize_t slen_delta = slen_new - slen;
			char *s1 = NULL;
			if (params.debug)
				if ((s1 = malloc(slen + 1)))
					{memcpy(s1, sni, slen); s1[slen] = 0;}
			if (slen_delta)
			{
				if ((*fake_tls_size + slen_delta) > fake_tls_buf_size)
				{
					DLOG_ERR("cannot apply sni tls mod. not enough space for new SNI\n");
					free(s1);
					return false;
				}
				memmove(sni + slen_new, sni + slen, fake_tls + *fake_tls_size - (sni + slen));
				phton16(fake_tls + 3, (uint16_t)(pntoh16(fake_tls + 3) + slen_delta));
				phton24(fake_tls + 6, (uint32_t)(pntoh24(fake_tls + 6) + slen_delta));
				phton16(fake_tls + extlen_offset, (uint16_t)(pntoh16(fake_tls + extlen_offset) + slen_delta));
				phton16(sniext - 2, (uint16_t)(pntoh16(sniext - 2) + slen_delta));
				phton16(sniext, (uint16_t)(pntoh16(sniext) + slen_delta));
				phton16(sni - 2, (uint16_t)(pntoh16(sni - 2) + slen_delta));
				*fake_tls_size += slen_delta;
				slen = slen_new;
			}
			DLOG("change SNI : %s => %s size_delta=%zd\n",  s1, tls_mod->sni, slen_delta);
			free(s1);
			memcpy(sni, tls_mod->sni, slen_new);
		}
		if (tls_mod->mod & FAKE_TLS_MOD_RND_SNI)
		{
			if (!slen)
			{
				DLOG_ERR("cannot apply rndsni tls mod. tls has zero sized SNI\n");
				return false;
			}
			else
			{
				char *s1 = NULL, *s2 = NULL;
				if (params.debug && (s1 = malloc(slen + 1)))
				{
					memcpy(s1, sni, slen);
					s1[slen] = 0;
				}

				fill_random_az(sni, 1);
				if (slen >= 7) // domain name in SNI must be at least 3 chars long to enable xxx.tls randomization
				{
					fill_random_az09(sni + 1, slen - 5);
					sni[slen - 4] = '.';
					memcpy(sni + slen - 3, tld[random() % (sizeof(tld) / sizeof(*tld))], 3);
				}
				else
					fill_random_az09(sni + 1, slen - 1);

				if (params.debug)
				{
					if (s1 && (s2 = malloc(slen + 1)))
					{
						memcpy(s2, sni, slen); s2[slen] = 0;
						DLOG("generated random SNI : %s -> %s\n",s1,s2);
					}
					free(s1); free(s2);
				}
			}
		}
	}
	if (tls_mod->mod & FAKE_TLS_MOD_RND)
	{
		fill_random_bytes(fake_tls + 11, 32); // random
		fill_random_bytes(fake_tls + 44, fake_tls[43]); // session id
		DLOG("applied rnd tls mod\n");
	}
	if (payload)
	{
		if (tls_mod->mod & FAKE_TLS_MOD_DUP_SID)
		{
			if (IsTLSClientHelloPartial(payload, payload_len))
			{
				if (payload_len < 44)
					DLOG("(nonfatal) cannot apply dupsid tls mod. data payload is too short.\n");
				else if (fake_tls[43] != payload[43])
					DLOG("(nonfatal) cannot apply dupsid tls mod. fake and orig session id length mismatch : %u!=%u.\n", fake_tls[43], payload[43]);
				else if (payload_len < (44 + payload[43]))
					DLOG("(nonfatal) cannot apply dupsid tls mod. data payload is not valid.\n");
				else
				{
					memcpy(fake_tls + 44, payload + 44, fake_tls[43]); // session id
					DLOG("applied dupsid tls mod\n");
				}
			}
			else
			{
				DLOG_ERR("(nonfatal) cannot apply dupsid tls mod. payload is not valid tls.\n");
			}
		}
		if (tls_mod->mod & FAKE_TLS_MOD_PADENCAP)
		{
			if (TLSFindExt(fake_tls, *fake_tls_size, 21, &ext, &extlen, false))
			{
				if ((ext - fake_tls + extlen) != *fake_tls_size)
				{
					DLOG_ERR("cannot apply padencap tls mod. tls padding ext is present but it's not at the end. padding ext offset %zu, padding ext size %zu, fake size %zu\n", ext - fake_tls, extlen, *fake_tls_size);
					return false;
				}
				padlen_offset = ext - fake_tls - 2;
				DLOG("tls padding ext is present, padding length offset %zu\n", padlen_offset);
			}
			else
			{
				if ((*fake_tls_size + 4) > fake_tls_buf_size)
				{
					DLOG_ERR("tls padding is absent and there's no space to add it\n");
					return false;
				}
				phton16(fake_tls + *fake_tls_size, 21);
				*fake_tls_size += 2;
				padlen_offset = *fake_tls_size;
				phton16(fake_tls + *fake_tls_size, 0);
				*fake_tls_size += 2;
				phton16(fake_tls + extlen_offset, pntoh16(fake_tls + extlen_offset) + 4);
				phton16(fake_tls + 3, pntoh16(fake_tls + 3) + 4); // increase tls record len
				phton24(fake_tls + 6, pntoh24(fake_tls + 6) + 4); // increase tls handshake len
				DLOG("tls padding is absent. added. padding length offset %zu\n", padlen_offset);
			}
			size_t sz_rec = pntoh16(fake_tls + 3) + payload_len;
			size_t sz_handshake = pntoh24(fake_tls + 6) + payload_len;
			size_t sz_ext = pntoh16(fake_tls + extlen_offset) + payload_len;
			size_t sz_pad = pntoh16(fake_tls + padlen_offset) + payload_len;
			if ((sz_rec & ~0xFFFF) || (sz_handshake & ~0xFFFFFF) || (sz_ext & ~0xFFFF) || (sz_pad & ~0xFFFF))
			{
				DLOG("(nonfatal) cannot apply padencap tls mod. length overflow.\n");
			}
			else
			{
				phton16(fake_tls + 3, (uint16_t)sz_rec);
				phton24(fake_tls + 6, (uint32_t)sz_handshake);
				phton16(fake_tls + extlen_offset, (uint16_t)sz_ext);
				phton16(fake_tls + padlen_offset, (uint16_t)sz_pad);
				DLOG("applied padencap tls mod. sizes increased by %zu bytes.\n", payload_len);
			}
		}
	}
	
	return true;
}






static uint8_t tvb_get_varint(const uint8_t *tvb, uint64_t *value)
{
	switch (*tvb >> 6)
	{
	case 0: /* 0b00 => 1 byte length (6 bits Usable) */
		if (value) *value = *tvb & 0x3F;
		return 1;
	case 1: /* 0b01 => 2 bytes length (14 bits Usable) */
		if (value) *value = pntoh16(tvb) & 0x3FFF;
		return 2;
	case 2: /* 0b10 => 4 bytes length (30 bits Usable) */
		if (value) *value = pntoh32(tvb) & 0x3FFFFFFF;
		return 4;
	case 3: /* 0b11 => 8 bytes length (62 bits Usable) */
		if (value) *value = pntoh64(tvb) & 0x3FFFFFFFFFFFFFFF;
		return 8;
	}
	// impossible case
	if (value) *value = 0;
	return 0;
}
static uint8_t tvb_get_size(uint8_t tvb)
{
	return 1 << (tvb >> 6);
}

bool IsQUICCryptoHello(const uint8_t *data, size_t len, size_t *hello_offset, size_t *hello_len)
{
	size_t offset = 1;
	uint64_t coff, clen;
	if (len < 3 || *data != 6) return false;
	if ((offset+tvb_get_size(data[offset])) >= len) return false;
	offset += tvb_get_varint(data + offset, &coff);
	// offset must be 0 if it's a full segment, not just a chunk
	if (coff || (offset+tvb_get_size(data[offset])) >= len) return false;
	offset += tvb_get_varint(data + offset, &clen);
	if ((offset + clen) > len || !IsTLSHandshakeClientHello(data+offset,clen,true)) return false;
	if (hello_offset) *hello_offset = offset;
	if (hello_len) *hello_len = (size_t)clen;
	return true;
}

static bool is_quic_v2(uint32_t version)
{
    return (version == 0x709A50C4) || (version == 0x6b3343cf);
}
/* Returns the QUIC draft version or 0 if not applicable. */
uint8_t QUICDraftVersion(uint32_t version)
{
	/* IETF Draft versions */
	if ((version >> 8) == 0xff0000)
		return (uint8_t)version;
	/* Facebook mvfst, based on draft -22. */
	if (version == 0xfaceb001)
		return 22;
	/* Facebook mvfst, based on draft -27. */
	if (version == 0xfaceb002 || version == 0xfaceb00e)
		return 27;
	/* GQUIC Q050, T050 and T051: they are not really based on any drafts,
	 * but we must return a sensible value */
	if (version == 0x51303530 || version == 0x54303530 || version == 0x54303531)
		return 27;
	/* https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15
	   "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
	   forcing version negotiation to be exercised"
	   It is tricky to return a correct draft version: such number is primarily
	   used to select a proper salt (which depends on the version itself), but
	   we don't have a real version here! Let's hope that we need to handle
	   only latest drafts... */
	if ((version & 0x0F0F0F0F) == 0x0a0a0a0a)
		return 29;
	/* QUIC (final?) constants for v1 are defined in draft-33, but draft-34 is the
	   final draft version */
	if (version == 0x00000001)
		return 34;
	/* QUIC Version 2 */
	/* TODO: for the time being use 100 as a number for V2 and let see how v2 drafts evolve */
	if (is_quic_v2(version))
		return 100;

	return 0;
}

static bool is_quic_draft_max(uint32_t draft_version, uint8_t max_version)
{
	return draft_version && draft_version <= max_version;
}

static bool quic_hkdf_expand_label(const uint8_t *secret, uint8_t secret_len, const char *label, uint8_t *out, size_t out_len)
{
	uint8_t hkdflabel[64];

	size_t label_size = strlen(label);
	if (label_size > 255) return false;
	size_t hkdflabel_size = 2 + 1 + label_size + 1;
	if (hkdflabel_size > sizeof(hkdflabel)) return false;

	phton16(hkdflabel, out_len);
	hkdflabel[2] = (uint8_t)label_size;
	memcpy(hkdflabel + 3, label, label_size);
	hkdflabel[3 + label_size] = 0;
	return !hkdfExpand(SHA256, secret, secret_len, hkdflabel, hkdflabel_size, out, out_len);
}

static bool quic_derive_initial_secret(const quic_cid_t *cid, uint8_t *client_initial_secret, uint32_t version)
{
	/*
	 * https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
	 *
	 * initial_salt = 0xafbfec289993d24c9e9786f19c6111e04390a899
	 * initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
	 *
	 * client_initial_secret = HKDF-Expand-Label(initial_secret,
	 *                                           "client in", "", Hash.length)
	 * server_initial_secret = HKDF-Expand-Label(initial_secret,
	 *                                           "server in", "", Hash.length)
	 *
	 * Hash for handshake packets is SHA-256 (output size 32).
	 */
	static const uint8_t handshake_salt_draft_22[20] = {
		0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
		0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a
	};
	static const uint8_t handshake_salt_draft_23[20] = {
		0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
		0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
	};
	static const uint8_t handshake_salt_draft_29[20] = {
		0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
		0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
	};
	static const uint8_t handshake_salt_v1[20] = {
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
	};
	static const uint8_t hanshake_salt_draft_q50[20] = {
		0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
		0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45
	};
	static const uint8_t hanshake_salt_draft_t50[20] = {
		0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80,
		0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10
	};
	static const uint8_t hanshake_salt_draft_t51[20] = {
		0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50,
		0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d
	};
	static const uint8_t handshake_salt_v2[20] = {
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
	};

	int err;
	const uint8_t *salt;
	uint8_t secret[USHAMaxHashSize];
	uint8_t draft_version = QUICDraftVersion(version);

	if (version == 0x51303530) {
		salt = hanshake_salt_draft_q50;
	}
	else if (version == 0x54303530) {
		salt = hanshake_salt_draft_t50;
	}
	else if (version == 0x54303531) {
		salt = hanshake_salt_draft_t51;
	}
	else if (is_quic_draft_max(draft_version, 22)) {
		salt = handshake_salt_draft_22;
	}
	else if (is_quic_draft_max(draft_version, 28)) {
		salt = handshake_salt_draft_23;
	}
	else if (is_quic_draft_max(draft_version, 32)) {
		salt = handshake_salt_draft_29;
	}
	else if (is_quic_draft_max(draft_version, 34)) {
		salt = handshake_salt_v1;
	}
	else {
		salt = handshake_salt_v2;
	}

	err = hkdfExtract(SHA256, salt, 20, cid->cid, cid->len, secret);
	if (err) return false;

	if (client_initial_secret && !quic_hkdf_expand_label(secret, SHA256HashSize, "tls13 client in", client_initial_secret, SHA256HashSize))
		return false;

	return true;
}
bool QUICIsLongHeader(const uint8_t *data, size_t len)
{
	return len>=9 && (*data & 0x80);
}
uint32_t QUICExtractVersion(const uint8_t *data, size_t len)
{
	// long header, fixed bit, type=initial
	return QUICIsLongHeader(data, len) ? pntoh32(data + 1) : 0;
}
bool QUICExtractDCID(const uint8_t *data, size_t len, quic_cid_t *cid)
{
	if (!QUICIsLongHeader(data,len) || !data[5] || data[5] > QUIC_MAX_CID_LENGTH || (6+data[5])>len) return false;
	cid->len = data[5];
	memcpy(&cid->cid, data + 6, data[5]);
	return true;
}
bool QUICDecryptInitial(const uint8_t *data, size_t data_len, uint8_t *clean, size_t *clean_len)
{
	uint32_t ver = QUICExtractVersion(data, data_len);
	if (!ver) return false;

	quic_cid_t dcid;
	if (!QUICExtractDCID(data, data_len, &dcid)) return false;

	uint8_t client_initial_secret[SHA256HashSize];
	if (!quic_derive_initial_secret(&dcid, client_initial_secret, ver)) return false;

	uint8_t aeskey[16], aesiv[12], aeshp[16];
	bool v1_label = !is_quic_v2(ver);
	if (!quic_hkdf_expand_label(client_initial_secret, SHA256HashSize, v1_label ? "tls13 quic key" : "tls13 quicv2 key", aeskey, sizeof(aeskey)) ||
		!quic_hkdf_expand_label(client_initial_secret, SHA256HashSize, v1_label ? "tls13 quic iv" : "tls13 quicv2 iv", aesiv, sizeof(aesiv)) ||
		!quic_hkdf_expand_label(client_initial_secret, SHA256HashSize, v1_label ? "tls13 quic hp" : "tls13 quicv2 hp", aeshp, sizeof(aeshp)))
	{
		return false;
	}

	uint64_t payload_len,token_len,pn_offset;
	pn_offset = 1 + 4 + 1 + data[5];
	if (pn_offset >= data_len) return false;
	// SCID length
	pn_offset += 1 + data[pn_offset];
	if (pn_offset >= data_len || (pn_offset + tvb_get_size(data[pn_offset])) >= data_len) return false;
	// token length
	pn_offset += tvb_get_varint(data + pn_offset, &token_len);
	pn_offset += token_len;
	if (pn_offset >= data_len || (pn_offset + tvb_get_size(data[pn_offset])) >= data_len) return false;
	pn_offset += tvb_get_varint(data + pn_offset, &payload_len);
	if (payload_len<20 || (pn_offset + payload_len)>data_len) return false;

	uint8_t sample_enc[16];
	aes_context ctx;
	if (aes_setkey(&ctx, 1, aeshp, sizeof(aeshp)) || aes_cipher(&ctx, data + pn_offset + 4, sample_enc)) return false;

	uint8_t mask[5];
	memcpy(mask, sample_enc, sizeof(mask));

	uint8_t packet0 = data[0] ^ (mask[0] & 0x0f);
	uint8_t pkn_len = (packet0 & 0x03) + 1;

	uint8_t pkn_bytes[4];
	memcpy(pkn_bytes, data + pn_offset, pkn_len);
	uint32_t pkn = 0;
	for (uint8_t i = 0; i < pkn_len; i++) pkn |= (uint32_t)(pkn_bytes[i] ^ mask[1 + i]) << (8 * (pkn_len - 1 - i));

 	phton64(aesiv + sizeof(aesiv) - 8, pntoh64(aesiv + sizeof(aesiv) - 8) ^ pkn);

	uint64_t cryptlen = payload_len - pkn_len - 16;
	if (cryptlen > *clean_len) return false;
	*clean_len = (size_t)cryptlen;
	const uint8_t *decrypt_begin = data + pn_offset + pkn_len;

	uint8_t atag[16],header[2048];
	uint64_t header_len = pn_offset + pkn_len;
	if (header_len > sizeof(header)) return false; // not likely header will be so large
	memcpy(header, data, header_len);
	header[0] = packet0;
	for(uint8_t i = 0; i < pkn_len; i++) header[header_len - 1 - i] = (uint8_t)(pkn >> (8 * i));

	if (aes_gcm_crypt(AES_DECRYPT, clean, decrypt_begin, cryptlen, aeskey, sizeof(aeskey), aesiv, sizeof(aesiv), header, header_len, atag, sizeof(atag)))
		return false;

	// check if message was decrypted correctly : good keys , no data corruption
	return !memcmp(data + pn_offset + pkn_len + cryptlen, atag, 16);
}

struct range64
{
	uint64_t offset,len;
};
#define MAX_DEFRAG_PIECES	128
static int cmp_range64(const void * a, const void * b)
{
	return (((struct range64*)a)->offset < ((struct range64*)b)->offset) ? -1 : (((struct range64*)a)->offset > ((struct range64*)b)->offset) ? 1 : 0;
}
/*
static bool intersected_u64(uint64_t l1, uint64_t r1, uint64_t l2, uint64_t r2)
{
	return l1 <= r2 && l2 <= r1;
}
*/

bool QUICDefragCrypto(const uint8_t *clean,size_t clean_len, uint8_t *defrag,size_t *defrag_len, bool *bFull)
{
	// Crypto frame can be split into multiple chunks
	// chromium randomly splits it and pads with zero/one bytes to force support the standard
	// mozilla does not split

	if (*defrag_len<10) return false;
	uint8_t *defrag_data = defrag+10;
	size_t defrag_data_len = *defrag_len-10;
	uint8_t ft;
	uint64_t offset,sz,szmax=0,zeropos=0,pos=0;
	bool found=false;
	struct range64 ranges[MAX_DEFRAG_PIECES];
	int i,j,range=0;

	while(pos<clean_len)
	{
		// frame type
		ft = clean[pos];
		pos++;
		if (ft>1) // 00 - padding, 01 - ping
		{
			if (ft!=6) return false; // dont want to know all possible frame type formats

			if (pos>=clean_len) return false;
			if (range>=MAX_DEFRAG_PIECES) return false;

			if ((pos+tvb_get_size(clean[pos])>=clean_len)) return false;
			pos += tvb_get_varint(clean+pos, &offset);

			if ((pos+tvb_get_size(clean[pos])>clean_len)) return false;
			pos += tvb_get_varint(clean+pos, &sz);
			if ((pos+sz)>clean_len) return false;

			if ((offset+sz)>defrag_data_len) return false; // defrag buf overflow

			// remove exact duplicates early to save cpu
			for(i=0;i<range;i++)
				if (ranges[i].offset==offset && ranges[i].len==sz)
					goto skip_range;

			if (zeropos < offset)
				// make sure no uninitialized gaps exist in case of not full fragment coverage
				memset(defrag_data+zeropos,0,offset-zeropos);
			if ((offset+sz) > zeropos)
				zeropos=offset+sz;

			found=true;
			if ((offset+sz) > szmax) szmax = offset+sz;
			memcpy(defrag_data+offset,clean+pos,sz);
			ranges[range].offset = offset;
			ranges[range].len = sz;
			range++;
skip_range:
			pos+=sz;
		}
	}
	if (found)
	{
		qsort(ranges, range, sizeof(*ranges), cmp_range64);

//		for(i=0 ; i<range ; i++)
//			printf("range1 %llu-%llu\n",ranges[i].offset,ranges[i].offset+ranges[i].len);

		if (range>0)
		{
			for (j=0,i=1; i < range; i++)
			{
				uint64_t current_end = ranges[j].offset + ranges[j].len;
				uint64_t next_start = ranges[i].offset;
				uint64_t next_end = ranges[i].offset + ranges[i].len;

				if (next_start <= current_end)
					ranges[j].len = MAX(next_end,current_end) - ranges[j].offset;
				else
					ranges[++j] = ranges[i];
			}
			range = j+1;
		}

//		for(i=0 ; i<range ; i++)
//			printf("range2 %llu-%llu\n",ranges[i].offset,ranges[i].offset+ranges[i].len);

		defrag[0] = 6;
		defrag[1] = 0; // offset
		// 2..9 - length 64 bit
		// +10 - data start
		phton64(defrag+2,szmax);
		defrag[2] |= 0xC0; // 64 bit value
		*defrag_len = (size_t)(szmax+10);

		*bFull = range==1 && !ranges[0].offset;
		//printf("bFull=%u\n",*bFull);
	}
	return found;
}

bool IsQUICInitial(const uint8_t *data, size_t len)
{
	// too small packets are not likely to be initials
	// long header, fixed bit
	if (len < 128) return false;

	uint32_t ver = QUICExtractVersion(data,len);
	if (QUICDraftVersion(ver) < 11) return false;

	if ((data[0] & 0xF0) != (is_quic_v2(ver) ? 0xD0 : 0xC0)) return false;

	uint64_t offset=5, sz, sz2;

	// DCID
	if (data[offset] > QUIC_MAX_CID_LENGTH) return false;
	offset += 1 + data[offset];

	if (offset>=len) return false;

	// SCID
	if (data[offset] > QUIC_MAX_CID_LENGTH) return false;
	offset += 1 + data[offset];

	// token length
	if (offset>=len || (offset + tvb_get_size(data[offset])) > len) return false;
	offset += tvb_get_varint(data + offset, &sz);
	offset += sz;
	if (offset >= len) return false;

	// payload length
	sz2 = tvb_get_size(data[offset]);
	if ((offset + sz2) > len) return false;
	tvb_get_varint(data + offset, &sz);
	offset += sz2 + sz;
	if (offset > len) return false;

	return true;
}



bool IsXMPPStream(const uint8_t *data, size_t len)
{
	return len>=16 && !memcmp(data,"<stream:stream ",15) || len>=36 && !memcmp(data,"<?xml ",6) && memmem(data+21,len-21,"<stream:stream ",15);
}
bool IsXMPPStartTLS(const uint8_t *data, size_t len)
{
	return len>=10 && !memcmp(data,"<starttls ",10);
}
bool IsXMPPProceedTLS(const uint8_t *data, size_t len)
{
	return len>=9 && !memcmp(data,"<proceed ",9);
}
bool IsXMPPFeatures(const uint8_t *data, size_t len)
{
	return len>=17 && !memcmp(data,"<stream:features",16);
}


bool IsDNSQuery(const uint8_t *data, size_t len)
{
	// message is a query, type standard query, questions: 1, answers: 0, authority: 0, additional <= 3 (for OPT or something else)
	// RFC 1035  512 byte limit can be ignored by clients or servers
	return len>=12 && !(data[2] & 0xFE) && !memcmp(data+4,"\x00\x01\x00\x00\x00\x00",6) && pntoh16(data+10)<=3;
}
bool IsDNSResponse(const uint8_t *data, size_t len)
{
	// message is a response, type standard response, questions: 1, answers <= 100, authority <= 100, additional <= 100
	// RFC 1035  512 byte limit can be ignored by clients or servers
	return len>=12 && (data[2] & 0xF8)==0x80 && pntoh16(data+4)==1 && pntoh16(data+6)<=100 && pntoh16(data+8)<=100 && pntoh16(data+10)<=100;
}
bool IsWireguardHandshakeInitiation(const uint8_t *data, size_t len)
{
	return len==148 && pntoh32(data)==0x01000000;
}
bool IsWireguardHandshakeResponse(const uint8_t *data, size_t len)
{
	return len==92 && pntoh32(data)==0x02000000;
}
bool IsWireguardHandshakeCookie(const uint8_t *data, size_t len)
{
	return len==64 && pntoh32(data)==0x03000000;
}
bool IsWireguardData(const uint8_t *data, size_t len)
{
	// 16 bytes wg header + min 20 bytes for ipv4 encrypted header + 16 byte auth tag
	return len>=52 && pntoh32(data)==0x04000000;
}
bool IsWireguardKeepalive(const uint8_t *data, size_t len)
{
	return len==32 && pntoh32(data)==0x04000000;
}
bool IsDht(const uint8_t *data, size_t len)
{
	return len>=5 && data[0]=='d' && data[2]==':' && data[len-1]=='e' &&
		(data[1]=='1' && data[3]=='a' && data[4]=='d' ||
		data[1]=='1' && data[3]=='r' && data[4]=='d' ||
		data[1]=='2' && data[3]=='i' && data[4]=='p' ||
		data[1]=='1' && data[3]=='e' && data[4]=='l');
}
bool IsDiscordIpDiscoveryRequest(const uint8_t *data, size_t len)
{
	return len==74 &&
		data[0]==0 && data[1]==1 &&
		data[2]==0 && data[3]==70 &&
		!memcmp(data+8,"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",64);
		// address is not set in request
}
bool IsStunMessage(const uint8_t *data, size_t len)
{
	return len>=20 && // header size
		(data[0]&0xC0)==0 && // 2 most significant bits must be zeroes
		(data[3]&3)==0 && // length must be a multiple of 4
		pntoh32(data+4)==0x2112A442 && // magic cookie
		pntoh16(data+2)<=(len-20);
}
#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
bool IsMTProto(const uint8_t *data, size_t len)
{
	if (len>=64)
	{
/*
		uint8_t decrypt[64] __attribute__((aligned));
		aes_ctr_crypt(data+8, 32, data+40, data, 64, decrypt);
		return !memcmp(decrypt+56,"\xEF\xEF\xEF\xEF",4);
*/
		// this way requires only one AES instead of 4
		uint8_t decrypt[16] __attribute__((aligned(16))), iv[16] __attribute__((aligned(16)));
		aes_context ctx;

		memcpy(iv, data+40, 16);
		ctr_add(iv,3);
		if (!aes_setkey(&ctx, AES_ENCRYPT, data+8, 32) && !aes_cipher(&ctx, iv, decrypt))
		{
			*((uint32_t*)(decrypt+8)) ^= *((uint32_t*)(data+56));
			return !memcmp(decrypt+8,"\xEF\xEF\xEF\xEF",4);
		}
	}
	return false;
}

bool IsDTLS(const uint8_t *data, size_t len)
{
	return ((len > 13) &&
		(data[0]>=0x14 && data[0]<=0x17) && /* Handshake, change-cipher-spec, Application-Data, Alert */
		((data[1] == 0xfe && data[2] == 0xff) || /* Versions */
		(data[1] == 0xfe && data[2] == 0xfd) ||
		(data[1] == 0xfe && data[2] == 0xfc) ||
		(data[1] == 0x01 && data[2] == 0x00)) &&
		(pntoh16(data+11)+13)<=len);
}
bool IsDTLSClientHello(const uint8_t *data, size_t len)
{
	return IsDTLS(data,len) && data[0]==0x16 && data[13]==1;
}
bool IsDTLSServerHello(const uint8_t *data, size_t len)
{
	return IsDTLS(data,len) && data[0]==0x16 && data[13]==2;
}

bool IsBTHandshake(const uint8_t *data, size_t len)
{
	// len, pstrlen, reserved, sha1, peer id
	return len>=(1+19+8+20+20) && !memcmp(data,"\x13" "BitTorrent protocol",20);
}
bool IsUTP_BTHandshake(const uint8_t *data, size_t len)
{
	// len, pstrlen, reserved, sha1, peer id
	return len>=(20+1+19+8+20+20) && data[0]==0x01 && !memcmp(data+20,"\x13" "BitTorrent protocol",20);;
}
