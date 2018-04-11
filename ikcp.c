//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#include "ikcp.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>



//=====================================================================
// KCP BASIC
//=====================================================================
const IUINT32 IKCP_RTO_NDL = 30;		// no delay min rto 无延时模式下最小超时重传时间
const IUINT32 IKCP_RTO_MIN = 100;		// normal min rto 正常模式最小超时重传
const IUINT32 IKCP_RTO_DEF = 200;       // default rto 默认超时重传
const IUINT32 IKCP_RTO_MAX = 60000;     // max rto 最大超时超时

const IUINT32 IKCP_CMD_PUSH = 81;		// cmd: push data 协议类型 [正常接收数据]
const IUINT32 IKCP_CMD_ACK  = 82;		// cmd: ack 协议类型 [收到ack回复] ack
const IUINT32 IKCP_CMD_WASK = 83;		// cmd: window probe (ask)请求告知窗口大小
const IUINT32 IKCP_CMD_WINS = 84;		// cmd: window size (tell)告知窗口大小

const IUINT32 IKCP_ASK_SEND = 1;		// need to send IKCP_CMD_WASK     是否需要发送 IKCP_CMD_WASK
const IUINT32 IKCP_ASK_TELL = 2;		// need to send IKCP_CMD_WINS     是否需要发送 IKCP_CMD_WINS

const IUINT32 IKCP_WND_SND = 32;                                        //发送队列滑动窗口最大值
const IUINT32 IKCP_WND_RCV = 128;       // must >= max fragment size    //接收队列滑动窗口最大值

const IUINT32 IKCP_MTU_DEF = 1400;      // segment: 报文默认大小 [mtu 网络最小传输单元]
const IUINT32 IKCP_ACK_FAST	= 3;        // null: 没有被用使用
const IUINT32 IKCP_INTERVAL	= 100;      // flush: 控制刷新时间间隔
const IUINT32 IKCP_OVERHEAD = 24;       // segment: 报文默认大小 [mtu 网络最小传输单元]
const IUINT32 IKCP_DEADLINK = 20;

const IUINT32 IKCP_THRESH_INIT = 2;     // ssthresh: 慢热启动 初始窗口大小
const IUINT32 IKCP_THRESH_MIN = 2;      // ssthresh: 慢热启动 最小窗口大小

const IUINT32 IKCP_PROBE_INIT = 7000;		// probe: 请求询问远端窗口大小的初始时间  7 secs to probe window size
const IUINT32 IKCP_PROBE_LIMIT = 120000;	// probe: 请求询问远端窗口大小的最大时间  up to 120 secs to probe window


//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------

/* encode 8 bits unsigned int */
static inline char *ikcp_encode8u(char *p, unsigned char c)
{
	*(unsigned char*)p++ = c;
	return p;
}

/* decode 8 bits unsigned int */
static inline const char *ikcp_decode8u(const char *p, unsigned char *c)
{
	*c = *(unsigned char*)p++;
	return p;
}

/* encode 16 bits unsigned int (lsb) */
static inline char *ikcp_encode16u(char *p, unsigned short w)
{
#if IWORDS_BIG_ENDIAN
	*(unsigned char*)(p + 0) = (w & 255);
	*(unsigned char*)(p + 1) = (w >> 8);
#else
	*(unsigned short*)(p) = w;
#endif
	p += 2;
	return p;
}

/* decode 16 bits unsigned int (lsb) */
static inline const char *ikcp_decode16u(const char *p, unsigned short *w)
{
#if IWORDS_BIG_ENDIAN
	*w = *(const unsigned char*)(p + 1);
	*w = *(const unsigned char*)(p + 0) + (*w << 8);
#else
	*w = *(const unsigned short*)p;
#endif
	p += 2;
	return p;
}

/* encode 32 bits unsigned int (lsb) */
static inline char *ikcp_encode32u(char *p, IUINT32 l)
{
#if IWORDS_BIG_ENDIAN
	*(unsigned char*)(p + 0) = (unsigned char)((l >>  0) & 0xff);
	*(unsigned char*)(p + 1) = (unsigned char)((l >>  8) & 0xff);
	*(unsigned char*)(p + 2) = (unsigned char)((l >> 16) & 0xff);
	*(unsigned char*)(p + 3) = (unsigned char)((l >> 24) & 0xff);
#else
	*(IUINT32*)p = l;
#endif
	p += 4;
	return p;
}

/* decode 32 bits unsigned int (lsb) */
static inline const char *ikcp_decode32u(const char *p, IUINT32 *l)
{
#if IWORDS_BIG_ENDIAN
	*l = *(const unsigned char*)(p + 3);
	*l = *(const unsigned char*)(p + 2) + (*l << 8);
	*l = *(const unsigned char*)(p + 1) + (*l << 8);
	*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else 
	*l = *(const IUINT32*)p;
#endif
	p += 4;
	return p;
}

static inline IUINT32 _imin_(IUINT32 a, IUINT32 b) {
	return a <= b ? a : b;
}

static inline IUINT32 _imax_(IUINT32 a, IUINT32 b) {
	return a >= b ? a : b;
}

static inline IUINT32 _ibound_(IUINT32 lower, IUINT32 middle, IUINT32 upper) 
{
	return _imin_(_imax_(lower, middle), upper);
}

static inline long _itimediff(IUINT32 later, IUINT32 earlier) 
{
	return ((IINT32)(later - earlier));
}

//---------------------------------------------------------------------
// manage segment
//---------------------------------------------------------------------
typedef struct IKCPSEG IKCPSEG;

static void* (*ikcp_malloc_hook)(size_t) = NULL;
static void (*ikcp_free_hook)(void *) = NULL;

// internal malloc
static void* ikcp_malloc(size_t size) {
	if (ikcp_malloc_hook) 
		return ikcp_malloc_hook(size);
	return malloc(size);
}

// internal free
static void ikcp_free(void *ptr) {
	if (ikcp_free_hook) {
		ikcp_free_hook(ptr);
	}	else {
		free(ptr);
	}
}

// redefine allocator
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*))
{
	ikcp_malloc_hook = new_malloc;
	ikcp_free_hook = new_free;
}

// allocate a new kcp segment
static IKCPSEG* ikcp_segment_new(ikcpcb *kcp, int size)
{
	return (IKCPSEG*)ikcp_malloc(sizeof(IKCPSEG) + size);
}

// delete a segment
static void ikcp_segment_delete(ikcpcb *kcp, IKCPSEG *seg)
{
	ikcp_free(seg);
}

// write log
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...)
{
	char buffer[1024];
	va_list argptr;
	if ((mask & kcp->logmask) == 0 || kcp->writelog == 0) return;
	va_start(argptr, fmt);
	vsprintf(buffer, fmt, argptr);
	va_end(argptr);
	kcp->writelog(buffer, kcp, kcp->user);
}

// check log mask
static int ikcp_canlog(const ikcpcb *kcp, int mask)
{
	if ((mask & kcp->logmask) == 0 || kcp->writelog == NULL) return 0;
	return 1;
}

// output segment
static int ikcp_output(ikcpcb *kcp, const void *data, int size)
{
	assert(kcp);
	assert(kcp->output);
	if (ikcp_canlog(kcp, IKCP_LOG_OUTPUT)) {
		ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size);
	}
	if (size == 0) return 0;
	return kcp->output((const char*)data, size, kcp, kcp->user);
}

// output queue
void ikcp_qprint(const char *name, const struct IQUEUEHEAD *head)
{
#if 0
	const struct IQUEUEHEAD *p;
	printf("<%s>: [", name);
	for (p = head->next; p != head; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		printf("(%lu %d)", (unsigned long)seg->sn, (int)(seg->ts % 10000));
		if (p->next != head) printf(",");
	}
	printf("]\n");
#endif
}


//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
ikcpcb* ikcp_create(IUINT32 conv, void *user)
{
	ikcpcb *kcp = (ikcpcb*)ikcp_malloc(sizeof(struct IKCPCB));
	if (kcp == NULL) return NULL;
	kcp->conv = conv;
	kcp->user = user;
	kcp->snd_una = 0;
	kcp->snd_nxt = 0;
	kcp->rcv_nxt = 0;
	kcp->ts_recent = 0;
	kcp->ts_lastack = 0;
	kcp->ts_probe = 0;
	kcp->probe_wait = 0;
	kcp->snd_wnd = IKCP_WND_SND;
	kcp->rcv_wnd = IKCP_WND_RCV;
	kcp->rmt_wnd = IKCP_WND_RCV;
	kcp->cwnd = 0;
	kcp->incr = 0;
	kcp->probe = 0;
	kcp->mtu = IKCP_MTU_DEF;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	kcp->stream = 0;

	kcp->buffer = (char*)ikcp_malloc((kcp->mtu + IKCP_OVERHEAD) * 3);
	if (kcp->buffer == NULL) {
		ikcp_free(kcp);
		return NULL;
	}

	iqueue_init(&kcp->snd_queue);
	iqueue_init(&kcp->rcv_queue);
	iqueue_init(&kcp->snd_buf);
	iqueue_init(&kcp->rcv_buf);
	kcp->nrcv_buf = 0;
	kcp->nsnd_buf = 0;
	kcp->nrcv_que = 0;
	kcp->nsnd_que = 0;
	kcp->state = 0;
	kcp->acklist = NULL;
	kcp->ackblock = 0;
	kcp->ackcount = 0;
	kcp->rx_srtt = 0;
	kcp->rx_rttval = 0;
	kcp->rx_rto = IKCP_RTO_DEF;
	kcp->rx_minrto = IKCP_RTO_MIN;
	kcp->current = 0;
	kcp->interval = IKCP_INTERVAL;
	kcp->ts_flush = IKCP_INTERVAL;
	kcp->nodelay = 0;
	kcp->updated = 0;
	kcp->logmask = 0;
	kcp->ssthresh = IKCP_THRESH_INIT;
	kcp->fastresend = 0;
	kcp->nocwnd = 0;
	kcp->xmit = 0;
	kcp->dead_link = IKCP_DEADLINK;
	kcp->output = NULL;
	kcp->writelog = NULL;

	return kcp;
}


//---------------------------------------------------------------------
// release a new kcpcb
//---------------------------------------------------------------------
void ikcp_release(ikcpcb *kcp)
{
	assert(kcp);
	if (kcp) {
		IKCPSEG *seg;
		while (!iqueue_is_empty(&kcp->snd_buf)) {
			seg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_buf)) {
			seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->snd_queue)) {
			seg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_queue)) {
			seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		if (kcp->buffer) {
			ikcp_free(kcp->buffer);
		}
		if (kcp->acklist) {
			ikcp_free(kcp->acklist);
		}

		kcp->nrcv_buf = 0;
		kcp->nsnd_buf = 0;
		kcp->nrcv_que = 0;
		kcp->nsnd_que = 0;
		kcp->ackcount = 0;
		kcp->buffer = NULL;
		kcp->acklist = NULL;
		ikcp_free(kcp);
	}
}


//---------------------------------------------------------------------
// set output callback, which will be invoked by kcp
//---------------------------------------------------------------------
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len,
	ikcpcb *kcp, void *user))
{
	kcp->output = output;
}


//---------------------------------------------------------------------
// user/upper level recv: returns size, returns below zero for EAGAIN
//---------------------------------------------------------------------
// 对应于 ikcp_send 的应用层接收函数为 ikcp_recv
// ikcp_recv 仅为上层调用的接口, KCP 协议需要从底层接受数据到 rcv_buf 中，这是通过函数 ikcp_input 实现
int ikcp_recv(ikcpcb *kcp, char *buffer, int len)
{
	struct IQUEUEHEAD *p;
	int ispeek = (len < 0)? 1 : 0;
	int peeksize;
	int recover = 0;
	IKCPSEG *seg;
	assert(kcp);

    // 处理异常流程
	if (iqueue_is_empty(&kcp->rcv_queue)) return -1; // 接收队列为空

	if (len < 0) len = -len;

	peeksize = ikcp_peeksize(kcp);
	if (peeksize < 0) return -2;

	if (peeksize > len)	return -3;

	// 1. 检测一下本次接收数据之后，是否需要进行窗口恢复
	if (kcp->nrcv_que >= kcp->rcv_wnd)  //  接收队列大于滑动窗口的size，触发快速发送我的窗口size给远端
        recover = 1;

    // 2. 将rcv_queue中的数据根据分片编号frg merge起来，然后拷贝到用户的buffer中    直到 frg = 0
	// merge fragment
	for (len = 0, p = kcp->rcv_queue.next; p != &kcp->rcv_queue; )
	{
		int fragment;
		seg = iqueue_entry(p, IKCPSEG, node);
		p = p->next;

		if (buffer)
		{
			memcpy(buffer, seg->data, seg->len);
			buffer += seg->len;
		}

		len += seg->len;
		fragment = seg->frg;

		if (ikcp_canlog(kcp, IKCP_LOG_RECV))
		{
			ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=%lu", seg->sn);
		}

		if (ispeek == 0)
		{
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
			kcp->nrcv_que--;
		}

		if (fragment == 0) 
			break;
	}

	assert(len == peeksize);

    // 3.rcv_buf -> rcv_queue：直到碰到缺口，或窗口变满
	// move available data from rcv_buf -> rcv_queue
	while (! iqueue_is_empty(&kcp->rcv_buf))
    {
		IKCPSEG *seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
		// 1. 根据 sn 确保数据是按序转移到 rcv_queue 中
		// 2. 根据接收窗口大小来判断是否可以接收数据
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd)
        {
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

	// 4. 最后进行窗口恢复
	// fast recover
	if (kcp->nrcv_que < kcp->rcv_wnd && recover)
	{
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		kcp->probe |= IKCP_ASK_TELL;
	}

	return len;
}


//---------------------------------------------------------------------
// peek data size
//---------------------------------------------------------------------
int ikcp_peeksize(const ikcpcb *kcp)
{
	struct IQUEUEHEAD *p;
	IKCPSEG *seg;
	int length = 0;

	assert(kcp);

	if (iqueue_is_empty(&kcp->rcv_queue)) return -1;

	seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
	if (seg->frg == 0) return seg->len;

	if (kcp->nrcv_que < seg->frg + 1) return -1;

	for (p = kcp->rcv_queue.next; p != &kcp->rcv_queue; p = p->next) {
		seg = iqueue_entry(p, IKCPSEG, node);
		length += seg->len;
		if (seg->frg == 0) break;
	}

	return length;
}


//---------------------------------------------------------------------
// user/upper level send, returns below zero for error
//---------------------------------------------------------------------
int ikcp_send(ikcpcb *kcp, const char *buffer, int len)
{
	IKCPSEG *seg;
	int count, i;

	assert(kcp->mss > 0);
	if (len < 0) return -1;

	// append to previous segment in streaming mode (if possible)
	if (kcp->stream != 0) //是否采用流传输模式
    {
		if (!iqueue_is_empty(&kcp->snd_queue))
        {
			IKCPSEG *old = iqueue_entry(kcp->snd_queue.prev, IKCPSEG, node);
			if (old->len < kcp->mss)
            {
				int capacity = kcp->mss - old->len;
				int extend = (len < capacity)? len : capacity;
				seg = ikcp_segment_new(kcp, old->len + extend);
				assert(seg);
				if (seg == NULL)
                {
					return -2;
				}
				iqueue_add_tail(&seg->node, &kcp->snd_queue);
				memcpy(seg->data, old->data, old->len);
				if (buffer)
                {
					memcpy(seg->data + old->len, buffer, extend);
					buffer += extend;
				}
				seg->len = old->len + extend;
				seg->frg = 0;
				len -= extend;
				iqueue_del_init(&old->node);
				ikcp_segment_delete(kcp, old);
			}
		}
		if (len <= 0) {
			return 0;
		}
	}
    // 1.计算拆分的报文数 count
	if (len <= (int)kcp->mss) count = 1;
	else count = (len + kcp->mss - 1) / kcp->mss;

	if (count >= IKCP_WND_RCV) return -2;

	if (count == 0) count = 1;

    // 2.为剩下的数据创建KCP segment,  把buff转换成snd_queue
	// fragment
	for (i = 0; i < count; i++)
    {
		int size = len > (int)kcp->mss ? (int)kcp->mss : len;
		seg = ikcp_segment_new(kcp, size);
		assert(seg);
		if (seg == NULL)
        {
			return -2;
		}
		if (buffer && len > 0)
        {
			memcpy(seg->data, buffer, size);
		}
		seg->len = size;
		seg->frg = (kcp->stream == 0)? (count - i - 1) : 0; // 流模式情况下分片编号不用填写
		iqueue_init(&seg->node);
		iqueue_add_tail(&seg->node, &kcp->snd_queue);	// 加入到 snd_queue 中
		kcp->nsnd_que++;
		if (buffer)
        {
			buffer += size;
		}
		len -= size;
	}

	return 0;
}


//---------------------------------------------------------------------
// parse ack
//---------------------------------------------------------------------
/**
 * rtt算法：调整rto的大小 [超时重传]
 * @param kcp
 * @param rtt
 */
static void ikcp_update_ack(ikcpcb *kcp, IINT32 rtt)
{
	IINT32 rto = 0;
	if (kcp->rx_srtt == 0) //ack接收rtt静态值
    {
		kcp->rx_srtt = rtt;
		kcp->rx_rttval = rtt / 2;
	}
    else
    {
		long delta = rtt - kcp->rx_srtt;
		if (delta < 0) delta = -delta;
		kcp->rx_rttval = (3 * kcp->rx_rttval + delta) / 4;
		kcp->rx_srtt = (7 * kcp->rx_srtt + rtt) / 8;
		if (kcp->rx_srtt < 1) kcp->rx_srtt = 1;
	}
	rto = kcp->rx_srtt + _imax_(kcp->interval, 4 * kcp->rx_rttval);
	kcp->rx_rto = _ibound_(kcp->rx_minrto, rto, IKCP_RTO_MAX);
}

static void ikcp_shrink_buf(ikcpcb *kcp)
{
	struct IQUEUEHEAD *p = kcp->snd_buf.next;
	if (p != &kcp->snd_buf) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		kcp->snd_una = seg->sn;
	}	else {
		kcp->snd_una = kcp->snd_nxt;
	}
}

static void ikcp_parse_ack(ikcpcb *kcp, IUINT32 sn)
{
	struct IQUEUEHEAD *p, *next;

	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
		return;

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next)
    {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (sn == seg->sn)
        {
			iqueue_del(p);
			ikcp_segment_delete(kcp, seg);
			kcp->nsnd_buf--;
			break;
		}
		if (_itimediff(sn, seg->sn) < 0)
        {
			break;
		}
	}
}

static void ikcp_parse_una(ikcpcb *kcp, IUINT32 una)
{
	struct IQUEUEHEAD *p, *next;
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next)
    {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (_itimediff(una, seg->sn) > 0)
        {
			iqueue_del(p);
			ikcp_segment_delete(kcp, seg);
			kcp->nsnd_buf--;
		}
        else
        {
			break;
		}
	}
}

static void ikcp_parse_fastack(ikcpcb *kcp, IUINT32 sn)
{
	struct IQUEUEHEAD *p, *next;

	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
		return;

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (_itimediff(sn, seg->sn) < 0) {
			break;
		}
		else if (sn != seg->sn) {
			seg->fastack++;
		}
	}
}


//---------------------------------------------------------------------
// ack append
//---------------------------------------------------------------------
static void ikcp_ack_push(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	size_t newsize = kcp->ackcount + 1;
	IUINT32 *ptr;

	if (newsize > kcp->ackblock) {
		IUINT32 *acklist;
		size_t newblock;

		for (newblock = 8; newblock < newsize; newblock <<= 1);
		acklist = (IUINT32*)ikcp_malloc(newblock * sizeof(IUINT32) * 2);

		if (acklist == NULL) {
			assert(acklist != NULL);
			abort();
		}

		if (kcp->acklist != NULL) {
			size_t x;
			for (x = 0; x < kcp->ackcount; x++) {
				acklist[x * 2 + 0] = kcp->acklist[x * 2 + 0];
				acklist[x * 2 + 1] = kcp->acklist[x * 2 + 1];
			}
			ikcp_free(kcp->acklist);
		}

		kcp->acklist = acklist;
		kcp->ackblock = newblock;
	}

	ptr = &kcp->acklist[kcp->ackcount * 2];
	ptr[0] = sn;
	ptr[1] = ts;
	kcp->ackcount++;
}

static void ikcp_ack_get(const ikcpcb *kcp, int p, IUINT32 *sn, IUINT32 *ts)
{
	if (sn) sn[0] = kcp->acklist[p * 2 + 0];
	if (ts) ts[0] = kcp->acklist[p * 2 + 1];
}


//---------------------------------------------------------------------
// parse data
//---------------------------------------------------------------------
void ikcp_parse_data(ikcpcb *kcp, IKCPSEG *newseg)
{
	struct IQUEUEHEAD *p, *prev;
	IUINT32 sn = newseg->sn;
	int repeat = 0;
	
	if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) >= 0 ||
		_itimediff(sn, kcp->rcv_nxt) < 0) {
		ikcp_segment_delete(kcp, newseg);
		return;
	}

	for (p = kcp->rcv_buf.prev; p != &kcp->rcv_buf; p = prev) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		prev = p->prev;
		if (seg->sn == sn) {
			repeat = 1;
			break;
		}
		if (_itimediff(sn, seg->sn) > 0) {
			break;
		}
	}

	if (repeat == 0) {
		iqueue_init(&newseg->node);
		iqueue_add(&newseg->node, p);
		kcp->nrcv_buf++;
	}	else {
		ikcp_segment_delete(kcp, newseg);
	}

#if 0
	ikcp_qprint("rcvbuf", &kcp->rcv_buf);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

	// move available data from rcv_buf -> rcv_queue
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
		IKCPSEG *seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

#if 0
	ikcp_qprint("queue", &kcp->rcv_queue);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

#if 1
//	printf("snd(buf=%d, queue=%d)\n", kcp->nsnd_buf, kcp->nsnd_que);
//	printf("rcv(buf=%d, queue=%d)\n", kcp->nrcv_buf, kcp->nrcv_que);
#endif
}


//---------------------------------------------------------------------
// input data
//---------------------------------------------------------------------
int ikcp_input(ikcpcb *kcp, const char *data, long size)
{
	IUINT32 una = kcp->snd_una;
	IUINT32 maxack = 0;
	int flag = 0;

	if (ikcp_canlog(kcp, IKCP_LOG_INPUT))
	{
		ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", size);
	}

	if (data == NULL || (int)size < (int)IKCP_OVERHEAD) return -1;

	while (1)
    {  // 1.首先将接收到的数据包进行解码，并进行基本的数据包长度和类型校验；KCP 协议只会接收到前文中所介绍的四种数据包
		IUINT32 ts, sn, len, una, conv;
		IUINT16 wnd;
		IUINT8 cmd, frg;
		IKCPSEG *seg;
        // 1.1 判断大小是否够一个最小报文
		if (size < (int)IKCP_OVERHEAD) break;
        // 1.2 即便大小够，也不一定是一个报文，需要判断 conv_ 值
		data = ikcp_decode32u(data, &conv);
		if (conv != kcp->conv) return -1;

		data = ikcp_decode8u(data, &cmd);
		data = ikcp_decode8u(data, &frg);
		data = ikcp_decode16u(data, &wnd);
		data = ikcp_decode32u(data, &ts);
		data = ikcp_decode32u(data, &sn);
		data = ikcp_decode32u(data, &una);
		data = ikcp_decode32u(data, &len);

		size -= IKCP_OVERHEAD;
        // 1.3 大小不一致
		if ((long)size < (long)len) return -2;

        // 1.4 协议类型不对
		if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS) 
			return -3;

		kcp->rmt_wnd = wnd;
		/**
		 * 注意 KCP 中所有的报文类型均带有 una 信息。前面介绍过，发送端发送的数据都会缓存在 snd_buf 中，直到接收到对方确认信息之后才会删除。
		 * 当接收到 una 信息后，表明 sn 小于 una 的数据包都已经被对方接收到，因此可以直接从 snd_buf 中删除
		 */
		ikcp_parse_una(kcp, una); //确定已经发送的数据包有哪些被对方接收到
		ikcp_shrink_buf(kcp);  //更新 KCP 控制块的 snd_una 数值
        // 1.5 基于协议内容处理报文
		if (cmd == IKCP_CMD_ACK)  // 1.5.1 处理普通报文
        {
			if (_itimediff(kcp->current, ts) >= 0)
			{
				ikcp_update_ack(kcp, _itimediff(kcp->current, ts));
			}
			ikcp_parse_ack(kcp, sn);// 更新 rtt
			ikcp_shrink_buf(kcp);	// 更新控制块的 snd_una
			if (flag == 0)
			{
				flag = 1;
				maxack = sn;
			}
			else
			{
				if (_itimediff(sn, maxack) > 0)
				{
					maxack = sn;
				}
			}
			if (ikcp_canlog(kcp, IKCP_LOG_IN_ACK))
			{
				ikcp_log(kcp, IKCP_LOG_IN_DATA, 
					"input ack: sn=%lu rtt=%ld rto=%ld", sn, 
					(long)_itimediff(kcp->current, ts),
					(long)kcp->rx_rto);
			}
		}
		else if (cmd == IKCP_CMD_PUSH)
        {
			if (ikcp_canlog(kcp, IKCP_LOG_IN_DATA))
			{
				ikcp_log(kcp, IKCP_LOG_IN_DATA, 
					"input psh: sn=%lu ts=%lu", sn, ts);
			}
			if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) < 0) //对于来自于对方的标准数据包，首先需要检测该报文的编号 sn 是否在窗口范围内；
			{
				ikcp_ack_push(kcp, sn, ts); //调用 ikcp_ack_push 将对该报文的确认 ACK 报文放入 ACK 列表中，ACK 列表的组织方式在前文中已经介绍
				if (_itimediff(sn, kcp->rcv_nxt) >= 0)
				{
					seg = ikcp_segment_new(kcp, len);
					seg->conv = conv;
					seg->cmd = cmd;
					seg->frg = frg;
					seg->wnd = wnd;
					seg->ts = ts;
					seg->sn = sn;
					seg->una = una;
					seg->len = len;

					if (len > 0)
					{
						memcpy(seg->data, data, len);
					}

					ikcp_parse_data(kcp, seg); //最后调用 ikcp_parse_data 将该报文插入到 rcv_buf 链表中
				}
			}
		}
		else if (cmd == IKCP_CMD_WASK)
        {
			// ready to send back IKCP_CMD_WINS in ikcp_flush
			// tell remote my window size
			kcp->probe |= IKCP_ASK_TELL; //直接标记下次将发送窗口通知报文
			if (ikcp_canlog(kcp, IKCP_LOG_IN_PROBE))
			{
				ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe");
			}
		}
		else if (cmd == IKCP_CMD_WINS)
        {
			// do nothing 无需做任何特殊操作
			if (ikcp_canlog(kcp, IKCP_LOG_IN_WINS))
			{
				ikcp_log(kcp, IKCP_LOG_IN_WINS,
					"input wins: %lu", (IUINT32)(wnd));
			}
		}
		else
		{
			return -3;
		}

		data += len;
		size -= len;
	}

	if (flag != 0)
	{
		//根据记录的最大的 ACK 编号 maxack 来更新 snd_buf 中的报文的 fastack
		//对于 fastack 大于设置的 resend 参数时，将立马进行快重传；
		ikcp_parse_fastack(kcp, maxack);
	}
    // 1.6 慢热启动 根据接收到报文的una和 KCP 控制块的 una 参数进行流控
	if (_itimediff(kcp->snd_una, una) > 0)
    {
		if (kcp->cwnd < kcp->rmt_wnd)
		{
			IUINT32 mss = kcp->mss;
			if (kcp->cwnd < kcp->ssthresh)
			{
				kcp->cwnd++;
				kcp->incr += mss;
			}
			else
			{
				if (kcp->incr < mss) kcp->incr = mss;
				kcp->incr += (mss * mss) / kcp->incr + (mss / 16);
				if ((kcp->cwnd + 1) * mss <= kcp->incr)
				{
					kcp->cwnd++;
				}
			}
			if (kcp->cwnd > kcp->rmt_wnd)
			{
				kcp->cwnd = kcp->rmt_wnd;
				kcp->incr = kcp->rmt_wnd * mss;
			}
		}
	}

	return 0;
}


//---------------------------------------------------------------------
// ikcp_encode_seg
//---------------------------------------------------------------------
static char *ikcp_encode_seg(char *ptr, const IKCPSEG *seg)
{
	ptr = ikcp_encode32u(ptr, seg->conv);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->cmd);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->frg);
	ptr = ikcp_encode16u(ptr, (IUINT16)seg->wnd);
	ptr = ikcp_encode32u(ptr, seg->ts);
	ptr = ikcp_encode32u(ptr, seg->sn);
	ptr = ikcp_encode32u(ptr, seg->una);
	ptr = ikcp_encode32u(ptr, seg->len);
	return ptr;
}

static int ikcp_wnd_unused(const ikcpcb *kcp)
{
	if (kcp->nrcv_que < kcp->rcv_wnd)
	{
		return kcp->rcv_wnd - kcp->nrcv_que;
	}
	return 0;
}


//---------------------------------------------------------------------
// ikcp_flush          下层函数ikcp_flush将会决定将多少数据从snd_queue中移到snd_buf中, 进行发送
//---------------------------------------------------------------------
void ikcp_flush(ikcpcb *kcp)
{
	IUINT32 current = kcp->current;
	char *buffer = kcp->buffer;
	char *ptr = buffer;
	int count, size, i;
	IUINT32 resent, cwnd;
	IUINT32 rtomin;
	struct IQUEUEHEAD *p;
	int change = 0;
	int lost = 0;
	IKCPSEG seg;

	// 1. 检查 kcp->update 是否更新，未更新直接返回
	// 'ikcp_update' haven't been called. 
	if (kcp->updated == 0) return;

	seg.conv = kcp->conv;
	seg.cmd = IKCP_CMD_ACK;
	seg.frg = 0;
	seg.wnd = ikcp_wnd_unused(kcp); //接收窗口未被使用的大小
	seg.una = kcp->rcv_nxt;			//待接收消息序号
	seg.len = 0;
	seg.sn = 0;
	seg.ts = 0;

    // 2.ACK：对接收到的报文进行应答(将acklist中记录的ACK报文发送出去)
	// flush acknowledges
	count = kcp->ackcount;
	for (i = 0; i < count; i++)
	{
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu)
        {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ikcp_ack_get(kcp, i, &seg.sn, &seg.ts); //从 acklist 中填充 ACK 报文的 sn 和 ts 字段
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	kcp->ackcount = 0;

    // 3. 询问对端窗口大小
	/**
	 * 由于 KCP 流量控制依赖于远端通知其可接受窗口的大小，
	 * 一旦远端接受窗口 kcp->rmt_wnd 为0，那么本地将不会再向远端发送数据，
	 * 因此就没有机会从远端接受ACK报文，从而没有机会更新远端窗口大小。
	 * 在这种情况下，KCP 需要发送窗口探测报文到远端，待远端回复窗口大小后，后续传输可以继续
	 */
    // probe window size (if remote window size equals zero)
	if (kcp->rmt_wnd == 0) //需要发送窗口探测报文到远端
    {
		if (kcp->probe_wait == 0) // 初始化探测间隔和下一次探测时间
        {
			kcp->probe_wait = IKCP_PROBE_INIT;
			kcp->ts_probe = kcp->current + kcp->probe_wait;
		}	
		else
        {
			if (_itimediff(kcp->current, kcp->ts_probe) >= 0)
            {
				if (kcp->probe_wait < IKCP_PROBE_INIT) kcp->probe_wait = IKCP_PROBE_INIT;
				kcp->probe_wait += kcp->probe_wait / 2;
				if (kcp->probe_wait > IKCP_PROBE_LIMIT) kcp->probe_wait = IKCP_PROBE_LIMIT;
				kcp->ts_probe = kcp->current + kcp->probe_wait;
				kcp->probe |= IKCP_ASK_SEND; // 标识需要探测远端窗口
			}
		}
	}
    else
    {
		kcp->ts_probe = 0; //下次探查窗口的时间戳
		kcp->probe_wait = 0; //探查窗口需要等待的时间
	}
	//4. 将窗口探测报文和窗口回复报文发送出去，这一步用来完成 3 中所说的窗口探测协议
	// flush window probing commands
	if (kcp->probe & IKCP_ASK_SEND)
    {
		seg.cmd = IKCP_CMD_WASK;
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu)
        {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg);
	}


	// flush window probing commands
	if (kcp->probe & IKCP_ASK_TELL)
    {
		seg.cmd = IKCP_CMD_WINS;
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu)
		{
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	kcp->probe = 0;

	//5. 计算本次发送可用的窗口大小，这里 KCP 采用了可以配置的策略
	// 正常情况下，KCP 的窗口大小由[发送窗口snd_wnd]，[远端接收窗口rmt_wnd] 以及 [根据流控计算得到的kcp->cwnd] 共同决定；
	// 但是当开启了 nocwnd 模式时，窗口大小仅由前两者决定；
	// calculate window size
	cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd);
	if (kcp->nocwnd == 0) cwnd = _imin_(kcp->cwnd, cwnd);

	//6. 将缓存在snd_queue 中的数据移到 snd_buf 中等待发送，这个两个 buf 的作用在前文中已经介绍；
	// move data from snd_queue to snd_buf
	while (_itimediff(kcp->snd_nxt, kcp->snd_una + cwnd) < 0)
    {
		IKCPSEG *newseg;
		if (iqueue_is_empty(&kcp->snd_queue)) break;

		newseg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);

		iqueue_del(&newseg->node);
		iqueue_add_tail(&newseg->node, &kcp->snd_buf);
		kcp->nsnd_que--;
		kcp->nsnd_buf++;

		newseg->conv = kcp->conv;
		newseg->cmd = IKCP_CMD_PUSH;
		newseg->wnd = seg.wnd;
		newseg->ts = current;
		newseg->sn = kcp->snd_nxt++;
		newseg->una = kcp->rcv_nxt;
		newseg->resendts = current;
		newseg->rto = kcp->rx_rto;
		newseg->fastack = 0;
		newseg->xmit = 0;
	}

	//7. 在发送数据之前，先设置快重传的次数和重传间隔
	// 每个报文的 fastack 记录了该报文被跳过了几次，由函数 ikcp_parse_fastack 更新
	// calculate resent 超时重传
	resent = (kcp->fastresend > 0)? (IUINT32)kcp->fastresend : 0xffffffff; // 是否设置了快重传次数 //KCP 允许设置快重传的次数，即 fastresend 参数
	rtomin = (kcp->nodelay == 0)? (kcp->rx_rto >> 3) : 0;// 是否开启了 nodelay         把kcp->rx_rto转化成2进制后向右移动3位


	//8. 将snd_buf中的数据发送出去，这里分为几种不同的情况处理
	// flush data segments
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next)
    {
		IKCPSEG *segment = iqueue_entry(p, IKCPSEG, node);
		int needsend = 0;
		if (segment->xmit == 0) { // 满足条件：一次都没重发     那么直接发送
			needsend = 1;
			segment->xmit++;
			segment->rto = kcp->rx_rto;
			segment->resendts = current + segment->rto + rtomin;
		}
		else if (_itimediff(current, segment->resendts) >= 0) { // 满足条件：当前时间超过重发时间    那么发送该报文
			needsend = 1;
			segment->xmit++;
			kcp->xmit++;
			if (kcp->nodelay == 0)
			{
				segment->rto += kcp->rx_rto;
			}
			else
			{
				segment->rto += kcp->rx_rto / 2;
			}
			segment->resendts = current + segment->rto;
			lost = 1;  // 记录出现了报文丢失
		}
		else if (segment->fastack >= resent) {// 满足条件：该报文被跳过的次数fastack 超过了设置的快重传次数，发送该报文
			needsend = 1;
			segment->xmit++;
			segment->fastack = 0;
			segment->resendts = current + segment->rto;
			change++; // 标识快重传发生
		}

		if (needsend)
		{
			int size, need;
			segment->ts = current;
			segment->wnd = seg.wnd;
			segment->una = kcp->rcv_nxt;

			size = (int)(ptr - buffer);
			need = IKCP_OVERHEAD + segment->len;

			if (size + need > (int)kcp->mtu)
			{
				ikcp_output(kcp, buffer, size);
				ptr = buffer;
			}

			ptr = ikcp_encode_seg(ptr, segment);

			if (segment->len > 0)
			{
				memcpy(ptr, segment->data, segment->len);
				ptr += segment->len;
			}

			if (segment->xmit >= kcp->dead_link)// 单个报文重传超过指定次数，视为断线
			{
				kcp->state = -1;
			}
		}
	}

	// flash remain segments
	size = (int)(ptr - buffer);
	if (size > 0) {
		ikcp_output(kcp, buffer, size);
	}

	// 9. 根据设置的 lost 和 change 更新窗口大小；注意 快重传和丢包时的窗口更新算法不一致，这一点类似于TCP协议的拥塞控制和快恢复算法；
	// update ssthresh
	if (change)
	{
		IUINT32 inflight = kcp->snd_nxt - kcp->snd_una;
		kcp->ssthresh = inflight / 2;
		if (kcp->ssthresh < IKCP_THRESH_MIN)
			kcp->ssthresh = IKCP_THRESH_MIN;
		kcp->cwnd = kcp->ssthresh + resent;
		kcp->incr = kcp->cwnd * kcp->mss;
	}

	if (lost)
	{
		kcp->ssthresh = cwnd / 2;
		if (kcp->ssthresh < IKCP_THRESH_MIN)
			kcp->ssthresh = IKCP_THRESH_MIN;
		kcp->cwnd = 1;
		kcp->incr = kcp->mss;
	}

	if (kcp->cwnd < 1)
	{
		kcp->cwnd = 1;
		kcp->incr = kcp->mss;
	}
}


//---------------------------------------------------------------------
// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec. 
//---------------------------------------------------------------------
// 上层应用需要每隔一段时间（10-100ms）调用 ikcp_update 来驱动 KCP 发送数据
void ikcp_update(ikcpcb *kcp, IUINT32 current)
{
	IINT32 slap;

	kcp->current = current;

	if (kcp->updated == 0)// 第一次处理
    {
		kcp->updated = 1;
		kcp->ts_flush = kcp->current;
	}

	slap = _itimediff(kcp->current, kcp->ts_flush);

	if (slap >= 10000 || slap < -10000) // 超时处理
    {
		kcp->ts_flush = kcp->current;
		slap = 0;
	}

	if (slap >= 0)// 利用ts_flush控制刷新的时间间隔，interval 控制频率
    {
		kcp->ts_flush += kcp->interval;
		if (_itimediff(kcp->current, kcp->ts_flush) >= 0)
        {
			kcp->ts_flush = kcp->current + kcp->interval;
		}
		ikcp_flush(kcp);
	}
}


//---------------------------------------------------------------------
// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
//---------------------------------------------------------------------
/**
 *  检测是否需要立即刷新
 * @param kcp
 * @param current
 * @return
 */
IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current)
{
	IUINT32 ts_flush = kcp->ts_flush;
	IINT32 tm_flush = 0x7fffffff;
	IINT32 tm_packet = 0x7fffffff;
	IUINT32 minimal = 0;
	struct IQUEUEHEAD *p;

	if (kcp->updated == 0) {
		return current;
	}

	if (_itimediff(current, ts_flush) >= 10000 || _itimediff(current, ts_flush) < -10000) // 1.如果超时，立即刷新
    {
		ts_flush = current;
	}

	if (_itimediff(current, ts_flush) >= 0)// 2.如果超过了应该刷新的时间，立即刷新
    {
		return current;
	}

	tm_flush = _itimediff(ts_flush, current);


    // 3.如果有需要超时重传的报文，立即刷新
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next)
    {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		IINT32 diff = _itimediff(seg->resendts, current);
		if (diff <= 0)
        {
			return current;
		}
		if (diff < tm_packet) tm_packet = diff;
	}

    // 4.计算最终下一次更新的时间
	minimal = (IUINT32)(tm_packet < tm_flush ? tm_packet : tm_flush);
	if (minimal >= kcp->interval) minimal = kcp->interval;

	return current + minimal;
}


/**
 * 最大传输单元
 * @param kcp
 * @param mtu
 * @return
 */
int ikcp_setmtu(ikcpcb *kcp, int mtu)
{
	char *buffer;
	if (mtu < 50 || mtu < (int)IKCP_OVERHEAD) 
		return -1;
	buffer = (char*)ikcp_malloc((mtu + IKCP_OVERHEAD) * 3);
	if (buffer == NULL) 
		return -2;
	kcp->mtu = mtu;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	ikcp_free(kcp->buffer);
	kcp->buffer = buffer;
	return 0;
}

int ikcp_interval(ikcpcb *kcp, int interval)
{
	if (interval > 5000) interval = 5000;
	else if (interval < 10) interval = 10;
	kcp->interval = interval;
	return 0;
}
/**
 * 工作模式 默认模式是一个标准的ARQ，需要通过配置打开各项加速开关
 * @param kcp
 * @param nodelay 是否启用 nodelay模式，0不启用；1启用。
 * @param interval 协议内部工作的 interval，单位毫秒，比如 10ms或者 20ms
 * @param resend 快速重传模式，默认0关闭，可以设置2（2次ACK跨越将会直接重传）                                           //快速重传
 * @param nc 是否关闭流控，默认是0代表不关闭，1代表关闭。
 * @return
 * 普通模式： ikcp_nodelay(kcp, 0, 40, 0, 0)
 * 极速模式： ikcp_nodelay(kcp, 1, 10, 2, 1)
 */
int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc)
{
	if (nodelay >= 0)
    {
		kcp->nodelay = nodelay;
		if (nodelay)
        {
			kcp->rx_minrto = IKCP_RTO_NDL;	
		}	
		else
        {
			kcp->rx_minrto = IKCP_RTO_MIN;
		}
	}
	if (interval >= 0)
    {
		if (interval > 5000) interval = 5000;
		else if (interval < 10) interval = 10;
		kcp->interval = interval;
	}
	if (resend >= 0)
    {
		kcp->fastresend = resend;
	}
	if (nc >= 0)
    {
		kcp->nocwnd = nc;
	}
	return 0;
}

/**
 * 最大窗口
 * @param kcp
 * @param sndwnd 最大发送窗口
 * @param rcvwnd 最大接收窗口大小
 * @return
 */
int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd)
{
	if (kcp) {
		if (sndwnd > 0) {
			kcp->snd_wnd = sndwnd;
		}
		if (rcvwnd > 0) {   // must >= max fragment size
			kcp->rcv_wnd = _imax_(rcvwnd, IKCP_WND_RCV);
		}
	}
	return 0;
}

int ikcp_waitsnd(const ikcpcb *kcp)
{
	return kcp->nsnd_buf + kcp->nsnd_que;
}


// read conv
IUINT32 ikcp_getconv(const void *ptr)
{
	IUINT32 conv;
	ikcp_decode32u((const char*)ptr, &conv);
	return conv;
}


