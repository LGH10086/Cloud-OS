/*
 * FILE: rdt_sender.cc
 * DESCRIPTION: Reliable data transfer sender.
 * NOTE: This implementation assumes there is no packet loss, corruption, or 
 *       reordering.  You will need to enhance it to deal with all these 
 *       situations.  In this implementation, the packet format is laid out as 
 *       the following:
 *       
 *       |<-  1 byte  ->|<-             the rest            ->|
 *       | payload size |<-             payload             ->|
 *
 *       The first byte of each packet indicates the size of the payload
 *       (excluding this single-byte header)
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <deque>
#include <map>

#include "rdt_struct.h"
#include "rdt_sender.h"

static const int PKT_TYPE_DATA = 0;
static const int PKT_TYPE_ACK = 1;
static const int WINDOW_SIZE = 10;
static const double RETRANSMIT_TIMEOUT = 0.3;

static const int OFF_TYPE = 0;
static const int OFF_SEQ = 1;
static const int OFF_ACK = 5;
static const int OFF_LEN = 9;
static const int OFF_CKSUM = 11;
static const int HEADER_SIZE = 13;
static const int MAX_PAYLOAD_SIZE = RDT_PKTSIZE - HEADER_SIZE;

struct PayloadChunk {
    int len;
    char data[MAX_PAYLOAD_SIZE];
};

static int g_base = 0;
static int g_next_seq = 0;
static std::map<int, packet> g_unacked;
static std::deque<PayloadChunk> g_waiting;

static void write_u16(char *buf, int off, unsigned short value)
{
    buf[off] = (char)((value >> 8) & 0xFF);
    buf[off + 1] = (char)(value & 0xFF);
}

static unsigned short read_u16(const char *buf, int off)
{
    return (unsigned short)((((unsigned char)buf[off]) << 8) |
                            ((unsigned char)buf[off + 1]));
}

static void write_i32(char *buf, int off, int value)
{
    unsigned int v = (unsigned int)value;
    buf[off] = (char)((v >> 24) & 0xFF);
    buf[off + 1] = (char)((v >> 16) & 0xFF);
    buf[off + 2] = (char)((v >> 8) & 0xFF);
    buf[off + 3] = (char)(v & 0xFF);
}

static int read_i32(const char *buf, int off)
{
    unsigned int v = 0;
    v |= ((unsigned int)(unsigned char)buf[off]) << 24;
    v |= ((unsigned int)(unsigned char)buf[off + 1]) << 16;
    v |= ((unsigned int)(unsigned char)buf[off + 2]) << 8;
    v |= ((unsigned int)(unsigned char)buf[off + 3]);
    return (int)v;
}

static unsigned short internet_checksum(const char *buf, int len)
{
    unsigned int sum = 0;
    int i;
    for (i = 0; i + 1 < len; i += 2) {
        unsigned short word = (unsigned short)((((unsigned char)buf[i]) << 8) |
                                               ((unsigned char)buf[i + 1]));
        sum += word;
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    if (i < len) {
        unsigned short word = (unsigned short)(((unsigned char)buf[i]) << 8);
        sum += word;
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    return (unsigned short)(~sum);
}

static void fill_packet(packet *pkt, int type, int seq, int ack, const char *payload, int len)
{
    memset(pkt->data, 0, RDT_PKTSIZE);
    pkt->data[OFF_TYPE] = (char)type;
    write_i32(pkt->data, OFF_SEQ, seq);
    write_i32(pkt->data, OFF_ACK, ack);
    write_u16(pkt->data, OFF_LEN, (unsigned short)len);
    if (len > 0) {
        memcpy(pkt->data + HEADER_SIZE, payload, len);
    }
    write_u16(pkt->data, OFF_CKSUM, 0);
    write_u16(pkt->data, OFF_CKSUM, internet_checksum(pkt->data, RDT_PKTSIZE));
}

static bool decode_packet(const packet *pkt, int *type, int *seq, int *ack, int *len)
{
    packet temp = *pkt;
    unsigned short old_cksum = read_u16(temp.data, OFF_CKSUM);
    write_u16(temp.data, OFF_CKSUM, 0);
    unsigned short computed = internet_checksum(temp.data, RDT_PKTSIZE);
    if (old_cksum != computed) {
        return false;
    }

    *type = (unsigned char)temp.data[OFF_TYPE];
    *seq = read_i32(temp.data, OFF_SEQ);
    *ack = read_i32(temp.data, OFF_ACK);
    *len = (int)read_u16(temp.data, OFF_LEN);
    if (*len < 0 || *len > MAX_PAYLOAD_SIZE) {
        return false;
    }

    return true;
}

static void try_send_from_queue()
{
    while (!g_waiting.empty() && g_next_seq < g_base + WINDOW_SIZE) {
        PayloadChunk ch = g_waiting.front();
        g_waiting.pop_front();

        packet pkt;
        fill_packet(&pkt, PKT_TYPE_DATA, g_next_seq, -1, ch.data, ch.len);
        g_unacked[g_next_seq] = pkt;
        Sender_ToLowerLayer(&pkt);

        if (g_base == g_next_seq) {
            Sender_StartTimer(RETRANSMIT_TIMEOUT);
        }
        g_next_seq += 1;
    }
}


/* sender initialization, called once at the very beginning */
void Sender_Init()
{
    fprintf(stdout, "At %.2fs: sender initializing ...\n", GetSimulationTime());
    g_base = 0;
    g_next_seq = 0;
    g_unacked.clear();
    g_waiting.clear();
}

/* sender finalization, called once at the very end.
   you may find that you don't need it, in which case you can leave it blank.
   in certain cases, you might want to take this opportunity to release some 
   memory you allocated in Sender_init(). */
void Sender_Final()
{
    fprintf(stdout, "At %.2fs: sender finalizing ...\n", GetSimulationTime());
}

/* event handler, called when a message is passed from the upper layer at the 
   sender */
void Sender_FromUpperLayer(struct message *msg)
{
    int cursor = 0;
    while (cursor < msg->size) {
        int chunk_len = msg->size - cursor;
        if (chunk_len > MAX_PAYLOAD_SIZE) {
            chunk_len = MAX_PAYLOAD_SIZE;
        }

        PayloadChunk ch;
        ch.len = chunk_len;
        memcpy(ch.data, msg->data + cursor, chunk_len);
        g_waiting.push_back(ch);

        cursor += chunk_len;
    }

    try_send_from_queue();
}

/* event handler, called when a packet is passed from the lower layer at the 
   sender */
void Sender_FromLowerLayer(struct packet *pkt)
{
    int type, seq, ack, len;
    if (!decode_packet(pkt, &type, &seq, &ack, &len)) {
        return;
    }

    if (type != PKT_TYPE_ACK) {
        return;
    }

    if (ack < g_base || ack >= g_next_seq) {
        return;
    }

    for (int s = g_base; s <= ack; ++s) {
        g_unacked.erase(s);
    }
    g_base = ack + 1;

    if (g_base == g_next_seq) {
        if (Sender_isTimerSet()) {
            Sender_StopTimer();
        }
    } else {
        Sender_StartTimer(RETRANSMIT_TIMEOUT);
    }

    try_send_from_queue();
}

/* event handler, called when the timer expires */
void Sender_Timeout()
{
    if (g_base >= g_next_seq) {
        return;
    }

    for (int s = g_base; s < g_next_seq; ++s) {
        std::map<int, packet>::iterator it = g_unacked.find(s);
        if (it != g_unacked.end()) {
            Sender_ToLowerLayer(&it->second);
        }
    }

    Sender_StartTimer(RETRANSMIT_TIMEOUT);
}
