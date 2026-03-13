/*
 * FILE: rdt_receiver.cc
 * DESCRIPTION: Reliable data transfer receiver.
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

#include "rdt_struct.h"
#include "rdt_receiver.h"

static const int PKT_TYPE_DATA = 0;
static const int PKT_TYPE_ACK = 1;

static const int OFF_TYPE = 0;
static const int OFF_SEQ = 1;
static const int OFF_ACK = 5;
static const int OFF_LEN = 9;
static const int OFF_CKSUM = 11;
static const int HEADER_SIZE = 13;
static const int MAX_PAYLOAD_SIZE = RDT_PKTSIZE - HEADER_SIZE;

static int g_expected_seq = 0;

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

static void fill_ack_packet(packet *pkt, int ack)
{
    memset(pkt->data, 0, RDT_PKTSIZE);
    pkt->data[OFF_TYPE] = (char)PKT_TYPE_ACK;
    write_i32(pkt->data, OFF_SEQ, 0);
    write_i32(pkt->data, OFF_ACK, ack);
    write_u16(pkt->data, OFF_LEN, 0);
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

static void send_last_ack()
{
    packet ack_pkt;
    fill_ack_packet(&ack_pkt, g_expected_seq - 1);
    Receiver_ToLowerLayer(&ack_pkt);
}


/* receiver initialization, called once at the very beginning */
void Receiver_Init()
{
    fprintf(stdout, "At %.2fs: receiver initializing ...\n", GetSimulationTime());
    g_expected_seq = 0;
}

/* receiver finalization, called once at the very end.
   you may find that you don't need it, in which case you can leave it blank.
   in certain cases, you might want to use this opportunity to release some 
   memory you allocated in Receiver_init(). */
void Receiver_Final()
{
    fprintf(stdout, "At %.2fs: receiver finalizing ...\n", GetSimulationTime());
}

/* event handler, called when a packet is passed from the lower layer at the 
   receiver */
void Receiver_FromLowerLayer(struct packet *pkt)
{
    int type, seq, ack, len;
    if (!decode_packet(pkt, &type, &seq, &ack, &len)) {
        send_last_ack();
        return;
    }

    if (type != PKT_TYPE_DATA) {
        send_last_ack();
        return;
    }

    if (seq == g_expected_seq) {
        struct message *msg = (struct message *)malloc(sizeof(struct message));
        ASSERT(msg != NULL);

        msg->size = len;
        msg->data = NULL;
        if (len > 0) {
            msg->data = (char *)malloc(len);
            ASSERT(msg->data != NULL);
            memcpy(msg->data, pkt->data + HEADER_SIZE, len);
        }

        Receiver_ToUpperLayer(msg);

        if (msg->data != NULL) {
            free(msg->data);
        }
        free(msg);

        g_expected_seq += 1;
    }

    send_last_ack();
}
