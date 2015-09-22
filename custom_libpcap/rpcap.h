#ifndef RCAP_H_INCLUDED
#define RCAP_H_INCLUDED


/* This data structs need to be transfered in rpcap.c once debug is completed*/
struct pcap_hdr {
    uint32_t magic_number; /*used to detect the file format itself and the byte
    ordering. The writing application writes 0xa1b2c3d4 with it's native byte
    ordering format into this field. The reading application will read either
    0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If the reading application
    reads the swapped 0xd4c3b2a1 value, it knows that all the following fields
    will have to be swapped too. For nanosecond-resolution files, the writing
    application writes 0xa1b23c4d, with the two nibbles of the two lower-order
    bytes swapped, and the reading application will read either 0xa1b23c4d
    (identical) or 0x4d3cb2a1 (swapped)*/
    uint16_t version_major;
    uint16_t version_minor; /*the version number of this file format */
    int32_t thiszone; /*the correction time in seconds between GMT (UTC) and the
    local timezone of the following packet header timestamps. Examples: If the
    timestamps are in GMT (UTC), thiszone is simply 0. If the timestamps are in
    Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00, thiszone
    must be -3600*/
    char resolution; /*if it is 'n', ts_usec in packet header specifies
    nanosecond-resolution, otherwise it is 'm' for microsecond-resolution*/
    uint32_t stampacc; /*the accuracy of time stamps in the capture*/
    uint32_t snaplen; /*the "snapshot length" for the capture (typically 65535
    or even more, but might be limited by the user)*/
    uint32_t network; /*link-layer header type, specifying the type of headers
    at the beginning of the packet (e.g. 1 for Ethernet); this can be various
    types such as 802.11, 802.11 with various radio information, PPP, Token
    Ring, FDDI, etc.*/
    
    //XXX
    uint32_t tot_pkt;
    uint64_t tot_len;
};

struct pcaprec_hdr {
    uint32_t ts_sec; /*the date and time when this packet was captured. This
    value is in seconds since January 1, 1970 00:00:00 GMT; this is also known
    as a UN*X time_t. If this timestamp isn't based on GMT (UTC), use thiszone
    from the global header for adjustments*/
    uint32_t ts_usec; /*in regular pcap files, the microseconds when this packet
    was captured, as an offset to ts_sec. In nanosecond-resolution files, this
    is, instead, the nanoseconds when the packet was captured, as an offset to
    ts_sec*/
    uint32_t incl_len; /*the number of bytes of packet data actually captured
    and saved in the file. This value should never become larger than orig_len
    or the snaplen value of the global header*/
    uint32_t orig_len; /* the length of the packet as it appeared on the network
    when it was captured. If incl_len and orig_len differ, the actually saved
    packet size was limited by snaplen*/
};
/* Data needs to be transfered untill here*/






typedef struct pcap_hdr pcap_hdr_t;

typedef struct pcaprec_hdr pcaprec_hdr_t;

struct pkt_list_element {
    pcaprec_hdr_t hdr;
    unsigned char *data;
    struct pkt_list_element* p;
};



typedef struct pkt_list_element packet_data;


/* The pcap file structure has the following members:
   - A global header which is pcap_hdr_t
   - A list of packets with the following members:
       + A packet header
       + packet payload
       + Pointer to the next packet
   - A pointer to the last packet in the list
*/
typedef struct pcap_file {
    pcap_hdr_t *ghdr;
    packet_data *list;
    packet_data *end;
} fpcap;

fpcap *readpcap(int file);
void destroy_pcap_file(fpcap **file);


#endif // RCAP_H_INCLUDED
