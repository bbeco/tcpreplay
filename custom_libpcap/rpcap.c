#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include "rpcap.h"

int main()
{
    int file = open("file.cap", O_RDONLY);
    if (file < 0) {
        fprintf(stderr, "Error opening file\n");
    }
    fpcap *fpc = readpcap(file);
    printf("Hello world!\n");
    printf("pacchetti catturati%d\nlunghezza totale %ld\n", fpc->ghdr->tot_pkt, (long int)fpc->ghdr->tot_len);
    printf("%d\n", fpc->list->hdr.ts_sec);
    printf("%c\n", fpc->ghdr->resolution);
    destroy_pcap_file(&fpc);
    return 0;
}




packet_data *new_packet_data() {
    packet_data *pkt = (packet_data *)calloc(sizeof(packet_data), 1);
    return pkt;
}

fpcap *new_fpcap() {
    fpcap *filepcap = (fpcap *)calloc(1, sizeof(fpcap));
    /*filepcap->ghdr = NULL;
    filepcap->list = NULL;
    filepcap->end = NULL;
    */
    return filepcap;
}


// Destroy a pcap file
void destroy_pcap_file(fpcap **file) {
    if (!*file) return;
    packet_data *tmp;
    if ((*file)->ghdr) {
        free((*file)->ghdr);
        (*file)->ghdr = NULL;
    }
    while ((*file)->list) {
        tmp = (*file)->list->p;
        if ((*file)->list->data) {
            free((*file)->list->data);
            (*file)->list->data = NULL;
        }
        free((*file)->list);
        (*file)->list = tmp;
    }
    free(*file);
    *file = NULL;
}

// Insert a packet in the pcap file struct ordered by means of ther timestamp
void insert_pkt(fpcap *file, packet_data *pkt) {
    packet_data *a, *b;
    if (pkt == NULL) return;
    // Empty list
    if (file->list == NULL) {
        file->list = pkt;
        file->end = pkt;
        return;
    }
    a = file->list;
    while (a && (pkt->hdr.ts_sec >= a->hdr.ts_sec ||
    (pkt->hdr.ts_sec == a->hdr.ts_sec && pkt->hdr.ts_usec >= a->hdr.ts_usec))) {
        b = a;
        a = a->p;
    }
    // insert in head
    if (a == file->list) {
        pkt->p = file->list;
        file->list = pkt;
        return;
    }
    // insert at the end
    if (a == NULL) {
        file->end->p = pkt;
        file->end = pkt;
        return;
    }
    // insert in the middle
    pkt->p = a;
    b->p = pkt;
    return;
}

// Read file pcap's header info and swap the content if the file has a byte
// ordering different than system byte ordering
int read_next_info(int file, unsigned char *data, int size, char swap) {
    int i;
    unsigned char tmp;
    i = read(file, data, size);
    if (i != size) {
        //fprintf("Error reading file pcap header\n");
        return i;
    }
    if (swap) {
        for (i = 0; i < size / 2; i++) {
            tmp = data[i];
            data[i] = data[size - (1 + i)];
            data[size - (1 + i)] = tmp;
        }
    }
    return size;
}

// Allocate a new pcap file structure, read infos from file and return
// structure's address
fpcap *readpcap(int file) {
    fpcap *filepcap = new_fpcap();
    packet_data *pkt;
    int ret;
    // If the system's byte ordering is different than file's, swap = 1
    char swap;

    filepcap->ghdr = (pcap_hdr_t *)calloc(1, sizeof(pcap_hdr_t));

    ret = read(file, &(filepcap->ghdr->magic_number), sizeof(uint32_t));
    if (ret != sizeof(uint32_t)) {
        goto fail;
    }
    switch (filepcap->ghdr->magic_number) {
        case 0xa1b2c3d4:
            swap = 0;
            filepcap->ghdr->resolution = 'm';
            break;
        case 0xd4c3b2a1:
            swap = 0;
            filepcap->ghdr->resolution = 'm';
            break;
        case 0xa1b23c4d:
            swap = 0;
            filepcap->ghdr->resolution = 'n';
            break;
        case 0x4d3cb2a1:
            swap = 1;
            filepcap->ghdr->resolution = 'n';
            break;
        default:
            goto fail;
    }

    if (read_next_info(file, (unsigned char *)&(filepcap->ghdr->version_major), sizeof(uint16_t), swap) != sizeof(uint16_t) ||
        read_next_info(file, (unsigned char *)&(filepcap->ghdr->version_minor), sizeof(uint16_t), swap) != sizeof(uint16_t) ||
        read_next_info(file, (unsigned char *)&(filepcap->ghdr->thiszone), sizeof(int32_t), swap) != sizeof(int32_t) ||
        read_next_info(file, (unsigned char *)&(filepcap->ghdr->stampacc), sizeof(uint32_t), swap) != sizeof(uint32_t) ||
        read_next_info(file, (unsigned char *)&(filepcap->ghdr->snaplen), sizeof(uint32_t), swap) != sizeof(uint32_t) ||
        read_next_info(file, (unsigned char *)&(filepcap->ghdr->network), sizeof(uint32_t), swap) != sizeof(uint32_t)) {
            goto fail;
    }
    while(1) {
        pkt = new_packet_data();
        ret = read_next_info(file, (unsigned char *)&(pkt->hdr.ts_sec), sizeof(uint32_t), swap);
        if (ret != sizeof(uint32_t)) {
            if (ret == 0) {
                // If no elements have been inserted in the data structure
                if (!filepcap->list) {
                    goto fail;
                }
                break;
            }
            goto fail;
        }
        if (read_next_info(file, (unsigned char *)&(pkt->hdr.ts_usec), sizeof(uint32_t), swap) != sizeof(uint32_t) ||
            read_next_info(file, (unsigned char *)&(pkt->hdr.incl_len), sizeof(uint32_t), swap) != sizeof(uint32_t) ||
            read_next_info(file, (unsigned char *)&(pkt->hdr.orig_len), sizeof(uint32_t), swap) != sizeof(uint32_t)) {
                goto fail;
        }
        pkt->data = (unsigned char *)malloc(pkt->hdr.incl_len);
        if (read(file, pkt->data, pkt->hdr.incl_len) < pkt->hdr.incl_len) {
            goto fail;
        }
        insert_pkt(filepcap, pkt);
        filepcap->ghdr->tot_len += pkt->hdr.incl_len;
        filepcap->ghdr->tot_pkt++;
    }

    return filepcap;

fail:
    fprintf(stderr, "Error reading pcap file\n");
    destroy_pcap_file(&filepcap);
    return NULL;
}
