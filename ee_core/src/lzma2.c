
#include <stdio.h>
#include <limits.h>
#include <tamtypes.h>
#include <lzma2.h>

#include "ee_core.h"
#include "modules.h"
#include "modmgr.h"
#include "util.h"

static unsigned char xz_header_magic[6] = {0xFD, '7', 'z', 'X', 'Z', 0x00};
static unsigned char xz_footer_magic[2] = {'Y', 'Z'};

// Returns number of bytes a number uses
static size_t decode(const unsigned char buf[], size_t size_max, unsigned long *num)
{
    if (size_max == 0)
        return 0;

    if (size_max > 9)
        size_max = 9;

    *num = buf[0] & 0x7F;
    size_t i = 0;

    while (buf[i++] & 0x80) {
        if (i >= size_max || buf[i] == 0x00)
            return 0;

        *num |= (u64)(buf[i] & 0x7F) << (i * 7);
    }

    return i;
}

static size_t lzma2_decode_size(unsigned char *index)
{
    int i;
    unsigned long records;
    unsigned long size;
    size_t uncompressed_size = 0;
    unsigned char *buf = index;

    if (*buf != 0) {
        return 0;
    }

    // First byte is 0
    buf++;

    // Number of records
    buf += decode(buf, 9, &records);

    for (i = 0; i < records; i++) {
        // Unpadded size
        buf += decode(buf, 9, &size);
        size = 0L;
        // Uncompressed size
        buf += decode(buf, 9, &size);
        uncompressed_size += size;
    }

    return uncompressed_size;
}

size_t lzma2_get_uncompressed_size(unsigned char *buf, unsigned long size)
{

    int i;
    unsigned char *index;
    xz_header_t *header;
    xz_footer_t *footer;

    if (buf == NULL) {
        return 0;
    }

    header = (xz_header_t *)buf;
    footer = (xz_footer_t *)(buf + size - 12);

    for (i = 0; i < 6; i++) {
        if (header->magic[i] != xz_header_magic[i]) {
            return 0;
        }
    }

    for (i = 0; i < 2; i++) {
        if (footer->magic[i] != xz_footer_magic[i]) {
            return 0;
        }
    }

    i = footer->backward_size;

    index = (unsigned char *)footer - ((i + 1) * 4);

    return lzma2_decode_size(index);
}

void *UncompressOnIop(void *in, int in_size, int *out_size)
{
    int length_rounded = (in_size + 0xF) & ~0xF;
    void *comp_buffer = SifAllocIopHeap(length_rounded);

    CopyToIop(in, in_size, comp_buffer);

    int unc_size = lzma2_get_uncompressed_size(in, in_size);
    length_rounded = (unc_size + 0xF) & ~0xF;
    void *unc_buffer = SifAllocIopHeap(length_rounded);

    lzma2_pkt_t pkt;
    pkt.in = comp_buffer;
    pkt.in_size = in_size;
    pkt.out = unc_buffer;
    pkt.out_size = unc_size;

    *out_size = unc_size;

    DPRINTF("comp %x size %d unc %x size %d\n", comp_buffer, in_size, unc_buffer, unc_size);

    int ret = LoadOPLModule(OPL_MODULE_ID_LZMA2, 0, sizeof(lzma2_pkt_t), (char *)&pkt);
    DPRINTF("ret %d\n", ret);
    SifFreeIopHeap(comp_buffer);

    return unc_buffer;
}
