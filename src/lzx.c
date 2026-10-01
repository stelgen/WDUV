// lzx.c — LZX decompressor ported from libmspack (mspack/lzxd.c, LGPL-2.1,
// Stuart Caie) to C. See docs/ANALYSIS.md for the design notes; this port is
// verified byte-for-byte against cabextract on real Microsoft packages.
#include "lzx.h"
#include "pe.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LZX_NUM_CHARS            256
#define LZX_NUM_PRIMARY_LENGTHS  7
#define LZX_NUM_SECONDARY_LENGTHS 249
#define LZX_MIN_MATCH            2
#define LZX_FRAME_SIZE           32768
#define LZX_MAX_CODE_LENGTH      16

#define BLOCK_VERBATIM     1
#define BLOCK_ALIGNED      2
#define BLOCK_UNCOMPRESSED 3

static const int position_slots[11] = { 30, 32, 34, 36, 38, 42, 50, 66, 98, 162, 290 };
static const uint8_t extra_bits_tab[36] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14,
    15, 15, 16, 16
};
static const uint32_t position_base[290] = {
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512,
    768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768,
    49152, 65536, 98304, 131072, 196608, 262144, 393216, 524288, 655360,
    786432, 917504, 1048576, 1179648, 1310720, 1441792, 1572864, 1703936,
    1835008, 1966080, 2097152, 2228224, 2359296, 2490368, 2621440, 2752512,
    2883584, 3014656, 3145728, 3276800, 3407872, 3538944, 3670016, 3801088,
    3932160, 4063232, 4194304, 4325376, 4456448, 4587520, 4718592, 4849664,
    4980736, 5111808, 5242880, 5373952, 5505024, 5636096, 5767168, 5898240,
    6029312, 6160384, 6291456, 6422528, 6553600, 6684672, 6815744, 6946816,
    7077888, 7208960, 7340032, 7471104, 7602176, 7733248, 7864320, 7995392,
    8126464, 8257536, 8388608, 8519680, 8650752, 8781824, 8912896, 9043968,
    9175040, 9306112, 9437184, 9568256, 9699328, 9830400, 9961472, 10092544,
    10223616, 10354688, 10485760, 10616832, 10747904, 10878976, 11010048,
    11141120, 11272192, 11403264, 11534336, 11665408, 11796480, 11927552,
    12058624, 12189696, 12320768, 12451840, 12582912, 12713984, 12845056,
    12976128, 13107200, 13238272, 13369344, 13500416, 13631488, 13762560,
    13893632, 14024704, 14155776, 14286848, 14417920, 14548992, 14680064,
    14811136, 14942208, 15073280, 15204352, 15335424, 15466496, 15597568,
    15728640, 15859712, 15990784, 16121856, 16252928, 16384000, 16515072,
    16646144, 16777216, 16908288, 17039360, 17170432, 17301504, 17432576,
    17563648, 17694720, 17825792, 17956864, 18087936, 18219008, 18350080,
    18481152, 18612224, 18743296, 18874368, 19005440, 19136512, 19267584,
    19398656, 19529728, 19660800, 19791872, 19922944, 20054016, 20185088,
    20316160, 20447232, 20578304, 20709376, 20840448, 20971520, 21102592,
    21233664, 21364736, 21495808, 21626880, 21757952, 21889024, 22020096,
    22151168, 22282240, 22413312, 22544384, 22675456, 22806528, 22937600,
    23068672, 23199744, 23330816, 23461888, 23592960, 23724032, 23855104,
    23986176, 24117248, 24248320, 24379392, 24510464, 24641536, 24772608,
    24903680, 25034752, 25165824, 25296896, 25427968, 25559040, 25690112,
    25821184, 25952256, 26083328, 26214400, 26345472, 26476544, 26607616,
    26738688, 26869760, 27000832, 27131904, 27262976, 27394048, 27525120,
    27656192, 27787264, 27918336, 28049408, 28180480, 28311552, 28442624,
    28573696, 28704768, 28835840, 28966912, 29097984, 29229056, 29360128,
    29491200, 29622272, 29753344, 29884416, 30015488, 30146560, 30277632,
    30408704, 30539776, 30670848, 30801920, 30932992, 31064064, 31195136,
    31326208, 31457280, 31588352, 31719424, 31850496, 31981568, 32112640,
    32243712, 32374784, 32505856, 32636928, 32768000, 32899072, 33030144,
    33161216, 33292288, 33423360
};

// input provider: byte-at-a-time over an abstract reader
struct lzx_decoder {
    lzx_in   in;
    lzx_out  out;
    uint32_t bb;
    int      bl;
    int      fake_eof;

    int      num_offsets;
    int      max_syms; // 256 + num_offsets (readLens bound)

    uint8_t *window;
    int      window_size;
    int      window_posn;
    int      frame_posn;
    int64_t  frame;
    int64_t  offset;
    int64_t  length;
    uint32_t r0, r1, r2;
    int      header_read;
    int64_t  intel_size;
    int      intel_start;
    int      block_type;
    int      block_remain;
    int      block_len;
    int      len_empty;

    uint8_t  mlens[256 + 290 * 8];
    uint16_t *mtab;
    uint8_t  llens[LZX_NUM_SECONDARY_LENGTHS + 1];
    uint16_t *ltab;
    uint8_t  plens[20];
    uint16_t *ptab;
    uint8_t  alens[8];
    uint16_t *atab;

    uint8_t e8buf[LZX_FRAME_SIZE];
};

lzx_decoder *lzx_new(int window_bits) {
    if (window_bits < 15 || window_bits > 21) return NULL;
    int slots = position_slots[window_bits - 15];
    lzx_decoder *d = xcalloc(1, sizeof(*d));
    d->num_offsets = slots * 8;
    d->max_syms = LZX_NUM_CHARS + d->num_offsets;
    d->window_size = 1 << window_bits;
    d->window = xmalloc((size_t)d->window_size);
    d->r0 = d->r1 = d->r2 = 1;
    d->block_type = -1;
    d->mtab = xmalloc(sizeof(uint16_t) * ((1 << 12) + 2 * sizeof(d->mlens)));
    d->ltab = xmalloc(sizeof(uint16_t) * ((1 << 12) + 2 * sizeof(d->llens)));
    d->ptab = xmalloc(sizeof(uint16_t) * ((1 << 6) + 2 * sizeof(d->plens)));
    d->atab = xmalloc(sizeof(uint16_t) * ((1 << 7) + 2 * sizeof(d->alens)));
    return d;
}

void lzx_free(lzx_decoder *d) {
    if (!d) return;
    free(d->window);
    free(d->mtab);
    free(d->ltab);
    free(d->ptab);
    free(d->atab);
    free(d);
}

static const char *ERR_INPUT = "lzx: out of input";

static int ensure(lzx_decoder *d, int n) {
    while (d->bl < n) {
        int b0 = d->in.read_byte(d->in.ud);
        int fake = 0;
        if (b0 < 0) {
            if (d->fake_eof) return -1;
            d->fake_eof = 1;
            fake = 1;
            b0 = 0;
        }
        int b1 = d->in.read_byte(d->in.ud);
        if (b1 < 0) {
            if (fake || !d->fake_eof) {
                if (!fake) d->fake_eof = 1;
                b1 = 0;
            } else {
                return -1;
            }
        }
        d->bb |= (uint32_t)((b1 << 8) | b0) << (16 - d->bl);
        d->bl += 16;
    }
    (void)ERR_INPUT;
    return 0;
}

static uint32_t peek(lzx_decoder *d, int n) { return d->bb >> (32 - n); }
static void remove_bits(lzx_decoder *d, int n) { d->bb <<= n; d->bl -= n; }

static int read_bits(lzx_decoder *d, int n, uint32_t *out) {
    if (ensure(d, n) != 0) return -1;
    *out = peek(d, n);
    remove_bits(d, n);
    return 0;
}

// canonical huffman table builder (MSB-first variant, readhuff.h)
static int make_decode_table(int nsyms, int nbits, const uint8_t *lens, uint16_t *table, size_t table_cap) {
    size_t table_mask = (size_t)1 << nbits;
    size_t bit_mask = table_mask >> 1;
    size_t pos = 0;
    for (int bit_num = 1; bit_num <= nbits; bit_num++) {
        for (int sym = 0; sym < nsyms; sym++) {
            if (lens[sym] != bit_num) continue;
            size_t leaf = pos;
            pos += bit_mask;
            if (pos > table_mask) return 0;
            if (leaf + bit_mask > table_cap) return 0;
            for (size_t f = 0; f < bit_mask; f++) table[leaf + f] = (uint16_t)sym;
        }
        bit_mask >>= 1;
    }
    if (pos == table_mask) return 1;
    for (size_t sym = pos; sym < table_mask; sym++) table[sym] = 0xFFFF;
    size_t next_symbol = table_mask >> 1;
    if ((size_t)nsyms > next_symbol) next_symbol = (size_t)nsyms;
    pos <<= 16;
    table_mask <<= 16;
    bit_mask = (size_t)1 << 15;
    for (int bit_num = nbits + 1; bit_num <= LZX_MAX_CODE_LENGTH; bit_num++) {
        for (int sym = 0; sym < nsyms; sym++) {
            if (lens[sym] != bit_num) continue;
            if (pos >= table_mask) return 0;
            size_t leaf = pos >> 16;
            for (int f = 0; f < bit_num - nbits; f++) {
                if (table[leaf] == 0xFFFF) {
                    if ((size_t)(next_symbol << 1) + 1 >= table_cap) return 0;
                    table[next_symbol << 1] = 0xFFFF;
                    table[(next_symbol << 1) + 1] = 0xFFFF;
                    table[leaf] = (uint16_t)next_symbol;
                    next_symbol++;
                }
                leaf = (size_t)table[leaf] << 1;
                if ((pos >> (15 - f)) & 1) leaf++;
            }
            if (leaf >= table_cap) return 0;
            table[leaf] = (uint16_t)sym;
            pos += bit_mask;
        }
        bit_mask >>= 1;
    }
    return pos == table_mask;
}

static int read_sym(lzx_decoder *d, const uint16_t *table, size_t table_cap,
                    int tab_bits, const uint8_t *lens, int max_syms, int *sym_out) {
    if (ensure(d, LZX_MAX_CODE_LENGTH) != 0) return -1;
    uint16_t sym = table[peek(d, tab_bits)];
    if (sym >= (uint16_t)max_syms) {
        if (sym == 0xFFFF) return -1;
        uint32_t mask = (uint32_t)1 << (32 - tab_bits);
        for (;;) {
            mask >>= 1;
            if (!mask) return -1;
            uint32_t bit = (d->bb & mask) ? 1 : 0;
            size_t idx = ((size_t)sym << 1) | bit;
            if (idx >= table_cap) return -1;
            sym = table[idx];
            if (sym < (uint16_t)max_syms) break;
        }
    }
    int ln = lens[sym];
    if (ln == 0) return -1;
    remove_bits(d, ln);
    *sym_out = sym;
    return 0;
}

static int read_lens(lzx_decoder *d, uint8_t *lens, int first, int last) {
    for (int x = 0; x < 20; x++) {
        uint32_t v;
        if (read_bits(d, 4, &v) != 0) return -1;
        d->plens[x] = (uint8_t)v;
    }
    if (!make_decode_table(20, 6, d->plens, d->ptab, (1 << 6) + 2 * sizeof(d->plens))) return -1;
    int x = first;
    while (x < last) {
        int z;
        if (read_sym(d, d->ptab, (1 << 6) + 2 * sizeof(d->plens), 6, d->plens, 20, &z) != 0) return -1;
        if (z == 17) {
            uint32_t y;
            if (read_bits(d, 4, &y) != 0) return -1;
            y += 4;
            if (x + (int)y > last) return -1;
            while (y--) lens[x++] = 0;
        } else if (z == 18) {
            uint32_t y;
            if (read_bits(d, 5, &y) != 0) return -1;
            y += 20;
            if (x + (int)y > last) return -1;
            while (y--) lens[x++] = 0;
        } else if (z == 19) {
            uint32_t y;
            if (read_bits(d, 1, &y) != 0) return -1;
            y += 4;
            int z2;
            if (read_sym(d, d->ptab, (1 << 6) + 2 * sizeof(d->plens), 6, d->plens, 20, &z2) != 0) return -1;
            int nz = (int)lens[x] - z2;
            if (nz < 0) nz += 17;
            if (x + (int)y > last) return -1;
            while (y--) lens[x++] = (uint8_t)nz;
        } else {
            int nz = (int)lens[x] - z;
            if (nz < 0) nz += 17;
            lens[x++] = (uint8_t)nz;
        }
    }
    return 0;
}

static int start_block(lzx_decoder *d) {
    if (d->block_type == BLOCK_UNCOMPRESSED && (d->block_len & 1)) {
        if (d->in.read_byte(d->in.ud) < 0) return -1;
    }
    uint32_t t, hi, lo;
    if (read_bits(d, 3, &t) != 0) return -1;
    if (read_bits(d, 16, &hi) != 0) return -1;
    if (read_bits(d, 8, &lo) != 0) return -1;
    d->block_len = (int)((hi << 8) | lo);
    d->block_remain = d->block_len;
    if (getenv("VDU_DBG")) fprintf(stderr, "DBG startBlock type=%d len=%d bl=%d\n", (int)t, d->block_len, d->bl);
    if (t == BLOCK_ALIGNED) {
        for (int i = 0; i < 8; i++) {
            uint32_t v;
            if (read_bits(d, 3, &v) != 0) return -1;
            d->alens[i] = (uint8_t)v;
        }
        if (!make_decode_table(8, 7, d->alens, d->atab, (1 << 7) + 2 * sizeof(d->alens))) return -1;
        t = BLOCK_ALIGNED;
        // fallthrough to verbatim header below
    }
    if (t == BLOCK_VERBATIM || t == BLOCK_ALIGNED) {
        if (read_lens(d, d->mlens, 0, LZX_NUM_CHARS) != 0) return -1;
        if (read_lens(d, d->mlens, LZX_NUM_CHARS, d->max_syms) != 0) return -1;
        if (!make_decode_table((int)sizeof(d->mlens), 12, d->mlens, d->mtab, (1 << 12) + 2 * sizeof(d->mlens))) return -1;
        if (d->mlens[0xE8] != 0) d->intel_start = 1;
        if (read_lens(d, d->llens, 0, LZX_NUM_SECONDARY_LENGTHS) != 0) return -1;
        d->len_empty = 0;
        if (!make_decode_table((int)sizeof(d->llens), 12, d->llens, d->ltab, (1 << 12) + 2 * sizeof(d->llens))) {
            int empty = 1;
            for (size_t i = 0; i < sizeof(d->llens); i++)
                if (d->llens[i] != 0) { empty = 0; break; }
            if (!empty) return -1;
            d->len_empty = 1;
        }
    } else if (t == BLOCK_UNCOMPRESSED) {
        d->intel_start = 1;
        if (d->bl == 0) { if (ensure(d, 16) != 0) return -1; }
        d->bl = 0;
        d->bb = 0;
        uint8_t buf[12];
        for (int i = 0; i < 12; i++) {
            int b = d->in.read_byte(d->in.ud);
            if (b < 0) return -1;
            buf[i] = (uint8_t)b;
        }
        d->r0 = vdu_le32(buf, 0);
        d->r1 = vdu_le32(buf, 4);
        d->r2 = vdu_le32(buf, 8);
    } else {
        return -1;
    }
    d->block_type = (int)t;
    return 0;
}

static int decode_compressed(lzx_decoder *d, int64_t this_run) {
    while (this_run > 0) {
        int main_element;
        if (read_sym(d, d->mtab, (1 << 12) + 2 * sizeof(d->mlens), 12, d->mlens, (int)sizeof(d->mlens), &main_element) != 0)
            return -1;
        if (getenv("VDU_DBG") && d->window_posn < 12)
            fprintf(stderr, "DBG sym=%d winPos=%d bl=%d\n", main_element, d->window_posn, d->bl);
        if (main_element < LZX_NUM_CHARS) {
            d->window[d->window_posn++] = (uint8_t)main_element;
            this_run--;
            continue;
        }
        int e = main_element - LZX_NUM_CHARS;
        int match_length = e & LZX_NUM_PRIMARY_LENGTHS;
        if (match_length == LZX_NUM_PRIMARY_LENGTHS) {
            if (d->len_empty) return -1;
            int footer;
            if (read_sym(d, d->ltab, (1 << 12) + 2 * sizeof(d->llens), 12, d->llens, (int)sizeof(d->llens), &footer) != 0)
                return -1;
            match_length += footer;
        }
        match_length += LZX_MIN_MATCH;

        int slot = e >> 3;
        uint32_t match_offset;
        if (slot == 0) {
            match_offset = d->r0;
        } else if (slot == 1) {
            match_offset = d->r1;
            d->r1 = d->r0;
            d->r0 = match_offset;
        } else if (slot == 2) {
            match_offset = d->r2;
            d->r2 = d->r0;
            d->r0 = match_offset;
        } else {
            int extra = (slot < 36) ? extra_bits_tab[slot] : 17;
            match_offset = position_base[slot] - 2;
            if (extra >= 3 && d->block_type == BLOCK_ALIGNED) {
                if (extra > 3) {
                    uint32_t vb;
                    if (read_bits(d, extra - 3, &vb) != 0) return -1;
                    match_offset += vb << 3;
                }
                int ab;
                if (read_sym(d, d->atab, (1 << 7) + 2 * sizeof(d->alens), 7, d->alens, 8, &ab) != 0) return -1;
                match_offset += (uint32_t)ab;
            } else if (extra > 0) {
                uint32_t vb;
                if (read_bits(d, extra, &vb) != 0) return -1;
                match_offset += vb;
            }
            d->r2 = d->r1;
            d->r1 = d->r0;
            d->r0 = match_offset;
        }

        if (d->window_posn + match_length > d->window_size) return -1;
        int i = match_length;
        if (match_offset > (uint32_t)d->window_posn) {
            if ((int64_t)match_offset > d->offset) return -1; // no reference data in plain LZX
            int j = (int)(match_offset - (uint32_t)d->window_posn);
            if (j > d->window_size) return -1;
            int runsrc = d->window_size - j;
            if (j < i) {
                i -= j;
                for (int k = 0; k < j; k++) d->window[d->window_posn + k] = d->window[runsrc + k];
                d->window_posn += j;
                runsrc = 0;
            }
            for (int k = 0; k < i; k++) d->window[d->window_posn + k] = d->window[runsrc + k];
            d->window_posn += i;
        } else {
            int runsrc = d->window_posn - (int)match_offset;
            for (int k = 0; k < i; k++) d->window[d->window_posn + k] = d->window[runsrc + k];
            d->window_posn += i;
        }
        this_run -= match_length;
    }
    if (this_run < 0) {
        if (-this_run > d->block_remain) return -1;
        d->block_remain -= (int)(-this_run);
    }
    return 0;
}

static void translate_frame(lzx_decoder *d, int frame_size) {
    memcpy(d->e8buf, d->window + d->frame_posn, (size_t)frame_size);
    int32_t curpos = (int32_t)d->offset;
    int32_t filesize = (int32_t)d->intel_size;
    int p = 0, end = frame_size - 10;
    while (p < end) {
        if (d->e8buf[p] != 0xE8) { p++; curpos++; continue; }
        int32_t abs_off = (int32_t)vdu_le32(d->e8buf, p + 1);
        if (abs_off >= -curpos && abs_off < filesize) {
            int32_t rel = (abs_off >= 0) ? abs_off - curpos : abs_off + filesize;
            d->e8buf[p + 1] = (uint8_t)rel;
            d->e8buf[p + 2] = (uint8_t)(rel >> 8);
            d->e8buf[p + 3] = (uint8_t)(rel >> 16);
            d->e8buf[p + 4] = (uint8_t)(rel >> 24);
        }
        p += 5;
        curpos += 5;
    }
}

void lzx_set_io(lzx_decoder *d, lzx_in in) { d->in = in; }

int vdu_read_bits(lzx_decoder *d, int n, uint32_t *out) { return read_bits(d, n, out); }
int vdu_read_sym(lzx_decoder *d, const uint16_t *table, size_t table_cap,
                 int tab_bits, const uint8_t *lens, int max_syms, int *sym_out) {
    return read_sym(d, table, table_cap, tab_bits, lens, max_syms, sym_out);
}
int vdu_read_lens(lzx_decoder *d, uint8_t *lens, int first, int last) {
    return read_lens(d, lens, first, last);
}
int vdu_make_decode_table(int nsyms, int nbits, const uint8_t *lens, uint16_t *table, size_t cap) {
    return make_decode_table(nsyms, nbits, lens, table, cap) ? 1 : 0;
}

int lzx_decompress(lzx_decoder *d, lzx_in in, lzx_out out, int64_t total) {
    d->in = in;
    d->out = out;
    if (d->length == 0 && total > 0) d->length = total;
    if (total < 0) return -1;
    if (total == 0) return 0;

    int64_t out_remaining = total;
    int64_t end_frame = (d->offset + total) / LZX_FRAME_SIZE + 1;

    while (d->frame < end_frame) {
        if (!d->header_read) {
            uint32_t i;
            if (read_bits(d, 1, &i) != 0) return -1;
            uint32_t lo = 0, hi = 0;
            if (i == 1) {
                if (read_bits(d, 16, &lo) != 0) return -1;
                if (read_bits(d, 16, &hi) != 0) return -1;
            }
            d->intel_size = (int64_t)((lo << 16) | hi);
            d->header_read = 1;
        }
        int64_t frame_size = LZX_FRAME_SIZE;
        if (d->length != 0 && d->length - d->offset < frame_size)
            frame_size = d->length - d->offset;

        int64_t bytes_todo = (int64_t)d->frame_posn + frame_size - (int64_t)d->window_posn;
        while (bytes_todo > 0) {
            if (d->block_remain == 0) {
                if (start_block(d) != 0) return -1;
            }
            int64_t this_run = d->block_remain;
            if (this_run > bytes_todo) this_run = bytes_todo;
            bytes_todo -= this_run;
            d->block_remain -= (int)this_run;
            if (d->block_type == BLOCK_VERBATIM || d->block_type == BLOCK_ALIGNED) {
                if (decode_compressed(d, this_run) != 0) return -1;
            } else if (d->block_type == BLOCK_UNCOMPRESSED) {
                int n = (int)this_run;
                if (d->window_posn + n > d->window_size) return -1;
                for (int k = 0; k < n; k++) {
                    int b = d->in.read_byte(d->in.ud);
                    if (b < 0) return -1;
                    d->window[d->window_posn + k] = (uint8_t)b;
                }
                d->window_posn += n;
                d->intel_start = 1;
            } else {
                return -1;
            }
        }
        if ((int64_t)(d->window_posn - d->frame_posn) != frame_size) return -1;

        if (d->bl > 0) { if (ensure(d, 16) != 0) return -1; }
        if (d->bl & 15) remove_bits(d, d->bl & 15);

        int fsz = (int)frame_size;
        const uint8_t *src = d->window + d->frame_posn;
        if (d->intel_start && d->intel_size != 0 && d->frame < 32768 && fsz > 10) {
            translate_frame(d, fsz);
            src = d->e8buf;
        }
        int64_t n = out_remaining < frame_size ? out_remaining : frame_size;
        if (out.write(out.ud, src, (size_t)n) != 0) return -1;
        d->offset += n;
        out_remaining -= n;
        d->frame_posn += fsz;
        d->frame++;
        if (d->window_posn == d->window_size) d->window_posn = 0;
        if (d->frame_posn == d->window_size) d->frame_posn = 0;
    }
    return out_remaining == 0 ? 0 : -1;
}
