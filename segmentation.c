#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_SEGMENTS 3
#define CODE 0
#define HEAP 1
#define STACK 2

#define R 1
#define W 2
#define X 4

typedef struct {
    uint16_t base;
    uint16_t size;
    uint16_t limit;
    uint8_t direction;
    uint8_t prot;
} seg_t;

typedef struct {
    uint8_t *mem;
    uint16_t mem_size;
    uint16_t addr_space;
    seg_t segs[MAX_SEGMENTS];
    uint8_t seg_bits;
} mmu_t;

mmu_t* create_mmu(uint16_t mem_size, uint16_t addr_space) {
    mmu_t *mmu = malloc(sizeof(mmu_t));

    mmu->mem = calloc(mem_size, 1);
    mmu->mem_size = mem_size;
    mmu->addr_space = addr_space;
    mmu->seg_bits = 2;

    int i;
    for (i = 0; i < MAX_SEGMENTS; i++) {
        mmu->segs[i].base = 0;
        mmu->segs[i].size = 0;
        mmu->segs[i].limit = addr_space >> mmu->seg_bits;
        mmu->segs[i].direction = 1;
        mmu->segs[i].prot = R | W;
    }

    mmu->segs[STACK].direction = 0;
    mmu->segs[CODE].prot = R | X;

    return mmu;
}

void setup_segment(mmu_t *mmu, uint8_t id, uint16_t base, uint16_t size, uint8_t prot) {
    if (id >= MAX_SEGMENTS) {
        printf("bad segment id\n");
        return;
    }

    if (base + size > mmu->mem_size) {
        printf("segment too big\n");
        return;
    }

    mmu->segs[id].base = base;
    mmu->segs[id].size = size;
    mmu->segs[id].prot = prot;
}

uint8_t which_segment(mmu_t *mmu, uint16_t vaddr) {
    uint8_t bits = 0;
    uint16_t tmp = mmu->addr_space - 1;
    while (tmp > 0) {
        bits++;
        tmp >>= 1;
    }

    return vaddr >> (bits - mmu->seg_bits);
}

uint16_t get_offset(mmu_t *mmu, uint16_t vaddr) {
    uint8_t bits = 0;
    uint16_t tmp = mmu->addr_space - 1;
    while (tmp > 0) {
        bits++;
        tmp >>= 1;
    }

    uint16_t mask = (1 << (bits - mmu->seg_bits)) - 1;
    return vaddr & mask;
}

int translate(mmu_t *mmu, uint16_t vaddr, uint16_t *paddr, uint8_t op) {
    uint8_t seg_id = which_segment(mmu, vaddr);
    uint16_t offset = get_offset(mmu, vaddr);

    printf("virtual 0x%x -> seg %d, offset %d\n", vaddr, seg_id, offset);

    if (seg_id >= MAX_SEGMENTS) {
        printf("invalid segment\n");
        return -1;
    }

    seg_t *seg = &mmu->segs[seg_id];

    if (!(seg->prot & op)) {
        printf("protection fault\n");
        return -1;
    }

    uint16_t real_offset;

    if (seg->direction) {
        real_offset = offset;
        if (offset >= seg->size) {
            printf("segfault: %d >= %d\n", offset, seg->size);
            return -1;
        }
    } else {
        if (offset >= seg->size) {
            printf("stack overflow\n");
            return -1;
        }
        real_offset = seg->limit - offset - 1;
    }

    *paddr = seg->base + real_offset;

    if (*paddr >= mmu->mem_size) {
        printf("physical address out of bounds\n");
        return -1;
    }

    printf("physical 0x%x\n", *paddr);
    return 0;
}

int write_byte(mmu_t *mmu, uint16_t vaddr, uint8_t val) {
    uint16_t paddr;
    if (translate(mmu, vaddr, &paddr, W) != 0) {
        return -1;
    }

    mmu->mem[paddr] = val;
    printf("wrote 0x%02x to 0x%x\n", val, paddr);
    return 0;
}

int read_byte(mmu_t *mmu, uint16_t vaddr, uint8_t *val) {
    uint16_t paddr;
    if (translate(mmu, vaddr, &paddr, R) != 0) {
        return -1;
    }

    *val = mmu->mem[paddr];
    printf("read 0x%02x from 0x%x\n", *val, paddr);
    return 0;
}

void write_bytes(mmu_t *mmu, uint16_t addr, uint8_t *data, uint16_t len) {
    printf("\nwriting %d bytes at 0x%x\n", len, addr);

    uint16_t i;
    for (i = 0; i < len; i++) {
        if (write_byte(mmu, addr + i, data[i]) != 0) {
            printf("failed at byte %d\n", i);
            return;
        }
    }
}

void read_bytes(mmu_t *mmu, uint16_t addr, uint16_t len) {
    printf("\nreading %d bytes from 0x%x: ", len, addr);

    uint16_t i;
    for (i = 0; i < len; i++) {
        uint8_t val;
        if (read_byte(mmu, addr + i, &val) == 0) {
            printf("%02x ", val);
        } else {
            printf("?? ");
            break;
        }
    }
    printf("\n");
}

void show_segments(mmu_t *mmu) {
    char *names[] = {"CODE", "HEAP", "STACK"};
    char *perms[] = {"---", "r--", "-w-", "rw-", "--x", "r-x", "-wx", "rwx"};

    printf("\nSegments:\n");
    printf("name     base  size  limit dir perm\n");
    printf("-------- ----- ----- ----- --- ----\n");

    int i;
    for (i = 0; i < MAX_SEGMENTS; i++) {
        printf("%-8s %5d %5d %5d  %c  %s\n",
               names[i],
               mmu->segs[i].base,
               mmu->segs[i].size,
               mmu->segs[i].limit,
               mmu->segs[i].direction ? '+' : '-',
               perms[mmu->segs[i].prot]);
    }
    printf("\n");
}

void dump_mem(mmu_t *mmu, uint16_t start, uint16_t len) {
    printf("memory dump 0x%04x-0x%04x:\n", start, start + len - 1);

    uint16_t i;
    for (i = 0; i < len; i += 16) {
        printf("%04x: ", start + i);

        uint16_t j;
        for (j = 0; j < 16 && (i + j) < len; j++) {
            if (start + i + j < mmu->mem_size) {
                printf("%02x ", mmu->mem[start + i + j]);
            } else {
                printf("?? ");
            }
        }

        printf("| ");

        for (j = 0; j < 16 && (i + j) < len; j++) {
            if (start + i + j < mmu->mem_size) {
                uint8_t b = mmu->mem[start + i + j];
                printf("%c", (b >= 32 && b <= 126) ? b : '.');
            } else {
                printf("?");
            }
        }
        printf("\n");
    }
    printf("\n");
}

void test_segmentation() {
    printf("Memory Segmentation Simulator\n");
    printf("============================\n\n");

    mmu_t *mmu = create_mmu(1024, 256);

    setup_segment(mmu, CODE, 512, 64, R | X);
    setup_segment(mmu, HEAP, 576, 96, R | W);
    setup_segment(mmu, STACK, 448, 64, R | W);

    show_segments(mmu);

    printf("Running tests...\n\n");

    printf("Test 1: write to heap\n");
    uint8_t msg[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00};
    write_bytes(mmu, 64, msg, 6);

    printf("\nTest 2: read from heap\n");
    read_bytes(mmu, 64, 6);

    printf("\nTest 3: write to stack\n");
    uint8_t stack_data[] = {0xde, 0xad, 0xbe, 0xef};
    write_bytes(mmu, 252, stack_data, 4);

    printf("\nTest 4: try to write to code (should fail)\n");
    uint8_t code[] = {0x90, 0x90};
    write_bytes(mmu, 0, code, 2);

    printf("\nTest 5: access out of bounds (should fail)\n");
    uint8_t dummy;
    read_byte(mmu, 200, &dummy);

    dump_mem(mmu, 440, 80);
    dump_mem(mmu, 570, 80);

    free(mmu->mem);
    free(mmu);
}

int main() {
    test_segmentation();
    return 0;
}