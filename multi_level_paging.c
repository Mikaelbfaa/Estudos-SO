#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define HYBRID_VA_BITS 32
#define HYBRID_PAGE_SIZE 4096
#define HYBRID_PAGE_BITS 12
#define HYBRID_SEG_BITS 2
#define HYBRID_VPN_BITS 18

typedef enum {
    SEG_UNUSED = 0,
    SEG_CODE = 1,
    SEG_HEAP = 2,
    SEG_STACK = 3
} SegmentType;

typedef struct {
    uint8_t valid;
    uint8_t present;
    uint8_t protection;
    uint32_t pfn;
} HybridPTE;

typedef struct {
    uint32_t base;
    uint32_t bounds;
    uint8_t valid;
} SegmentRegister;

typedef struct {
    SegmentRegister segments[4];
    HybridPTE** page_tables;
    uint8_t* physical_memory;
    uint32_t physical_memory_size;
    uint32_t memory_used_for_page_tables;
    uint32_t total_translations;
    uint32_t segmentation_faults;
} HybridSystem;

#define ML_VA_BITS 30
#define ML_PAGE_SIZE 512
#define ML_PAGE_BITS 9
#define ML_VPN_BITS 21
#define ML_PTE_SIZE 4
#define ML_PTES_PER_PAGE (ML_PAGE_SIZE / ML_PTE_SIZE)

#define ML_PT_INDEX_BITS 7
#define ML_PD_INDEX_BITS 14

#define ML_L3_PT_BITS 7
#define ML_L2_PD_BITS 7
#define ML_L1_PD_BITS 7

typedef struct {
    uint8_t valid;
    uint32_t pfn;
} PageDirectoryEntry;

typedef struct {
    uint8_t valid;
    uint8_t present;
    uint8_t protection;
    uint8_t dirty;
    uint8_t referenced;
    uint32_t pfn;
} MultiLevelPTE;

typedef struct {
    PageDirectoryEntry* page_directory;
    MultiLevelPTE** page_tables;
    uint32_t num_page_tables;
    uint8_t* physical_memory;
    uint32_t physical_memory_size;
    uint32_t memory_used;
    uint32_t total_accesses;
    uint32_t page_faults;
} TwoLevelSystem;

typedef struct {
    PageDirectoryEntry* top_level_pd;
    PageDirectoryEntry** second_level_pds;
    MultiLevelPTE*** page_tables;
    uint8_t* physical_memory;
    uint32_t physical_memory_size;
    uint32_t memory_used;
    uint32_t total_accesses;
    uint32_t page_faults;
} ThreeLevelSystem;

#define INV_PHYS_PAGES 1024

typedef struct {
    uint8_t valid;
    uint32_t pid;
    uint32_t vpn;
    uint32_t hash_next;
} InvertedPageTableEntry;

typedef struct {
    InvertedPageTableEntry table[INV_PHYS_PAGES];
    uint32_t* hash_table;
    uint32_t hash_size;
    uint32_t lookups;
    uint32_t collisions;
} InvertedPageTable;

HybridSystem* init_hybrid_system() {
    HybridSystem* sys = (HybridSystem*)calloc(1, sizeof(HybridSystem));

    sys->segments[SEG_CODE].valid = 1;
    sys->segments[SEG_CODE].base = 0;
    sys->segments[SEG_CODE].bounds = 3;

    sys->segments[SEG_HEAP].valid = 1;
    sys->segments[SEG_HEAP].base = 1000;
    sys->segments[SEG_HEAP].bounds = 10;

    sys->segments[SEG_STACK].valid = 1;
    sys->segments[SEG_STACK].base = 2000;
    sys->segments[SEG_STACK].bounds = 5;

    sys->page_tables = (HybridPTE**)calloc(4, sizeof(HybridPTE*));

    for (int seg = 0; seg < 4; seg++) {
        if (sys->segments[seg].valid) {
            uint32_t num_pages = sys->segments[seg].bounds;
            sys->page_tables[seg] = (HybridPTE*)calloc(num_pages, sizeof(HybridPTE));
            sys->memory_used_for_page_tables += num_pages * sizeof(HybridPTE);

            for (uint32_t i = 0; i < num_pages && i < 2; i++) {
                sys->page_tables[seg][i].valid = 1;
                sys->page_tables[seg][i].present = 1;
                sys->page_tables[seg][i].pfn = (seg * 100) + i;
                sys->page_tables[seg][i].protection = 0x7;
            }
        }
    }

    printf("Sistema Híbrido inicializado:\n");
    printf("- Memória usada para tabelas: %u bytes\n", sys->memory_used_for_page_tables);
    printf("- Economia vs. linear: ~%u bytes\n",
           (1 << HYBRID_VPN_BITS) * sizeof(HybridPTE) - sys->memory_used_for_page_tables);

    return sys;
}

uint32_t hybrid_translate(HybridSystem* sys, uint32_t va) {
    sys->total_translations++;

    uint32_t seg = (va >> (HYBRID_VA_BITS - HYBRID_SEG_BITS)) & 0x3;
    uint32_t vpn = (va >> HYBRID_PAGE_BITS) & ((1 << HYBRID_VPN_BITS) - 1);
    uint32_t offset = va & ((1 << HYBRID_PAGE_BITS) - 1);

    printf("Híbrido - VA: 0x%08X -> Seg: %u, VPN: %u, Offset: %u\n", va, seg, vpn, offset);

    if (!sys->segments[seg].valid) {
        printf("  ERRO: Segmento inválido!\n");
        sys->segmentation_faults++;
        return 0xFFFFFFFF;
    }

    if (vpn >= sys->segments[seg].bounds) {
        printf("  ERRO: VPN fora dos limites do segmento!\n");
        sys->segmentation_faults++;
        return 0xFFFFFFFF;
    }

    HybridPTE* pte = &sys->page_tables[seg][vpn];

    if (!pte->valid) {
        printf("  ERRO: Página inválida!\n");
        return 0xFFFFFFFF;
    }

    uint32_t pa = (pte->pfn << HYBRID_PAGE_BITS) | offset;
    printf("  PA: 0x%08X (PFN: %u)\n", pa, pte->pfn);

    return pa;
}

TwoLevelSystem* init_two_level_system() {
    TwoLevelSystem* sys = (TwoLevelSystem*)calloc(1, sizeof(TwoLevelSystem));

    uint32_t pd_entries = 1 << ML_PD_INDEX_BITS;
    sys->page_directory = (PageDirectoryEntry*)calloc(pd_entries, sizeof(PageDirectoryEntry));
    sys->memory_used = pd_entries * sizeof(PageDirectoryEntry);

    sys->page_directory[0].valid = 1;
    sys->page_directory[0].pfn = 100;

    sys->page_directory[pd_entries - 1].valid = 1;
    sys->page_directory[pd_entries - 1].pfn = 101;

    sys->num_page_tables = 2;
    sys->page_tables = (MultiLevelPTE**)calloc(pd_entries, sizeof(MultiLevelPTE*));

    sys->page_tables[0] = (MultiLevelPTE*)calloc(ML_PTES_PER_PAGE, sizeof(MultiLevelPTE));
    sys->memory_used += ML_PTES_PER_PAGE * sizeof(MultiLevelPTE);

    sys->page_tables[0][0].valid = 1;
    sys->page_tables[0][0].present = 1;
    sys->page_tables[0][0].pfn = 10;
    sys->page_tables[0][0].protection = 0x5;

    sys->page_tables[0][1].valid = 1;
    sys->page_tables[0][1].present = 1;
    sys->page_tables[0][1].pfn = 23;
    sys->page_tables[0][1].protection = 0x5;

    sys->page_tables[pd_entries - 1] = (MultiLevelPTE*)calloc(ML_PTES_PER_PAGE, sizeof(MultiLevelPTE));
    sys->memory_used += ML_PTES_PER_PAGE * sizeof(MultiLevelPTE);

    sys->page_tables[pd_entries - 1][126].valid = 1;
    sys->page_tables[pd_entries - 1][126].present = 1;
    sys->page_tables[pd_entries - 1][126].pfn = 55;
    sys->page_tables[pd_entries - 1][126].protection = 0x3;

    sys->page_tables[pd_entries - 1][127].valid = 1;
    sys->page_tables[pd_entries - 1][127].present = 1;
    sys->page_tables[pd_entries - 1][127].pfn = 45;
    sys->page_tables[pd_entries - 1][127].protection = 0x3;

    uint32_t linear_size = (1 << ML_VPN_BITS) * sizeof(MultiLevelPTE);
    printf("Sistema Multi-nível (2 níveis) inicializado:\n");
    printf("- Memória usada: %u bytes\n", sys->memory_used);
    printf("- Memória para tabela linear: %u bytes\n", linear_size);
    printf("- Economia: %u bytes (%.2f%%)\n",
           linear_size - sys->memory_used,
           ((float)(linear_size - sys->memory_used) / linear_size) * 100);

    return sys;
}

uint32_t two_level_translate(TwoLevelSystem* sys, uint32_t va) {
    sys->total_accesses++;

    uint32_t vpn = (va >> ML_PAGE_BITS) & ((1 << ML_VPN_BITS) - 1);
    uint32_t pd_index = (vpn >> ML_PT_INDEX_BITS) & ((1 << ML_PD_INDEX_BITS) - 1);
    uint32_t pt_index = vpn & ((1 << ML_PT_INDEX_BITS) - 1);
    uint32_t offset = va & ((1 << ML_PAGE_BITS) - 1);

    printf("2-Level - VA: 0x%08X\n", va);
    printf("  VPN: %u -> PD_Index: %u, PT_Index: %u, Offset: %u\n",
           vpn, pd_index, pt_index, offset);

    PageDirectoryEntry* pde = &sys->page_directory[pd_index];
    if (!pde->valid) {
        printf("  ERRO: PDE inválido!\n");
        sys->page_faults++;
        return 0xFFFFFFFF;
    }
    printf("  PDE válido, PFN da PT: %u\n", pde->pfn);

    if (!sys->page_tables[pd_index]) {
        printf("  ERRO: Page table não alocada!\n");
        sys->page_faults++;
        return 0xFFFFFFFF;
    }

    MultiLevelPTE* pte = &sys->page_tables[pd_index][pt_index];
    if (!pte->valid) {
        printf("  ERRO: PTE inválido!\n");
        sys->page_faults++;
        return 0xFFFFFFFF;
    }

    uint32_t pa = (pte->pfn << ML_PAGE_BITS) | offset;
    printf("  PTE válido, PFN: %u -> PA: 0x%08X\n", pte->pfn, pa);

    return pa;
}

InvertedPageTable* init_inverted_table() {
    InvertedPageTable* ipt = (InvertedPageTable*)calloc(1, sizeof(InvertedPageTable));

    ipt->hash_size = INV_PHYS_PAGES / 4;
    ipt->hash_table = (uint32_t*)malloc(ipt->hash_size * sizeof(uint32_t));

    for (uint32_t i = 0; i < ipt->hash_size; i++) {
        ipt->hash_table[i] = 0xFFFFFFFF;
    }

    for (uint32_t i = 0; i < INV_PHYS_PAGES; i++) {
        ipt->table[i].valid = 0;
        ipt->table[i].hash_next = 0xFFFFFFFF;
    }

    uint32_t hash = (1 * 1000 + 0) % ipt->hash_size;
    ipt->table[10].valid = 1;
    ipt->table[10].pid = 1;
    ipt->table[10].vpn = 0;
    ipt->table[10].hash_next = ipt->hash_table[hash];
    ipt->hash_table[hash] = 10;

    hash = (1 * 1000 + 1) % ipt->hash_size;
    ipt->table[20].valid = 1;
    ipt->table[20].pid = 1;
    ipt->table[20].vpn = 1;
    ipt->table[20].hash_next = ipt->hash_table[hash];
    ipt->hash_table[hash] = 20;

    hash = (2 * 1000 + 0) % ipt->hash_size;
    ipt->table[30].valid = 1;
    ipt->table[30].pid = 2;
    ipt->table[30].vpn = 0;
    ipt->table[30].hash_next = ipt->hash_table[hash];
    ipt->hash_table[hash] = 30;

    printf("Tabela Invertida inicializada:\n");
    printf("- Tamanho da tabela: %lu bytes\n",
           sizeof(InvertedPageTableEntry) * INV_PHYS_PAGES);
    printf("- Tamanho da hash table: %lu bytes\n",
           sizeof(uint32_t) * ipt->hash_size);
    printf("- Total: %lu bytes (independente do número de processos!)\n",
           sizeof(InvertedPageTableEntry) * INV_PHYS_PAGES + sizeof(uint32_t) * ipt->hash_size);

    return ipt;
}

uint32_t inverted_lookup(InvertedPageTable* ipt, uint32_t pid, uint32_t vpn) {
    ipt->lookups++;

    uint32_t hash = (pid * 1000 + vpn) % ipt->hash_size;
    uint32_t frame = ipt->hash_table[hash];

    printf("Invertida - PID: %u, VPN: %u\n", pid, vpn);
    printf("  Hash: %u -> Frame inicial: %u\n", hash, frame);

    while (frame != 0xFFFFFFFF) {
        InvertedPageTableEntry* entry = &ipt->table[frame];

        if (entry->valid && entry->pid == pid && entry->vpn == vpn) {
            printf("  ENCONTRADO no frame %u\n", frame);
            return frame;
        }

        frame = entry->hash_next;
        ipt->collisions++;
    }

    printf("  NÃO ENCONTRADO\n");
    return 0xFFFFFFFF;
}

void test_hybrid_system() {
    printf("\n=== TESTE DO SISTEMA HÍBRIDO ===\n\n");

    HybridSystem* sys = init_hybrid_system();

    printf("\nTeste de traduções:\n");

    uint32_t code_va = 0x40000000;
    hybrid_translate(sys, code_va);

    uint32_t heap_va = 0x80001000;
    hybrid_translate(sys, heap_va);

    uint32_t stack_va = 0xC0000000;
    hybrid_translate(sys, stack_va);

    uint32_t invalid_va = 0x00000000;
    hybrid_translate(sys, invalid_va);

    printf("\nEstatísticas:\n");
    printf("- Total de traduções: %u\n", sys->total_translations);
    printf("- Falhas de segmentação: %u\n", sys->segmentation_faults);

    free(sys);
}

void test_two_level_system() {
    printf("\n=== TESTE DO SISTEMA MULTI-NÍVEL (2 NÍVEIS) ===\n\n");

    TwoLevelSystem* sys = init_two_level_system();

    printf("\nTeste de traduções:\n");

    uint32_t va1 = 0x00000000;
    two_level_translate(sys, va1);

    uint32_t va2 = 0x3FFFFF00;
    two_level_translate(sys, va2);

    uint32_t va3 = 0x10000000;
    two_level_translate(sys, va3);

    printf("\nEstatísticas:\n");
    printf("- Total de acessos: %u\n", sys->total_accesses);
    printf("- Page faults: %u\n", sys->page_faults);
    printf("- Memória economizada: %u bytes\n",
           ((1 << ML_VPN_BITS) * sizeof(MultiLevelPTE)) - sys->memory_used);

    free(sys);
}

void test_inverted_table() {
    printf("\n=== TESTE DA TABELA INVERTIDA ===\n\n");

    InvertedPageTable* ipt = init_inverted_table();

    printf("\nTeste de buscas:\n");

    uint32_t frame1 = inverted_lookup(ipt, 1, 0);
    uint32_t frame2 = inverted_lookup(ipt, 1, 1);
    uint32_t frame3 = inverted_lookup(ipt, 2, 0);

    uint32_t frame4 = inverted_lookup(ipt, 3, 0);

    printf("\nEstatísticas:\n");
    printf("- Total de buscas: %u\n", ipt->lookups);
    printf("- Colisões: %u\n", ipt->collisions);
    printf("- Taxa de colisão: %.2f%%\n",
           ipt->lookups > 0 ? (float)ipt->collisions / ipt->lookups * 100 : 0);

    free(ipt);
}

int main() {
    printf("DEMONSTRAÇÃO DE TABELAS DE PÁGINAS OTIMIZADAS\n");

    test_hybrid_system();
    test_two_level_system();
    test_inverted_table();

    printf("COMPARAÇÃO FINAL\n");

    printf("\n1. SISTEMA HÍBRIDO (Segmentação + Paginação):\n");
    printf("   - Vantagens: Economiza memória para espaços esparsos\n");
    printf("   - Desvantagens: Fragmentação externa, menos flexível\n");

    printf("\n2. SISTEMA MULTI-NÍVEL:\n");
    printf("   - Vantagens: Muito eficiente para espaços esparsos\n");
    printf("   - Desvantagens: Múltiplos acessos à memória em TLB miss\n");

    printf("\n3. TABELA INVERTIDA:\n");
    printf("   - Vantagens: Tamanho fixo independente do nº de processos\n");
    printf("   - Desvantagens: Busca mais lenta, dificulta compartilhamento\n");

    return 0;
}