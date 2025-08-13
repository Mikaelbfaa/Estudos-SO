#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// sistema hibrido - segmentacao + paginacao
#define VIRT_ADDR_BITS 32
#define PAGE_SIZE 4096
#define PAGE_OFFSET_BITS 12
#define SEGMENT_BITS 2
#define VPN_BITS 18

// tipos de segmento no sistema hibrido
typedef enum {
    UNUSED_SEG = 0,
    CODE_SEG = 1, 
    HEAP_SEG = 2,
    STACK_SEG = 3
} segment_type_t;

// entrada da tabela de paginas no sistema hibrido
typedef struct {
    uint8_t valid;        // entrada valida?
    uint8_t present;      // pagina na memoria?
    uint8_t protection;   // permissoes
    uint32_t frame_num;   // numero do frame fisico
} hybrid_page_entry_t;

// registrador de segmento
typedef struct {
    uint32_t base_addr;   // endereco base
    uint32_t limit;       // limite do segmento
    uint8_t is_valid;     // segmento ativo?
} segment_register_t;

// sistema hibrido completo
typedef struct {
    segment_register_t segments[4];          // registradores de segmento
    hybrid_page_entry_t** page_tables;       // tabelas de paginas por segmento
    uint8_t* ram;                            // memoria fisica
    uint32_t ram_size;                       // tamanho da memoria
    uint32_t page_table_memory;              // memoria usada pelas tabelas
    uint32_t translation_count;              // contador de traducoes
    uint32_t seg_fault_count;                // contador de segfaults
} hybrid_system_t;

// sistema multinivel (2 niveis)
#define ML_ADDR_BITS 30
#define ML_PAGE_SIZE 512
#define ML_PAGE_BITS 9
#define ML_VPN_BITS 21
#define ML_ENTRY_SIZE 4
#define ML_ENTRIES_PER_PAGE (ML_PAGE_SIZE / ML_ENTRY_SIZE)

#define PT_INDEX_BITS 7
#define PD_INDEX_BITS 14

#define ML_L3_PT_BITS 7
#define ML_L2_PD_BITS 7
#define ML_L1_PD_BITS 7

// entrada do diretorio de paginas
typedef struct {
    uint8_t valid;     // entrada valida?
    uint32_t pfn;      // numero do frame da tabela
} page_dir_entry_t;

// entrada da tabela de paginas multinivel
typedef struct {
    uint8_t valid;        // entrada valida?
    uint8_t present;      // pagina presente?
    uint8_t protection;   // permissoes
    uint8_t dirty;        // foi modificada?
    uint8_t referenced;   // foi acessada?
    uint32_t pfn;         // numero do frame
} multilevel_entry_t;

// sistema de 2 niveis completo
typedef struct {
    page_dir_entry_t* page_directory;    // diretorio de paginas
    multilevel_entry_t** page_tables;    // tabelas de pagina
    uint32_t num_page_tables;            // quantas tabelas temos
    uint8_t* ram;                        // memoria fisica
    uint32_t ram_size;                   // tamanho da memoria
    uint32_t memory_used;                // memoria usada pelas estruturas
    uint32_t access_count;               // contador de acessos
    uint32_t page_fault_count;           // contador de page faults
} two_level_system_t;

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

// sistema de tabela invertida
#define PHYS_PAGES 1024

// entrada da tabela invertida
typedef struct {
    uint8_t valid;         // entrada valida?
    uint32_t process_id;   // id do processo
    uint32_t virtual_page; // numero da pagina virtual
    uint32_t next_entry;   // proximo na lista de colisao
} inverted_entry_t;

// tabela invertida completa
typedef struct {
    inverted_entry_t table[PHYS_PAGES];  // tabela principal
    uint32_t* hash_table;                 // tabela hash
    uint32_t hash_size;                   // tamanho da hash
    uint32_t lookup_count;                // contador de buscas
    uint32_t collision_count;             // contador de colisoes
} inverted_table_t;

hybrid_system_t* setup_hybrid_system() {
    hybrid_system_t* sys = (hybrid_system_t*)calloc(1, sizeof(hybrid_system_t));

    // configura segmento de codigo
    sys->segments[CODE_SEG].is_valid = 1;
    sys->segments[CODE_SEG].base_addr = 0;
    sys->segments[CODE_SEG].limit = 3;

    // configura heap
    sys->segments[HEAP_SEG].is_valid = 1;
    sys->segments[HEAP_SEG].base_addr = 1000;
    sys->segments[HEAP_SEG].limit = 10;

    // configura stack
    sys->segments[STACK_SEG].is_valid = 1;
    sys->segments[STACK_SEG].base_addr = 2000;
    sys->segments[STACK_SEG].limit = 5;

    // aloca as tabelas de pagina
    sys->page_tables = (hybrid_page_entry_t**)calloc(4, sizeof(hybrid_page_entry_t*));

    for (int seg = 0; seg < 4; seg++) {
        if (sys->segments[seg].is_valid) {
            uint32_t num_pages = sys->segments[seg].limit;
            sys->page_tables[seg] = (hybrid_page_entry_t*)calloc(num_pages, sizeof(hybrid_page_entry_t));
            sys->page_table_memory += num_pages * sizeof(hybrid_page_entry_t);

            // inicializa algumas paginas como exemplo
            for (uint32_t i = 0; i < num_pages && i < 2; i++) {
                sys->page_tables[seg][i].valid = 1;
                sys->page_tables[seg][i].present = 1;
                sys->page_tables[seg][i].frame_num = (seg * 100) + i;
                sys->page_tables[seg][i].protection = 0x7;  // rwx
            }
        }
    }

    printf("Sistema Hibrido inicializado:\n");
    printf("- Memoria usada para tabelas: %u bytes\n", sys->page_table_memory);
    printf("- Economia vs. linear: ~%u bytes\n",
           (1 << VPN_BITS) * sizeof(hybrid_page_entry_t) - sys->page_table_memory);

    return sys;
}

uint32_t do_hybrid_translation(hybrid_system_t* sys, uint32_t virtual_addr) {
    sys->translation_count++;

    uint32_t seg = (virtual_addr >> (VIRT_ADDR_BITS - SEGMENT_BITS)) & 0x3;
    uint32_t vpn = (virtual_addr >> PAGE_OFFSET_BITS) & ((1 << VPN_BITS) - 1);
    uint32_t offset = virtual_addr & ((1 << PAGE_OFFSET_BITS) - 1);

    printf("Hibrido - VA: 0x%08X -> Seg: %u, VPN: %u, Offset: %u\n", virtual_addr, seg, vpn, offset);

    if (!sys->segments[seg].is_valid) {
        printf("  ERRO: Segmento invalido!\n");
        sys->seg_fault_count++;
        return 0xFFFFFFFF;
    }

    if (vpn >= sys->segments[seg].limit) {
        printf("  ERRO: VPN fora dos limites do segmento!\n");
        sys->seg_fault_count++;
        return 0xFFFFFFFF;
    }

    hybrid_page_entry_t* entry = &sys->page_tables[seg][vpn];

    if (!entry->valid) {
        printf("  ERRO: Pagina invalida!\n");
        return 0xFFFFFFFF;
    }

    uint32_t phys_addr = (entry->frame_num << PAGE_OFFSET_BITS) | offset;
    printf("  PA: 0x%08X (Frame: %u)\n", phys_addr, entry->frame_num);

    return phys_addr;
}

two_level_system_t* setup_two_level() {
    two_level_system_t* sys = (two_level_system_t*)calloc(1, sizeof(two_level_system_t));

    uint32_t pd_entries = 1 << PD_INDEX_BITS;
    sys->page_directory = (page_dir_entry_t*)calloc(pd_entries, sizeof(page_dir_entry_t));
    sys->memory_used = pd_entries * sizeof(page_dir_entry_t);

    sys->page_directory[0].valid = 1;
    sys->page_directory[0].pfn = 100;

    sys->page_directory[pd_entries - 1].valid = 1;
    sys->page_directory[pd_entries - 1].pfn = 101;

    sys->num_page_tables = 2;
    sys->page_tables = (multilevel_entry_t**)calloc(pd_entries, sizeof(multilevel_entry_t*));

    sys->page_tables[0] = (multilevel_entry_t*)calloc(ML_ENTRIES_PER_PAGE, sizeof(multilevel_entry_t));
    sys->memory_used += ML_ENTRIES_PER_PAGE * sizeof(multilevel_entry_t);

    sys->page_tables[0][0].valid = 1;
    sys->page_tables[0][0].present = 1;
    sys->page_tables[0][0].pfn = 10;
    sys->page_tables[0][0].protection = 0x5;

    sys->page_tables[0][1].valid = 1;
    sys->page_tables[0][1].present = 1;
    sys->page_tables[0][1].pfn = 23;
    sys->page_tables[0][1].protection = 0x5;

    sys->page_tables[pd_entries - 1] = (multilevel_entry_t*)calloc(ML_ENTRIES_PER_PAGE, sizeof(multilevel_entry_t));
    sys->memory_used += ML_ENTRIES_PER_PAGE * sizeof(multilevel_entry_t);

    sys->page_tables[pd_entries - 1][126].valid = 1;
    sys->page_tables[pd_entries - 1][126].present = 1;
    sys->page_tables[pd_entries - 1][126].pfn = 55;
    sys->page_tables[pd_entries - 1][126].protection = 0x3;

    sys->page_tables[pd_entries - 1][127].valid = 1;
    sys->page_tables[pd_entries - 1][127].present = 1;
    sys->page_tables[pd_entries - 1][127].pfn = 45;
    sys->page_tables[pd_entries - 1][127].protection = 0x3;

    uint32_t linear_size = (1 << ML_VPN_BITS) * sizeof(multilevel_entry_t);
    printf("Sistema Multi-nivel (2 niveis) inicializado:\n");
    printf("- Memoria usada: %u bytes\n", sys->memory_used);
    printf("- Memoria para tabela linear: %u bytes\n", linear_size);
    printf("- Economia: %u bytes (%.2f%%)\n",
           linear_size - sys->memory_used,
           ((float)(linear_size - sys->memory_used) / linear_size) * 100);

    return sys;
}

uint32_t do_two_level_translation(two_level_system_t* sys, uint32_t virtual_addr) {
    sys->access_count++;

    uint32_t vpn = (virtual_addr >> ML_PAGE_BITS) & ((1 << ML_VPN_BITS) - 1);
    uint32_t pd_index = (vpn >> PT_INDEX_BITS) & ((1 << PD_INDEX_BITS) - 1);
    uint32_t pt_index = vpn & ((1 << PT_INDEX_BITS) - 1);
    uint32_t offset = virtual_addr & ((1 << ML_PAGE_BITS) - 1);

    printf("2-Level - VA: 0x%08X\n", virtual_addr);
    printf("  VPN: %u -> PD_Index: %u, PT_Index: %u, Offset: %u\n",
           vpn, pd_index, pt_index, offset);

    page_dir_entry_t* pde = &sys->page_directory[pd_index];
    if (!pde->valid) {
        printf("  ERRO: PDE invalido!\n");
        sys->page_fault_count++;
        return 0xFFFFFFFF;
    }
    printf("  PDE valido, PFN da PT: %u\n", pde->pfn);

    if (!sys->page_tables[pd_index]) {
        printf("  ERRO: Page table nao alocada!\n");
        sys->page_fault_count++;
        return 0xFFFFFFFF;
    }

    multilevel_entry_t* pte = &sys->page_tables[pd_index][pt_index];
    if (!pte->valid) {
        printf("  ERRO: PTE invalido!\n");
        sys->page_fault_count++;
        return 0xFFFFFFFF;
    }

    uint32_t phys_addr = (pte->pfn << ML_PAGE_BITS) | offset;
    printf("  PTE valido, PFN: %u -> PA: 0x%08X\n", pte->pfn, phys_addr);

    return phys_addr;
}

inverted_table_t* setup_inverted_table() {
    inverted_table_t* table = (inverted_table_t*)calloc(1, sizeof(inverted_table_t));

    table->hash_size = PHYS_PAGES / 4;  // hash menor que a tabela
    table->hash_table = (uint32_t*)malloc(table->hash_size * sizeof(uint32_t));

    // inicializa hash table como vazia
    for (uint32_t i = 0; i < table->hash_size; i++) {
        table->hash_table[i] = 0xFFFFFFFF;
    }

    // inicializa entradas da tabela
    for (uint32_t i = 0; i < PHYS_PAGES; i++) {
        table->table[i].valid = 0;
        table->table[i].next_entry = 0xFFFFFFFF;
    }

    // adiciona algumas entradas de exemplo
    uint32_t hash = (1 * 1000 + 0) % table->hash_size;
    table->table[10].valid = 1;
    table->table[10].process_id = 1;
    table->table[10].virtual_page = 0;
    table->table[10].next_entry = table->hash_table[hash];
    table->hash_table[hash] = 10;

    hash = (1 * 1000 + 1) % table->hash_size;
    table->table[20].valid = 1;
    table->table[20].process_id = 1;
    table->table[20].virtual_page = 1;
    table->table[20].next_entry = table->hash_table[hash];
    table->hash_table[hash] = 20;

    hash = (2 * 1000 + 0) % table->hash_size;
    table->table[30].valid = 1;
    table->table[30].process_id = 2;
    table->table[30].virtual_page = 0;
    table->table[30].next_entry = table->hash_table[hash];
    table->hash_table[hash] = 30;

    printf("Tabela Invertida inicializada:\n");
    printf("- Tamanho da tabela: %lu bytes\n",
           sizeof(inverted_entry_t) * PHYS_PAGES);
    printf("- Tamanho da hash table: %lu bytes\n",
           sizeof(uint32_t) * table->hash_size);
    printf("- Total: %lu bytes (independente do numero de processos!)\n",
           sizeof(inverted_entry_t) * PHYS_PAGES + sizeof(uint32_t) * table->hash_size);

    return table;
}

uint32_t inverted_lookup(inverted_table_t* table, uint32_t pid, uint32_t vpn) {
    table->lookup_count++;

    uint32_t hash = (pid * 1000 + vpn) % table->hash_size;
    uint32_t frame = table->hash_table[hash];

    printf("Invertida - PID: %u, VPN: %u\n", pid, vpn);
    printf("  Hash: %u -> Frame inicial: %u\n", hash, frame);

    while (frame != 0xFFFFFFFF) {
        inverted_entry_t* entry = &table->table[frame];

        if (entry->valid && entry->process_id == pid && entry->virtual_page == vpn) {
            printf("  ENCONTRADO no frame %u\n", frame);
            return frame;
        }

        frame = entry->next_entry;
        table->collision_count++;
    }

    printf("  NAO ENCONTRADO\n");
    return 0xFFFFFFFF;
}

void test_hybrid() {
    printf("\n=== TESTE DO SISTEMA HIBRIDO ===\n\n");

    hybrid_system_t* sys = setup_hybrid_system();

    printf("\nTeste de traducoes:\n");

    uint32_t code_addr = 0x40000000;
    do_hybrid_translation(sys, code_addr);

    uint32_t heap_addr = 0x80001000;
    do_hybrid_translation(sys, heap_addr);

    uint32_t stack_addr = 0xC0000000;
    do_hybrid_translation(sys, stack_addr);

    uint32_t invalid_addr = 0x00000000;
    do_hybrid_translation(sys, invalid_addr);

    printf("\nEstatisticas:\n");
    printf("- Total de traducoes: %u\n", sys->translation_count);
    printf("- Falhas de segmentacao: %u\n", sys->seg_fault_count);

    free(sys);
}

void test_two_level() {
    printf("\n=== TESTE DO SISTEMA MULTI-NIVEL (2 NIVEIS) ===\n\n");

    two_level_system_t* sys = setup_two_level();

    printf("\nTeste de traducoes:\n");

    uint32_t addr1 = 0x00000000;
    do_two_level_translation(sys, addr1);

    uint32_t addr2 = 0x3FFFFF00;
    do_two_level_translation(sys, addr2);

    uint32_t addr3 = 0x10000000;
    do_two_level_translation(sys, addr3);

    printf("\nEstatisticas:\n");
    printf("- Total de acessos: %u\n", sys->access_count);
    printf("- Page faults: %u\n", sys->page_fault_count);
    printf("- Memoria economizada: %u bytes\n",
           ((1 << ML_VPN_BITS) * sizeof(multilevel_entry_t)) - sys->memory_used);

    free(sys);
}

void test_inverted() {
    printf("\n=== TESTE DA TABELA INVERTIDA ===\n\n");

    inverted_table_t* table = setup_inverted_table();

    printf("\nTeste de buscas:\n");

    uint32_t frame1 = inverted_lookup(table, 1, 0);
    uint32_t frame2 = inverted_lookup(table, 1, 1);
    uint32_t frame3 = inverted_lookup(table, 2, 0);

    // busca que nao deve encontrar nada
    uint32_t frame4 = inverted_lookup(table, 3, 0);

    printf("\nEstatisticas:\n");
    printf("- Total de buscas: %u\n", table->lookup_count);
    printf("- Colisoes: %u\n", table->collision_count);
    printf("- Taxa de colisao: %.2f%%\n",
           table->lookup_count > 0 ? (float)table->collision_count / table->lookup_count * 100 : 0);

    free(table);
}

int main() {
    printf("DEMONSTRACAO DE TABELAS DE PAGINAS OTIMIZADAS\n");

    test_hybrid();
    test_two_level();
    test_inverted();

    printf("\nCOMPARACAO FINAL\n");

    printf("\n1. SISTEMA HIBRIDO (Segmentacao + Paginacao):\n");
    printf("   - Vantagens: Economiza memoria para espacos esparsos\n");
    printf("   - Desvantagens: Fragmentacao externa, menos flexivel\n");

    printf("\n2. SISTEMA MULTI-NIVEL:\n");
    printf("   - Vantagens: Muito eficiente para espacos esparsos\n");
    printf("   - Desvantagens: Multiplos acessos a memoria em TLB miss\n");

    printf("\n3. TABELA INVERTIDA:\n");
    printf("   - Vantagens: Tamanho fixo independente do num de processos\n");
    printf("   - Desvantagens: Busca mais lenta, dificulta compartilhamento\n");

    return 0;
}