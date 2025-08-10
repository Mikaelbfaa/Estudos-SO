#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define VIRTUAL_ADDRESS_BITS 14
#define PAGE_SIZE_BITS 6
#define PAGE_SIZE (1 << PAGE_SIZE_BITS)
#define NUM_VIRTUAL_PAGES (1 << (VIRTUAL_ADDRESS_BITS - PAGE_SIZE_BITS))
#define PHYSICAL_MEMORY_SIZE 8192
#define NUM_PHYSICAL_FRAMES (PHYSICAL_MEMORY_SIZE / PAGE_SIZE)

typedef struct {
    uint8_t valid;
    uint8_t present;
    uint8_t dirty;
    uint8_t referenced;
    uint8_t protection;
    uint16_t pfn;
} PageTableEntry;

typedef struct {
    uint8_t physical_memory[PHYSICAL_MEMORY_SIZE];
    PageTableEntry page_table[NUM_VIRTUAL_PAGES];
    uint16_t page_table_base_register;
    uint32_t num_translations;
    uint32_t num_page_faults;
} MemorySystem;

MemorySystem* init_memory_system() {
    MemorySystem* sys = (MemorySystem*)calloc(1, sizeof(MemorySystem));
    if (!sys) {
        printf("Erro ao alocar memória\n");
        exit(1);
    }
    
    for (int i = 0; i < NUM_VIRTUAL_PAGES; i++) {
        sys->page_table[i].valid = 0;
        sys->page_table[i].present = 0;
        sys->page_table[i].pfn = 0;
    }
    
    sys->page_table[0].valid = 1;
    sys->page_table[0].present = 1;
    sys->page_table[0].protection = 0x5;
    sys->page_table[0].pfn = 3;
    
    sys->page_table[1].valid = 1;
    sys->page_table[1].present = 1;
    sys->page_table[1].protection = 0x5;
    sys->page_table[1].pfn = 7;
    
    sys->page_table[4].valid = 1;
    sys->page_table[4].present = 1;
    sys->page_table[4].protection = 0x3;
    sys->page_table[4].pfn = 5;
    
    sys->page_table[254].valid = 1;
    sys->page_table[254].present = 1;
    sys->page_table[254].protection = 0x3;
    sys->page_table[254].pfn = 2;
    
    sys->page_table[255].valid = 1;
    sys->page_table[255].present = 1;
    sys->page_table[255].protection = 0x3;
    sys->page_table[255].pfn = 6;
    
    return sys;
}

uint16_t get_vpn(uint16_t virtual_address) {
    return (virtual_address >> PAGE_SIZE_BITS) & ((1 << (VIRTUAL_ADDRESS_BITS - PAGE_SIZE_BITS)) - 1);
}

uint16_t get_offset(uint16_t virtual_address) {
    return virtual_address & ((1 << PAGE_SIZE_BITS) - 1);
}

uint16_t translate_address(MemorySystem* sys, uint16_t virtual_address) {
    sys->num_translations++;
    
    uint16_t vpn = get_vpn(virtual_address);
    uint16_t offset = get_offset(virtual_address);
    
    printf("Traducao: VA=0x%04X -> VPN=%d, Offset=%d\n", 
           virtual_address, vpn, offset);
    
    if (vpn >= NUM_VIRTUAL_PAGES) {
        printf("ERRO: VPN fora dos limites\n");
        return 0xFFFF;
    }
    
    PageTableEntry* pte = &sys->page_table[vpn];
    
    if (!pte->valid) {
        printf("ERRO: Pagina nao valida (SEGMENTATION_FAULT)\n");
        sys->num_page_faults++;
        return 0xFFFF;
    }
    
    if (!pte->present) {
        printf("ERRO: Pagina nao presente (PAGE_FAULT)\n");
        sys->num_page_faults++;
        return 0xFFFF;
    }
    
    pte->referenced = 1;
    
    uint16_t physical_address = (pte->pfn << PAGE_SIZE_BITS) | offset;
    
    printf("  -> PA=0x%04X (PFN=%d)\n", physical_address, pte->pfn);
    
    return physical_address;
}

uint8_t read_memory(MemorySystem* sys, uint16_t virtual_address) {
    uint16_t physical_address = translate_address(sys, virtual_address);
    
    if (physical_address == 0xFFFF) {
        return 0;
    }
    
    uint16_t vpn = get_vpn(virtual_address);
    // if (!(sys->page_table[vpn].protection & 0x4)) {
    //     printf("ERRO: Sem permissao de leitura\n");
    //     return 0;
    // }
    
    return sys->physical_memory[physical_address];
}

void write_memory(MemorySystem* sys, uint16_t virtual_address, uint8_t value) {
    uint16_t physical_address = translate_address(sys, virtual_address);
    
    if (physical_address == 0xFFFF) {
        return;
    }
    
    uint16_t vpn = get_vpn(virtual_address);
    if (!(sys->page_table[vpn].protection & 0x2)) {
        printf("ERRO: Sem permissao de escrita\n");
        return;
    }
    
    sys->page_table[vpn].dirty = 1;
    
    sys->physical_memory[physical_address] = value;
    printf("  Escrito valor %d no endereco fisico 0x%04X\n", value, physical_address);
}

void print_page_table(MemorySystem* sys) {
    printf("\n=== TABELA DE PaGINAS ===\n");
    printf("VPN\tValid\tPresent\tPFN\tProt\tDirty\tRef\n");
    printf("---\t-----\t-------\t---\t----\t-----\t---\n");
    
    for (int i = 0; i < NUM_VIRTUAL_PAGES; i++) {
        if (sys->page_table[i].valid) {
            printf("%d\t%d\t%d\t%d\t", 
                   i, 
                   sys->page_table[i].valid,
                   sys->page_table[i].present,
                   sys->page_table[i].pfn);
            
            if (sys->page_table[i].protection & 0x4) printf("R");
            else printf("-");
            if (sys->page_table[i].protection & 0x2) printf("W");
            else printf("-");
            if (sys->page_table[i].protection & 0x1) printf("X");
            else printf("-");
            
            printf("\t%d\t%d\n",
                   sys->page_table[i].dirty,
                   sys->page_table[i].referenced);
        }
    }
}

void simulate_memory_trace(MemorySystem* sys) {
    printf("\n=== SIMULAcaO DE TRACE DE MEMÓRIA ===\n");
    
    printf("\nInicializando array em VA 0x100 (VPN=4):\n");
    for (int i = 0; i < 10; i++) {
        uint16_t addr = 0x100 + i * 4;
        write_memory(sys, addr, i);
    }
    
    printf("\nLendo array:\n");
    for (int i = 0; i < 10; i++) {
        uint16_t addr = 0x100 + i * 4;
        uint8_t value = read_memory(sys, addr);
        printf("  array[%d] = %d\n", i, value);
    }
    
    printf("\nTentando acessar pagina invalida (VA=0x200):\n");
    read_memory(sys, 0x200);
}

int main() {
    printf("=== SISTEMA DE PAGINAcaO BaSICA ===\n");
    printf("Tamanho do espaco de enderecamento: %d bytes\n", 1 << VIRTUAL_ADDRESS_BITS);
    printf("Tamanho da pagina: %d bytes\n", PAGE_SIZE);
    printf("Número de paginas virtuais: %d\n", NUM_VIRTUAL_PAGES);
    printf("Tamanho da memória fisica: %d bytes\n", PHYSICAL_MEMORY_SIZE);
    printf("Número de frames fisicos: %d\n", NUM_PHYSICAL_FRAMES);
    
    MemorySystem* sys = init_memory_system();
    
    print_page_table(sys);
    
    simulate_memory_trace(sys);
    
    print_page_table(sys);
    
    printf("\n=== ESTATiSTICAS ===\n");
    printf("Total de traducoes: %d\n", sys->num_translations);
    printf("Page faults: %d\n", sys->num_page_faults);
    
    free(sys);
    return 0;
}