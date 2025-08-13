#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Configuracoes do sistema de memoria
#define ADDR_BITS 14
#define PAGE_BITS 6  
#define PAGE_SIZE (1 << PAGE_BITS)
#define TOTAL_PAGES (1 << (ADDR_BITS - PAGE_BITS))
#define MEM_SIZE 8192
#define TOTAL_FRAMES (MEM_SIZE / PAGE_SIZE)

// entrada da tabela de paginas
typedef struct {
    uint8_t valid;       // se a pagina eh valida
    uint8_t present;     // se ta na memoria fisica
    uint8_t dirty;       // foi modificada?
    uint8_t referenced;  // foi acessada recentemente?
    uint8_t protection;  // permissoes (rwx)
    uint16_t frame_num;  // numero do frame fisico
} page_entry_t;

// o sistema de memoria completo
typedef struct {
    uint8_t ram[MEM_SIZE];                // memoria fisica
    page_entry_t pages[TOTAL_PAGES];      // tabela de paginas
    uint16_t ptbr;                        // registrador base da tabela
    uint32_t translation_count;           // contador de traducoes
    uint32_t page_fault_count;            // contador de page faults
} memory_sys_t;

memory_sys_t* setup_memory() {
    memory_sys_t* sys = (memory_sys_t*)calloc(1, sizeof(memory_sys_t));
    if (!sys) {
        printf("Ops, nao consegui alocar memoria\n");
        exit(1);
    }
    
    // inicializa todas as paginas como invalidas
    for (int i = 0; i < TOTAL_PAGES; i++) {
        sys->pages[i].valid = 0;
        sys->pages[i].present = 0;
        sys->pages[i].frame_num = 0;
    }
    
    // configura algumas paginas de exemplo
    sys->pages[0].valid = 1;
    sys->pages[0].present = 1;
    sys->pages[0].protection = 0x5;  // r-x
    sys->pages[0].frame_num = 3;
    
    sys->pages[1].valid = 1;
    sys->pages[1].present = 1;
    sys->pages[1].protection = 0x5;  // r-x  
    sys->pages[1].frame_num = 7;
    
    sys->pages[4].valid = 1;
    sys->pages[4].present = 1;
    sys->pages[4].protection = 0x3;  // rw-
    sys->pages[4].frame_num = 5;
    
    // algumas paginas no final do espaco de enderecamento
    sys->pages[254].valid = 1;
    sys->pages[254].present = 1;
    sys->pages[254].protection = 0x3;
    sys->pages[254].frame_num = 2;
    
    sys->pages[255].valid = 1;
    sys->pages[255].present = 1;
    sys->pages[255].protection = 0x3;
    sys->pages[255].frame_num = 6;
    
    return sys;
}

// extrai o numero da pagina virtual
uint16_t extract_page_num(uint16_t addr) {
    return (addr >> PAGE_BITS) & ((1 << (ADDR_BITS - PAGE_BITS)) - 1);
}

// pega o offset dentro da pagina
uint16_t extract_offset(uint16_t addr) {
    return addr & ((1 << PAGE_BITS) - 1);
}

uint16_t translate_addr(memory_sys_t* sys, uint16_t virt_addr) {
    sys->translation_count++;
    
    uint16_t page_num = extract_page_num(virt_addr);
    uint16_t offset = extract_offset(virt_addr);
    
    printf("Traduzindo: VA=0x%04X -> Pagina=%d, Offset=%d\n", 
           virt_addr, page_num, offset);
    
    if (page_num >= TOTAL_PAGES) {
        printf("ERRO: numero da pagina invalido\n");
        return 0xFFFF;
    }
    
    page_entry_t* entry = &sys->pages[page_num];
    
    if (!entry->valid) {
        printf("ERRO: pagina nao eh valida (SEGFAULT)\n");
        sys->page_fault_count++;
        return 0xFFFF;
    }
    
    if (!entry->present) {
        printf("ERRO: pagina nao ta na memoria (PAGE FAULT)\n");
        sys->page_fault_count++;
        return 0xFFFF;
    }
    
    entry->referenced = 1;  // marca como acessada
    
    uint16_t phys_addr = (entry->frame_num << PAGE_BITS) | offset;
    
    printf("  -> Endereco fisico=0x%04X (Frame=%d)\n", phys_addr, entry->frame_num);
    
    return phys_addr;
}

uint8_t read_mem(memory_sys_t* sys, uint16_t virt_addr) {
    uint16_t phys_addr = translate_addr(sys, virt_addr);
    
    if (phys_addr == 0xFFFF) {
        return 0;  // falhou na traducao
    }
    
    uint16_t page_num = extract_page_num(virt_addr);
    // TODO: verificar permissoes de leitura
    // if (!(sys->pages[page_num].protection & 0x4)) {
    //     printf("ERRO: sem permissao de leitura\n");
    //     return 0;
    // }
    
    return sys->ram[phys_addr];
}

void write_mem(memory_sys_t* sys, uint16_t virt_addr, uint8_t val) {
    uint16_t phys_addr = translate_addr(sys, virt_addr);
    
    if (phys_addr == 0xFFFF) {
        return;  // traducao falhou
    }
    
    uint16_t page_num = extract_page_num(virt_addr);
    if (!(sys->pages[page_num].protection & 0x2)) {
        printf("ERRO: nao pode escrever nessa pagina\n");
        return;
    }
    
    sys->pages[page_num].dirty = 1;  // marca como modificada
    
    sys->ram[phys_addr] = val;
    printf("  Escreveu %d no endereco fisico 0x%04X\n", val, phys_addr);
}

void show_page_table(memory_sys_t* sys) {
    printf("\n=== Tabela de Paginas ===\n");
    printf("Pag\tValid\tPresent\tFrame\tPerm\tDirty\tRef\n");
    printf("---\t-----\t-------\t-----\t----\t-----\t---\n");
    
    for (int i = 0; i < TOTAL_PAGES; i++) {
        if (sys->pages[i].valid) {
            printf("%d\t%d\t%d\t%d\t", 
                   i, 
                   sys->pages[i].valid,
                   sys->pages[i].present,
                   sys->pages[i].frame_num);
            
            // mostra as permissoes de forma legivel
            if (sys->pages[i].protection & 0x4) printf("r");
            else printf("-");
            if (sys->pages[i].protection & 0x2) printf("w");
            else printf("-");
            if (sys->pages[i].protection & 0x1) printf("x");
            else printf("-");
            
            printf("\t%d\t%d\n",
                   sys->pages[i].dirty,
                   sys->pages[i].referenced);
        }
    }
}

void test_memory_ops(memory_sys_t* sys) {
    printf("\n=== Teste de operacoes de memoria ===\n");
    
    printf("\nInicializando um array em 0x100 (pagina 4):\n");
    for (int i = 0; i < 10; i++) {
        uint16_t addr = 0x100 + i * 4;
        write_mem(sys, addr, i);
    }
    
    printf("\nLendo de volta o array:\n");
    for (int i = 0; i < 10; i++) {
        uint16_t addr = 0x100 + i * 4;
        uint8_t val = read_mem(sys, addr);
        printf("  array[%d] = %d\n", i, val);
    }
    
    printf("\nTentando acessar pagina invalida (0x200):\n");
    read_mem(sys, 0x200);
}

int main() {
    printf("=== Sistema de Paginacao Basica ===\n");
    printf("Espaco de enderecamento: %d bytes\n", 1 << ADDR_BITS);
    printf("Tamanho da pagina: %d bytes\n", PAGE_SIZE);
    printf("Total de paginas virtuais: %d\n", TOTAL_PAGES);
    printf("Memoria fisica: %d bytes\n", MEM_SIZE);
    printf("Frames fisicos: %d\n", TOTAL_FRAMES);
    
    memory_sys_t* sys = setup_memory();
    
    show_page_table(sys);
    test_memory_ops(sys);
    show_page_table(sys);
    
    printf("\n=== Estatisticas ===\n");
    printf("Traducoes realizadas: %d\n", sys->translation_count);
    printf("Page faults: %d\n", sys->page_fault_count);
    
    free(sys);
    return 0;
}