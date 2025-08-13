#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// configuracoes do sistema
#define ADDR_BITS 16
#define PAGE_BITS 10
#define PAGE_SIZE (1 << PAGE_BITS)
#define TOTAL_PAGES (1 << (ADDR_BITS - PAGE_BITS))
#define RAM_SIZE 32768
#define TOTAL_FRAMES (RAM_SIZE / PAGE_SIZE)

// configuracoes da TLB
#define TLB_ENTRIES 16
#define ASID_BITS 8

// politicas de substituicao da TLB
typedef enum {
    POLICY_LRU,     // least recently used
    POLICY_RANDOM,  // aleatoria
    POLICY_FIFO     // first in first out
} replacement_policy_t;

// entrada da TLB (translation lookaside buffer)
typedef struct {
    uint8_t valid;        // entrada valida?
    uint16_t vpn;         // virtual page number
    uint16_t pfn;         // physical frame number
    uint8_t asid;         // address space id
    uint8_t protection;   // permissoes rwx
    uint8_t dirty;        // foi modificada?
    uint8_t global;       // pagina global?
    uint32_t timestamp;   // quando foi acessada
} tlb_entry_t;

// entrada da tabela de paginas
typedef struct {
    uint8_t valid;        // entrada valida?
    uint8_t present;      // pagina na memoria?
    uint8_t dirty;        // foi modificada?
    uint8_t referenced;   // foi acessada?
    uint8_t protection;   // permissoes
    uint16_t pfn;         // physical frame number
} page_entry_t;

// processo com sua tabela de paginas
typedef struct {
    uint8_t asid;             // id do espaco de enderecamento
    page_entry_t* page_table; // tabela de paginas
    char name[32];            // nome do processo
} process_t;

// sistema completo com TLB
typedef struct {
    uint8_t ram[RAM_SIZE];                 // memoria fisica
    tlb_entry_t tlb[TLB_ENTRIES];          // translation lookaside buffer
    process_t* current_process;            // processo atual
    process_t processes[4];                // lista de processos
    replacement_policy_t policy;           // politica de substituicao
    uint32_t clock_tick;                   // contador de tempo
    uint32_t hit_count;                    // acertos na TLB
    uint32_t miss_count;                   // falhas na TLB
    uint32_t access_count;                 // total de acessos
    uint32_t context_switch_count;         // mudancas de contexto
} tlb_system_t;

tlb_system_t* setup_tlb_system() {
    tlb_system_t* sys = (tlb_system_t*)calloc(1, sizeof(tlb_system_t));
    if (!sys) {
        printf("Erro ao alocar memoria\n");
        exit(1);
    }

    // inicializa TLB como vazia
    for (int i = 0; i < TLB_ENTRIES; i++) {
        sys->tlb[i].valid = 0;
    }

    // cria alguns processos de exemplo
    for (int i = 0; i < 4; i++) {
        sys->processes[i].asid = i + 1;
        sprintf(sys->processes[i].name, "Process_%d", i + 1);
        sys->processes[i].page_table = (page_entry_t*)calloc(TOTAL_PAGES, sizeof(page_entry_t));

        if (i == 0) {
            for (int j = 0; j < 3; j++) {
                sys->processes[i].page_table[j].valid = 1;
                sys->processes[i].page_table[j].present = 1;
                sys->processes[i].page_table[j].pfn = j + 10;
                sys->processes[i].page_table[j].protection = 0x7;
            }
        } else if (i == 1) {
            sys->processes[i].page_table[0].valid = 1;
            sys->processes[i].page_table[0].present = 1;
            sys->processes[i].page_table[0].pfn = 20;
            sys->processes[i].page_table[0].protection = 0x5;

            sys->processes[i].page_table[1].valid = 1;
            sys->processes[i].page_table[1].present = 1;
            sys->processes[i].page_table[1].pfn = 21;
            sys->processes[i].page_table[1].protection = 0x5;

            sys->processes[i].page_table[10].valid = 1;
            sys->processes[i].page_table[10].present = 1;
            sys->processes[i].page_table[10].pfn = 25;
            sys->processes[i].page_table[10].protection = 0x3;

            sys->processes[i].page_table[11].valid = 1;
            sys->processes[i].page_table[11].present = 1;
            sys->processes[i].page_table[11].pfn = 26;
            sys->processes[i].page_table[11].protection = 0x3;
        }
    }

    sys->current_process = &sys->processes[0];
    sys->policy = POLICY_LRU;  // usa LRU por padrao
    sys->clock_tick = 0;

    srand(time(NULL));

    return sys;
}

// procura uma entrada na TLB
int search_tlb(tlb_system_t* sys, uint16_t vpn, uint8_t asid) {
    for (int i = 0; i < TLB_ENTRIES; i++) {
        if (sys->tlb[i].valid &&
            sys->tlb[i].vpn == vpn &&
            (sys->tlb[i].global || sys->tlb[i].asid == asid)) {

            sys->tlb[i].timestamp = sys->clock_tick++;  // atualiza timestamp
            return i;
        }
    }
    return -1;  // nao encontrou
}

// encontra uma entrada da TLB para substituir
int find_victim_entry(tlb_system_t* sys) {
    // primeiro procura por entrada vazia
    for (int i = 0; i < TLB_ENTRIES; i++) {
        if (!sys->tlb[i].valid) {
            return i;
        }
    }

    int victim = 0;
    
    switch (sys->policy) {
        case POLICY_LRU:
            {
                uint32_t oldest = sys->tlb[0].timestamp;
                for (int i = 1; i < TLB_ENTRIES; i++) {
                    if (sys->tlb[i].timestamp < oldest) {
                        oldest = sys->tlb[i].timestamp;
                        victim = i;
                    }
                }
            }
            break;

        case POLICY_RANDOM:
            victim = rand() % TLB_ENTRIES;
            break;

        case POLICY_FIFO:
            {
                uint32_t oldest = sys->tlb[0].timestamp;
                for (int i = 1; i < TLB_ENTRIES; i++) {
                    if (sys->tlb[i].timestamp < oldest) {
                        oldest = sys->tlb[i].timestamp;
                        victim = i;
                    }
                }
            }
            break;
    }

    return victim;
}

// insere uma nova entrada na TLB
void insert_tlb_entry(tlb_system_t* sys, uint16_t vpn, uint16_t pfn, uint8_t protection) {
    int slot = find_victim_entry(sys);

    sys->tlb[slot].valid = 1;
    sys->tlb[slot].vpn = vpn;
    sys->tlb[slot].pfn = pfn;
    sys->tlb[slot].asid = sys->current_process->asid;
    sys->tlb[slot].protection = protection;
    sys->tlb[slot].dirty = 0;
    sys->tlb[slot].global = 0;
    sys->tlb[slot].timestamp = sys->clock_tick++;

    printf("  TLB: Inserido VPN=%d -> PFN=%d no slot %d\n", vpn, pfn, slot);
}

// limpa toda a TLB
void flush_tlb(tlb_system_t* sys) {
    for (int i = 0; i < TLB_ENTRIES; i++) {
        sys->tlb[i].valid = 0;
    }
    printf("  TLB: Flush completo\n");
}

// remove entradas de um processo especifico
void flush_asid_entries(tlb_system_t* sys, uint8_t asid) {
    int removed = 0;
    for (int i = 0; i < TLB_ENTRIES; i++) {
        if (sys->tlb[i].valid && sys->tlb[i].asid == asid && !sys->tlb[i].global) {
            sys->tlb[i].valid = 0;
            removed++;
        }
    }
    printf("  TLB: Removidas %d entradas do ASID %d\n", removed, asid);
}

// faz traducao usando TLB + tabela de paginas
uint32_t translate_address(tlb_system_t* sys, uint32_t virtual_addr) {
    sys->access_count++;

    uint16_t vpn = (virtual_addr >> PAGE_BITS) & ((1 << (ADDR_BITS - PAGE_BITS)) - 1);
    uint16_t offset = virtual_addr & ((1 << PAGE_BITS) - 1);
    uint8_t asid = sys->current_process->asid;

    printf("\nTraducao: VA=0x%08X (Processo %s, ASID=%d)\n",
           virtual_addr, sys->current_process->name, asid);
    printf("  VPN=%d, Offset=%d\n", vpn, offset);

    int tlb_slot = search_tlb(sys, vpn, asid);

    if (tlb_slot >= 0) {
        // acerto na TLB!
        sys->hit_count++;
        tlb_entry_t* entry = &sys->tlb[tlb_slot];
        uint32_t phys_addr = (entry->pfn << PAGE_BITS) | offset;

        printf("  TLB HIT! Slot=%d, PFN=%d\n", tlb_slot, entry->pfn);
        printf("  PA=0x%08X\n", phys_addr);

        return phys_addr;
    } else {
        // falha na TLB - precisa consultar tabela de paginas
        sys->miss_count++;
        printf("  TLB MISS!\n");

        page_entry_t* entry = &sys->current_process->page_table[vpn];

        if (!entry->valid) {
            printf("  ERRO: Pagina nao valida (SEGFAULT)\n");
            return 0xFFFFFFFF;
        }

        if (!entry->present) {
            printf("  ERRO: Pagina nao presente (PAGE FAULT)\n");
            return 0xFFFFFFFF;
        }

        // insere na TLB para proximos acessos
        insert_tlb_entry(sys, vpn, entry->pfn, entry->protection);

        uint32_t phys_addr = (entry->pfn << PAGE_BITS) | offset;
        printf("  PA=0x%08X (da tabela de paginas)\n", phys_addr);

        return phys_addr;
    }
}

// muda de processo
void switch_process(tlb_system_t* sys, int process_id) {
    if (process_id < 0 || process_id >= 4) {
        printf("ID de processo invalido\n");
        return;
    }

    sys->context_switch_count++;
    process_t* old_proc = sys->current_process;
    sys->current_process = &sys->processes[process_id];

    printf("\n=== MUDANCA DE CONTEXTO: %s -> %s ===\n",
           old_proc->name, sys->current_process->name);

    printf("  Mantendo TLB com ASIDs (nao precisa flush)\n");
}

// mostra o estado atual da TLB
void show_tlb_state(tlb_system_t* sys) {
    printf("\n=== ESTADO DA TLB ===\n");
    printf("Slot\tValid\tVPN\tPFN\tASID\tGlobal\tPerm\tTime\n");
    printf("----\t-----\t---\t---\t----\t------\t----\t----\n");

    for (int i = 0; i < TLB_ENTRIES; i++) {
        if (sys->tlb[i].valid) {
            printf("%d\t%d\t%d\t%d\t%d\t%d\t",
                   i,
                   sys->tlb[i].valid,
                   sys->tlb[i].vpn,
                   sys->tlb[i].pfn,
                   sys->tlb[i].asid,
                   sys->tlb[i].global);

            // mostra permissoes de forma legivel
            if (sys->tlb[i].protection & 0x4) printf("r");
            else printf("-");
            if (sys->tlb[i].protection & 0x2) printf("w");
            else printf("-");
            if (sys->tlb[i].protection & 0x1) printf("x");
            else printf("-");

            printf("\t%d\n", sys->tlb[i].timestamp);
        }
    }
}

// simula acesso a um array para testar localidade
void test_array_access(tlb_system_t* sys) {
    printf("\n=== SIMULACAO DE ACESSO A ARRAY ===\n");
    printf("Acessando array de 10 elementos (4 bytes cada) comecando em VA 0x0000\n");

    // primeira passada - muitos TLB misses
    for (int i = 0; i < 10; i++) {
        uint32_t addr = i * 4;
        translate_address(sys, addr);
    }

    printf("\n--- Segunda passada (demonstra localidade temporal) ---\n");
    // segunda passada - mais TLB hits
    for (int i = 0; i < 10; i++) {
        uint32_t addr = i * 4;
        translate_address(sys, addr);
    }
}

// mostra estatisticas do sistema
void show_stats(tlb_system_t* sys) {
    printf("\n=== ESTATISTICAS DO SISTEMA ===\n");
    printf("Total de acessos: %d\n", sys->access_count);
    printf("TLB Hits: %d\n", sys->hit_count);
    printf("TLB Misses: %d\n", sys->miss_count);

    if (sys->access_count > 0) {
        float hit_rate = (float)sys->hit_count / sys->access_count * 100;
        printf("Taxa de acerto da TLB: %.2f%%\n", hit_rate);
    }

    printf("Mudancas de contexto: %d\n", sys->context_switch_count);
}

int main() {
    printf("=== SISTEMA DE PAGINACAO COM TLB ===\n");
    printf("Tamanho da TLB: %d entradas\n", TLB_ENTRIES);
    printf("Tamanho da pagina: %d bytes\n", PAGE_SIZE);
    printf("Bits para ASID: %d\n", ASID_BITS);

    tlb_system_t* sys = setup_tlb_system();

    printf("\n### TESTE 1: Localidade Espacial e Temporal ###\n");
    test_array_access(sys);
    show_tlb_state(sys);

    printf("\n### TESTE 2: Mudanca de Processo ###\n");
    switch_process(sys, 1);

    translate_address(sys, 0x0000);
    translate_address(sys, 0x0400);
    translate_address(sys, 0x2800);

    show_tlb_state(sys);

    printf("\n### TESTE 3: Retorno ao Processo 1 ###\n");
    switch_process(sys, 0);

    translate_address(sys, 0x0000);
    translate_address(sys, 0x0010);

    show_stats(sys);

    return 0;
}