#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define VIRTUAL_ADDRESS_BITS 16
#define PAGE_SIZE_BITS 10
#define PAGE_SIZE (1 << PAGE_SIZE_BITS)
#define NUM_VIRTUAL_PAGES (1 << (VIRTUAL_ADDRESS_BITS - PAGE_SIZE_BITS))
#define PHYSICAL_MEMORY_SIZE 32768
#define NUM_PHYSICAL_FRAMES (PHYSICAL_MEMORY_SIZE / PAGE_SIZE)

#define TLB_SIZE 16
#define ASID_BITS 8

typedef enum {
    REPLACEMENT_LRU,
    REPLACEMENT_RANDOM,
    REPLACEMENT_FIFO
} ReplacementPolicy;

typedef struct {
    uint8_t valid;
    uint16_t vpn;
    uint16_t pfn;
    uint8_t asid;
    uint8_t protection;
    uint8_t dirty;
    uint8_t global;
    uint32_t last_access;
} TLBEntry;

typedef struct {
    uint8_t valid;
    uint8_t present;
    uint8_t dirty;
    uint8_t referenced;
    uint8_t protection;
    uint16_t pfn;
} PageTableEntry;

typedef struct {
    uint8_t asid;
    PageTableEntry* page_table;
    char name[32];
} Process;

typedef struct {
    uint8_t physical_memory[PHYSICAL_MEMORY_SIZE];
    TLBEntry tlb[TLB_SIZE];
    Process* current_process;
    Process processes[4];
    ReplacementPolicy replacement_policy;
    uint32_t clock_counter;
    uint32_t tlb_hits;
    uint32_t tlb_misses;
    uint32_t total_accesses;
    uint32_t context_switches;
} TLBSystem;

TLBSystem* init_tlb_system() {
    TLBSystem* sys = (TLBSystem*)calloc(1, sizeof(TLBSystem));
    if (!sys) {
        printf("Erro ao alocar memória\n");
        exit(1);
    }

    for (int i = 0; i < TLB_SIZE; i++) {
        sys->tlb[i].valid = 0;
    }

    for (int i = 0; i < 4; i++) {
        sys->processes[i].asid = i + 1;
        sprintf(sys->processes[i].name, "Process_%d", i + 1);
        sys->processes[i].page_table = (PageTableEntry*)calloc(NUM_VIRTUAL_PAGES, sizeof(PageTableEntry));

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
    sys->replacement_policy = REPLACEMENT_LRU;
    sys->clock_counter = 0;

    srand(time(NULL));

    return sys;
}

int tlb_lookup(TLBSystem* sys, uint16_t vpn, uint8_t asid) {
    for (int i = 0; i < TLB_SIZE; i++) {
        if (sys->tlb[i].valid &&
            sys->tlb[i].vpn == vpn &&
            (sys->tlb[i].global || sys->tlb[i].asid == asid)) {

            sys->tlb[i].last_access = sys->clock_counter++;
            return i;
        }
    }
    return -1;
}

int find_tlb_victim(TLBSystem* sys) {
    int victim = 0;

    for (int i = 0; i < TLB_SIZE; i++) {
        if (!sys->tlb[i].valid) {
            return i;
        }
    }

    switch (sys->replacement_policy) {
        case REPLACEMENT_LRU:
            {
                uint32_t oldest_time = sys->tlb[0].last_access;
                victim = 0;
                for (int i = 1; i < TLB_SIZE; i++) {
                    if (sys->tlb[i].last_access < oldest_time) {
                        oldest_time = sys->tlb[i].last_access;
                        victim = i;
                    }
                }
            }
            break;

        case REPLACEMENT_RANDOM:
            victim = rand() % TLB_SIZE;
            break;

        case REPLACEMENT_FIFO:
            {
                uint32_t oldest_time = sys->tlb[0].last_access;
                victim = 0;
                for (int i = 1; i < TLB_SIZE; i++) {
                    if (sys->tlb[i].last_access < oldest_time) {
                        oldest_time = sys->tlb[i].last_access;
                        victim = i;
                    }
                }
            }
            break;
    }

    return victim;
}

void tlb_insert(TLBSystem* sys, uint16_t vpn, uint16_t pfn, uint8_t protection) {
    int victim = find_tlb_victim(sys);

    sys->tlb[victim].valid = 1;
    sys->tlb[victim].vpn = vpn;
    sys->tlb[victim].pfn = pfn;
    sys->tlb[victim].asid = sys->current_process->asid;
    sys->tlb[victim].protection = protection;
    sys->tlb[victim].dirty = 0;
    sys->tlb[victim].global = 0;
    sys->tlb[victim].last_access = sys->clock_counter++;

    printf("  TLB: Inserido VPN=%d -> PFN=%d no slot %d\n", vpn, pfn, victim);
}

void tlb_flush(TLBSystem* sys) {
    for (int i = 0; i < TLB_SIZE; i++) {
        sys->tlb[i].valid = 0;
    }
    printf("  TLB: Flush completo\n");
}

void tlb_flush_asid(TLBSystem* sys, uint8_t asid) {
    int count = 0;
    for (int i = 0; i < TLB_SIZE; i++) {
        if (sys->tlb[i].valid && sys->tlb[i].asid == asid && !sys->tlb[i].global) {
            sys->tlb[i].valid = 0;
            count++;
        }
    }
    printf("  TLB: Removidas %d entradas do ASID %d\n", count, asid);
}

uint32_t translate_with_tlb(TLBSystem* sys, uint32_t virtual_address) {
    sys->total_accesses++;

    uint16_t vpn = (virtual_address >> PAGE_SIZE_BITS) & ((1 << (VIRTUAL_ADDRESS_BITS - PAGE_SIZE_BITS)) - 1);
    uint16_t offset = virtual_address & ((1 << PAGE_SIZE_BITS) - 1);
    uint8_t asid = sys->current_process->asid;

    printf("\nTradução: VA=0x%08X (Processo %s, ASID=%d)\n",
           virtual_address, sys->current_process->name, asid);
    printf("  VPN=%d, Offset=%d\n", vpn, offset);

    int tlb_index = tlb_lookup(sys, vpn, asid);

    if (tlb_index >= 0) {
        sys->tlb_hits++;
        TLBEntry* entry = &sys->tlb[tlb_index];
        uint32_t physical_address = (entry->pfn << PAGE_SIZE_BITS) | offset;

        printf("  TLB HIT! Slot=%d, PFN=%d\n", tlb_index, entry->pfn);
        printf("  PA=0x%08X\n", physical_address);

        return physical_address;
    } else {
        sys->tlb_misses++;
        printf("  TLB MISS!\n");

        PageTableEntry* pte = &sys->current_process->page_table[vpn];

        if (!pte->valid) {
            printf("  ERRO: Página não válida (SEGMENTATION_FAULT)\n");
            return 0xFFFFFFFF;
        }

        if (!pte->present) {
            printf("  ERRO: Página não presente (PAGE_FAULT)\n");
            return 0xFFFFFFFF;
        }

        tlb_insert(sys, vpn, pte->pfn, pte->protection);

        uint32_t physical_address = (pte->pfn << PAGE_SIZE_BITS) | offset;
        printf("  PA=0x%08X (da tabela de páginas)\n", physical_address);

        return physical_address;
    }
}

void context_switch(TLBSystem* sys, int process_id) {
    if (process_id < 0 || process_id >= 4) {
        printf("Processo inválido\n");
        return;
    }

    sys->context_switches++;
    Process* old_process = sys->current_process;
    sys->current_process = &sys->processes[process_id];

    printf("\n=== CONTEXT SWITCH: %s -> %s ===\n",
           old_process->name, sys->current_process->name);

    printf("  Mantendo TLB com ASIDs\n");
}

void print_tlb(TLBSystem* sys) {
    printf("\n=== ESTADO DA TLB ===\n");
    printf("Slot\tValid\tVPN\tPFN\tASID\tGlobal\tProt\tLast\n");
    printf("----\t-----\t---\t---\t----\t------\t----\t----\n");

    for (int i = 0; i < TLB_SIZE; i++) {
        if (sys->tlb[i].valid) {
            printf("%d\t%d\t%d\t%d\t%d\t%d\t",
                   i,
                   sys->tlb[i].valid,
                   sys->tlb[i].vpn,
                   sys->tlb[i].pfn,
                   sys->tlb[i].asid,
                   sys->tlb[i].global);

            if (sys->tlb[i].protection & 0x4) printf("R");
            else printf("-");
            if (sys->tlb[i].protection & 0x2) printf("W");
            else printf("-");
            if (sys->tlb[i].protection & 0x1) printf("X");
            else printf("-");

            printf("\t%d\n", sys->tlb[i].last_access);
        }
    }
}

void simulate_array_access(TLBSystem* sys) {
    printf("\n=== SIMULAÇÃO DE ACESSO A ARRAY ===\n");
    printf("Acessando array de 10 elementos (4 bytes cada) começando em VA 0x0000\n");

    for (int i = 0; i < 10; i++) {
        uint32_t addr = i * 4;
        translate_with_tlb(sys, addr);
    }

    printf("\n--- Segunda passada pelo array (demonstra localidade temporal) ---\n");
    for (int i = 0; i < 10; i++) {
        uint32_t addr = i * 4;
        translate_with_tlb(sys, addr);
    }
}

void print_statistics(TLBSystem* sys) {
    printf("\n=== ESTATÍSTICAS DO SISTEMA ===\n");
    printf("Total de acessos: %d\n", sys->total_accesses);
    printf("TLB Hits: %d\n", sys->tlb_hits);
    printf("TLB Misses: %d\n", sys->tlb_misses);

    if (sys->total_accesses > 0) {
        float hit_rate = (float)sys->tlb_hits / sys->total_accesses * 100;
        printf("Taxa de acerto da TLB: %.2f%%\n", hit_rate);
    }

    printf("Mudanças de contexto: %d\n", sys->context_switches);
}

int main() {
    printf("=== SISTEMA DE PAGINAÇÃO COM TLB ===\n");
    printf("Tamanho da TLB: %d entradas\n", TLB_SIZE);
    printf("Tamanho da página: %d bytes\n", PAGE_SIZE);
    printf("Bits para ASID: %d\n", ASID_BITS);

    TLBSystem* sys = init_tlb_system();

    printf("\n### TESTE 1: Localidade Espacial e Temporal ###\n");
    simulate_array_access(sys);
    print_tlb(sys);

    printf("\n### TESTE 2: Context Switch ###\n");
    context_switch(sys, 1);

    translate_with_tlb(sys, 0x0000);
    translate_with_tlb(sys, 0x0400);
    translate_with_tlb(sys, 0x2800);

    print_tlb(sys);

    printf("\n### TESTE 3: Retorno ao Processo 1 ###\n");
    context_switch(sys, 0);

    translate_with_tlb(sys, 0x0000);
    translate_with_tlb(sys, 0x0010);

    print_statistics(sys);

    return 0;
}