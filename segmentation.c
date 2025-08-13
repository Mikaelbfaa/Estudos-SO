#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// tipos de segmento
#define MAX_SEGS 3
#define CODE_SEG 0
#define HEAP_SEG 1
#define STACK_SEG 2

// permissoes
#define READ_PERM 1
#define WRITE_PERM 2
#define EXEC_PERM 4

// dados de um segmento
typedef struct {
    uint16_t base_addr;    // endereco base
    uint16_t size;         // tamanho do segmento
    uint16_t limit;        // limite maximo
    uint8_t grows_up;      // cresce para cima ou para baixo?
    uint8_t permissions;   // permissoes rwx
} segment_t;

// unidade de gerenciamento de memoria
typedef struct {
    uint8_t *memory;                // ponteiro para memoria fisica
    uint16_t total_memory;          // tamanho total da memoria
    uint16_t virtual_space;         // tamanho do espaco virtual
    segment_t segments[MAX_SEGS];   // array de segmentos
    uint8_t segment_bits;           // bits usados para identificar segmento
} mmu_t;

mmu_t* setup_mmu(uint16_t mem_size, uint16_t addr_space) {
    mmu_t *mmu = malloc(sizeof(mmu_t));

    mmu->memory = calloc(mem_size, 1);
    mmu->total_memory = mem_size;
    mmu->virtual_space = addr_space;
    mmu->segment_bits = 2;  // usamos 2 bits para identificar o segmento

    // inicializa os segmentos com valores padrao
    for (int i = 0; i < MAX_SEGS; i++) {
        mmu->segments[i].base_addr = 0;
        mmu->segments[i].size = 0;
        mmu->segments[i].limit = addr_space >> mmu->segment_bits;
        mmu->segments[i].grows_up = 1;  // por padrao cresce para cima
        mmu->segments[i].permissions = READ_PERM | WRITE_PERM;
    }

    // configura particularidades de cada segmento
    mmu->segments[STACK_SEG].grows_up = 0;  // stack cresce para baixo
    mmu->segments[CODE_SEG].permissions = READ_PERM | EXEC_PERM;  // codigo eh read+exec

    return mmu;
}

void configure_segment(mmu_t *mmu, uint8_t seg_id, uint16_t base, uint16_t size, uint8_t perms) {
    if (seg_id >= MAX_SEGS) {
        printf("id de segmento invalido\n");
        return;
    }

    if (base + size > mmu->total_memory) {
        printf("segmento muito grande\n");
        return;
    }

    mmu->segments[seg_id].base_addr = base;
    mmu->segments[seg_id].size = size;
    mmu->segments[seg_id].permissions = perms;
}

// descobre qual segmento baseado no endereco virtual
uint8_t get_segment_id(mmu_t *mmu, uint16_t virtual_addr) {
    uint8_t total_bits = 0;
    uint16_t temp = mmu->virtual_space - 1;
    
    // calcula quantos bits temos no total
    while (temp > 0) {
        total_bits++;
        temp >>= 1;
    }

    return virtual_addr >> (total_bits - mmu->segment_bits);
}

// extrai o offset dentro do segmento
uint16_t get_segment_offset(mmu_t *mmu, uint16_t virtual_addr) {
    uint8_t total_bits = 0;
    uint16_t temp = mmu->virtual_space - 1;
    
    while (temp > 0) {
        total_bits++;
        temp >>= 1;
    }

    uint16_t mask = (1 << (total_bits - mmu->segment_bits)) - 1;
    return virtual_addr & mask;
}

// faz a traducao de endereco virtual para fisico
int do_translation(mmu_t *mmu, uint16_t virt_addr, uint16_t *phys_addr, uint8_t operation) {
    uint8_t seg_id = get_segment_id(mmu, virt_addr);
    uint16_t offset = get_segment_offset(mmu, virt_addr);

    printf("virtual 0x%x -> segmento %d, offset %d\n", virt_addr, seg_id, offset);

    if (seg_id >= MAX_SEGS) {
        printf("segmento invalido\n");
        return -1;
    }

    segment_t *seg = &mmu->segments[seg_id];

    // verifica permissoes
    if (!(seg->permissions & operation)) {
        printf("violacao de protecao\n");
        return -1;
    }

    uint16_t real_offset;

    if (seg->grows_up) {
        // segmento que cresce para cima (code, heap)
        real_offset = offset;
        if (offset >= seg->size) {
            printf("segfault: %d >= %d\n", offset, seg->size);
            return -1;
        }
    } else {
        // segmento que cresce para baixo (stack)
        if (offset >= seg->size) {
            printf("stack overflow\n");
            return -1;
        }
        real_offset = seg->limit - offset - 1;
    }

    *phys_addr = seg->base_addr + real_offset;

    if (*phys_addr >= mmu->total_memory) {
        printf("endereco fisico fora dos limites\n");
        return -1;
    }

    printf("endereco fisico: 0x%x\n", *phys_addr);
    return 0;
}

int write_byte(mmu_t *mmu, uint16_t virt_addr, uint8_t value) {
    uint16_t phys_addr;
    if (do_translation(mmu, virt_addr, &phys_addr, WRITE_PERM) != 0) {
        return -1;
    }

    mmu->memory[phys_addr] = value;
    printf("escreveu 0x%02x em 0x%x\n", value, phys_addr);
    return 0;
}

int read_byte(mmu_t *mmu, uint16_t virt_addr, uint8_t *value) {
    uint16_t phys_addr;
    if (do_translation(mmu, virt_addr, &phys_addr, READ_PERM) != 0) {
        return -1;
    }

    *value = mmu->memory[phys_addr];
    printf("leu 0x%02x de 0x%x\n", *value, phys_addr);
    return 0;
}

void write_data(mmu_t *mmu, uint16_t addr, uint8_t *data, uint16_t length) {
    printf("\nescrevendo %d bytes em 0x%x\n", length, addr);

    for (int i = 0; i < length; i++) {
        if (write_byte(mmu, addr + i, data[i]) != 0) {
            printf("falhou no byte %d\n", i);
            return;
        }
    }
}

void read_data(mmu_t *mmu, uint16_t addr, uint16_t length) {
    printf("\nlendo %d bytes de 0x%x: ", length, addr);

    for (int i = 0; i < length; i++) {
        uint8_t value;
        if (read_byte(mmu, addr + i, &value) == 0) {
            printf("%02x ", value);
        } else {
            printf("?? ");
            break;
        }
    }
    printf("\n");
}

void display_segments(mmu_t *mmu) {
    char *seg_names[] = {"CODE", "HEAP", "STACK"};
    char *perm_strings[] = {"---", "r--", "-w-", "rw-", "--x", "r-x", "-wx", "rwx"};

    printf("\nSegmentos:\n");
    printf("nome     base  tam   limite dir perm\n");
    printf("-------- ----- ----- ------ --- ----\n");

    for (int i = 0; i < MAX_SEGS; i++) {
        printf("%-8s %5d %5d %6d  %c  %s\n",
               seg_names[i],
               mmu->segments[i].base_addr,
               mmu->segments[i].size,
               mmu->segments[i].limit,
               mmu->segments[i].grows_up ? '+' : '-',
               perm_strings[mmu->segments[i].permissions]);
    }
    printf("\n");
}

void dump_memory(mmu_t *mmu, uint16_t start, uint16_t length) {
    printf("dump da memoria 0x%04x-0x%04x:\n", start, start + length - 1);

    for (int i = 0; i < length; i += 16) {
        printf("%04x: ", start + i);

        // mostra os bytes em hex
        for (int j = 0; j < 16 && (i + j) < length; j++) {
            if (start + i + j < mmu->total_memory) {
                printf("%02x ", mmu->memory[start + i + j]);
            } else {
                printf("?? ");
            }
        }

        printf("| ");

        // mostra os caracteres ASCII
        for (int j = 0; j < 16 && (i + j) < length; j++) {
            if (start + i + j < mmu->total_memory) {
                uint8_t byte = mmu->memory[start + i + j];
                printf("%c", (byte >= 32 && byte <= 126) ? byte : '.');
            } else {
                printf("?");
            }
        }
        printf("\n");
    }
    printf("\n");
}

void run_tests() {
    printf("Simulador de Segmentacao de Memoria\n");
    printf("===================================\n\n");

    mmu_t *mmu = setup_mmu(1024, 256);

    // configura os segmentos
    configure_segment(mmu, CODE_SEG, 512, 64, READ_PERM | EXEC_PERM);
    configure_segment(mmu, HEAP_SEG, 576, 96, READ_PERM | WRITE_PERM);
    configure_segment(mmu, STACK_SEG, 448, 64, READ_PERM | WRITE_PERM);

    display_segments(mmu);

    printf("Executando testes...\n\n");

    printf("Teste 1: escrever no heap\n");
    uint8_t mensagem[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00};  // "Hello"
    write_data(mmu, 64, mensagem, 6);

    printf("\nTeste 2: ler do heap\n");
    read_data(mmu, 64, 6);

    printf("\nTeste 3: escrever na stack\n");
    uint8_t stack_data[] = {0xde, 0xad, 0xbe, 0xef};
    write_data(mmu, 252, stack_data, 4);

    printf("\nTeste 4: tentar escrever no codigo (deve falhar)\n");
    uint8_t codigo[] = {0x90, 0x90};  // instrucoes NOP
    write_data(mmu, 0, codigo, 2);

    printf("\nTeste 5: acesso fora dos limites (deve falhar)\n");
    uint8_t temp;
    read_byte(mmu, 200, &temp);

    dump_memory(mmu, 440, 80);
    dump_memory(mmu, 570, 80);

    // limpa a memoria
    free(mmu->memory);
    free(mmu);
}

int main() {
    run_tests();
    return 0;
}