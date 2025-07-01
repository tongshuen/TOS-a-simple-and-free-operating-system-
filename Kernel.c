/* kernel.c - 完整功能内核 */
#define VIDEO_MEMORY 0xB8000
#define COLS 80
#define ROWS 25
#define SECTOR_SIZE 512
#define MAX_PATH_LEN 128
#define MAX_CMD_LEN 128

// 颜色定义
typedef enum {
    COLOR_BLACK = 0,
    COLOR_BLUE = 1,
    COLOR_GREEN = 2,
    COLOR_CYAN = 3,
    COLOR_RED = 4,
    COLOR_MAGENTA = 5,
    COLOR_BROWN = 6,
    COLOR_LGRAY = 7,
    COLOR_DGRAY = 8,
    COLOR_LBLUE = 9,
    COLOR_LGREEN = 10,
    COLOR_LCYAN = 11,
    COLOR_LRED = 12,
    COLOR_LMAGENTA = 13,
    COLOR_YELLOW = 14,
    COLOR_WHITE = 15
} Color;

// 文件系统结构
typedef struct {
    uint8_t boot_jump[3];
    char oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t fat_count;
    uint16_t root_entries;
    uint16_t total_sectors;
    uint8_t media_type;
    uint16_t sectors_per_fat;
    uint16_t sectors_per_track;
    uint16_t head_count;
    uint32_t hidden_sectors;
    uint32_t total_sectors_large;
    uint8_t drive_number;
    uint8_t flags;
    uint8_t signature;
    uint32_t volume_id;
    char volume_label[11];
    char fs_type[8];
} __attribute__((packed)) FatBootSector;

typedef struct {
    char name[8];
    char ext[3];
    uint8_t attributes;
    uint8_t reserved;
    uint8_t create_time_fine;
    uint16_t create_time;
    uint16_t create_date;
    uint16_t access_date;
    uint16_t cluster_high;
    uint16_t modify_time;
    uint16_t modify_date;
    uint16_t cluster_low;
    uint32_t file_size;
} __attribute__((packed)) FatDirEntry;

// 全局变量
uint16_t* video_mem = (uint16_t*)VIDEO_MEMORY;
uint16_t cursor_pos = 0;
FatBootSector* boot_sector;
FatDirEntry* root_dir;
uint16_t* fat_table;
char current_dir[MAX_PATH_LEN] = "/";
char current_prompt[MAX_PATH_LEN + 4] = "/ $ ";

// 函数声明
void clear_screen(Color bg, Color fg);
void set_cursor(uint16_t pos);
void putchar(char c, Color fg, Color bg);
void puts(const char* str, Color fg, Color bg);
void print_error(const char* msg);
void print_success(const char* msg);
void print_info(const char* msg);
void read_sectors(uint32_t lba, uint16_t count, void* buffer);
void write_sectors(uint32_t lba, uint16_t count, const void* buffer);
void init_fs();
FatDirEntry* find_file(const char* name);
int read_file(FatDirEntry* file, void* buffer);
int write_file(const char* name, const void* data, uint32_t size);
int delete_file(const char* name);
void execute_command(const char* cmd);
void shell();

// 主函数
void kmain() {
    clear_screen(COLOR_BLACK, COLOR_WHITE);
    puts("TOS Kernel v2.0", COLOR_LGREEN, COLOR_BLACK);
    puts("Initializing...", COLOR_WHITE, COLOR_BLACK);
    
    init_fs();
    shell();
}

// 清屏
void clear_screen(Color bg, Color fg) {
    uint16_t attr = (bg << 12) | (fg << 8);
    uint16_t blank = attr | ' ';
    for (int i = 0; i < COLS * ROWS; i++) {
        video_mem[i] = blank;
    }
    cursor_pos = 0;
    set_cursor(0);
}

// 设置光标位置
void set_cursor(uint16_t pos) {
    outb(0x3D4, 0x0F);
    outb(0x3D5, (uint8_t)(pos & 0xFF));
    outb(0x3D4, 0x0E);
    outb(0x3D5, (uint8_t)((pos >> 8) & 0xFF));
}

// 输出字符
void putchar(char c, Color fg, Color bg) {
    if (c == '\n') {
        cursor_pos = ((cursor_pos / COLS) + 1) * COLS;
    } else if (c == '\b') {
        if (cursor_pos > 0) {
            cursor_pos--;
            video_mem[cursor_pos] = (COLOR_BLACK << 12) | (COLOR_WHITE << 8) | ' ';
        }
    } else {
        uint16_t attr = (bg << 12) | (fg << 8);
        video_mem[cursor_pos] = attr | c;
        cursor_pos++;
    }

    if (cursor_pos >= COLS * ROWS) {
        for (int i = 0; i < (ROWS - 1) * COLS; i++) {
            video_mem[i] = video_mem[i + COLS];
        }
        for (int i = (ROWS - 1) * COLS; i < ROWS * COLS; i++) {
            video_mem[i] = (COLOR_BLACK << 12) | (COLOR_WHITE << 8) | ' ';
        }
        cursor_pos = (ROWS - 1) * COLS;
    }
    set_cursor(cursor_pos);
}

// 输出字符串
void puts(const char* str, Color fg, Color bg) {
    while (*str) {
        putchar(*str++, fg, bg);
    }
}

// 打印错误信息
void print_error(const char* msg) {
    puts("Error: ", COLOR_RED, COLOR_BLACK);
    puts(msg, COLOR_WHITE, COLOR_BLACK);
    putchar('\n', COLOR_WHITE, COLOR_BLACK);
}

// 打印成功信息
void print_success(const char* msg) {
    puts(msg, COLOR_GREEN, COLOR_BLACK);
    putchar('\n', COLOR_WHITE, COLOR_BLACK);
}

// 打印信息
void print_info(const char* msg) {
    puts(msg, COLOR_CYAN, COLOR_BLACK);
    putchar('\n', COLOR_WHITE, COLOR_BLACK);
}

// 读取磁盘扇区
void read_sectors(uint32_t lba, uint16_t count, void* buffer) {
    asm volatile (
        "mov %0, %%esi\n"
        "mov %1, %%ecx\n"
        "mov %2, %%edi\n"
        "push %%ds\n"
        "push %%es\n"
        "mov $0x1000, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "xor %%bx, %%bx\n"
        "1:\n"
        "push %%ecx\n"
        "mov $0x42, %%ah\n"
        "mov $0x80, %%dl\n"
        "mov %%esi, %%si\n"
        "int $0x13\n"
        "pop %%ecx\n"
        "add $512, %%edi\n"
        "inc %%esi\n"
        "loop 1b\n"
        "pop %%es\n"
        "pop %%ds\n"
        : 
        : "r"(lba), "r"(count), "r"(buffer)
        : "eax", "ebx", "ecx", "edx", "esi", "edi", "memory"
    );
}

// 写入磁盘扇区
void write_sectors(uint32_t lba, uint16_t count, const void* buffer) {
    asm volatile (
        "mov %0, %%esi\n"
        "mov %1, %%ecx\n"
        "mov %2, %%edi\n"
        "push %%ds\n"
        "push %%es\n"
        "mov $0x1000, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "xor %%bx, %%bx\n"
        "1:\n"
        "push %%ecx\n"
        "mov $0x43, %%ah\n"
        "mov $0x80, %%dl\n"
        "mov %%esi, %%si\n"
        "int $0x13\n"
        "pop %%ecx\n"
        "add $512, %%edi\n"
        "inc %%esi\n"
        "loop 1b\n"
        "pop %%es\n"
        "pop %%ds\n"
        : 
        : "r"(lba), "r"(count), "r"(buffer)
        : "eax", "ebx", "ecx", "edx", "esi", "edi", "memory"
    );
}

// 初始化文件系统
void init_fs() {
    boot_sector = (FatBootSector*)0x7E00;
    root_dir = (FatDirEntry*)(0x7E00 + sizeof(FatBootSector));
    
    // 读取FAT表
    fat_table = (uint16_t*)0x10000;
    uint32_t fat_start = boot_sector->reserved_sectors;
    uint32_t fat_size = boot_sector->sectors_per_fat;
    
    for (uint32_t i = 0; i < fat_size; i++) {
        read_sectors(fat_start + i, 1, fat_table + (i * SECTOR_SIZE / 2));
    }
}

// 查找文件
FatDirEntry* find_file(const char* name) {
    for (uint16_t i = 0; i < boot_sector->root_entries; i++) {
        if (root_dir[i].name[0] == 0xE5 || root_dir[i].name[0] == 0) continue;
        
        char fullname[12];
        memcpy(fullname, root_dir[i].name, 8);
        fullname[8] = '.';
        memcpy(fullname + 9, root_dir[i].ext, 3);
        fullname[12] = '\0';
        
        if (strcmp(fullname, name) == 0) {
            return &root_dir[i];
        }
    }
    return NULL;
}

// 读取文件
int read_file(FatDirEntry* file, void* buffer) {
    uint16_t cluster = file->cluster_low;
    uint32_t size = file->file_size;
    uint8_t* ptr = (uint8_t*)buffer;
    uint32_t read = 0;
    
    while (cluster < 0xFFF8 && read < size) {
        uint32_t sector = boot_sector->reserved_sectors + 
                         (boot_sector->fat_count * boot_sector->sectors_per_fat) +
                         ((cluster - 2) * boot_sector->sectors_per_cluster);
        
        for (int i = 0; i < boot_sector->sectors_per_cluster; i++) {
            uint8_t sector_buf[SECTOR_SIZE];
            read_sectors(sector + i, 1, sector_buf);
            
            uint32_t to_copy = SECTOR_SIZE;
            if (read + to_copy > size) {
                to_copy = size - read;
            }
            
            memcpy(ptr, sector_buf, to_copy);
            ptr += to_copy;
            read += to_copy;
            
            if (read >= size) break;
        }
        
        cluster = fat_table[cluster];
    }
    
    return read;
}

// 写入文件
int write_file(const char* name, const void* data, uint32_t size) {
    FatDirEntry* entry = NULL;
    for (uint16_t i = 0; i < boot_sector->root_entries; i++) {
        if (root_dir[i].name[0] == 0xE5) {
            entry = &root_dir[i];
            break;
        }
    }
    if (!entry) return 0;
    
    // 解析文件名
    char base[9], ext[4];
    memset(base, ' ', 8);
    memset(ext, ' ', 3);
    
    const char* dot = strchr(name, '.');
    if (dot) {
        int base_len = dot - name;
        if (base_len > 8) base_len = 8;
        memcpy(base, name, base_len);
        
        int ext_len = strlen(dot + 1);
        if (ext_len > 3) ext_len = 3;
        memcpy(ext, dot + 1, ext_len);
    } else {
        int name_len = strlen(name);
        if (name_len > 8) name_len = 8;
        memcpy(base, name, name_len);
    }
    
    // 设置目录项
    memcpy(entry->name, base, 8);
    memcpy(entry->ext, ext, 3);
    entry->attributes = 0;
    entry->file_size = size;
    
    // 分配簇链
    uint16_t clusters_needed = (size + SECTOR_SIZE * boot_sector->sectors_per_cluster - 1) / 
                              (SECTOR_SIZE * boot_sector->sectors_per_cluster);
    
    uint16_t prev_cluster = 0;
    uint16_t first_cluster = 0;
    
    for (uint16_t i = 2; i < 0xFFF0 && clusters_needed > 0; i++) {
        if (fat_table[i] == 0) {
            if (prev_cluster == 0) {
                first_cluster = i;
            } else {
                fat_table[prev_cluster] = i;
            }
            prev_cluster = i;
            clusters_needed--;
        }
    }
    
    if (clusters_needed > 0) return 0;
    
    fat_table[prev_cluster] = 0xFFFF;
    entry->cluster_low = first_cluster;
    
    // 写入数据
    uint16_t cluster = first_cluster;
    const uint8_t* ptr = (const uint8_t*)data;
    uint32_t written = 0;
    
    while (cluster < 0xFFF8 && written < size) {
        uint32_t sector = boot_sector->reserved_sectors + 
                         (boot_sector->fat_count * boot_sector->sectors_per_fat) +
                         ((cluster - 2) * boot_sector->sectors_per_cluster);
        
        for (int i = 0; i < boot_sector->sectors_per_cluster; i++) {
            uint8_t sector_buf[SECTOR_SIZE];
            uint32_t to_write = SECTOR_SIZE;
            if (written + to_write > size) {
                to_write = size - written;
                memset(sector_buf, 0, SECTOR_SIZE);
            }
            
            memcpy(sector_buf, ptr, to_write);
            write_sectors(sector + i, 1, sector_buf);
            ptr += to_write;
            written += to_write;
            
            if (written >= size) break;
        }
        
        cluster = fat_table[cluster];
    }
    
    return written;
}

// 删除文件
int delete_file(const char* name) {
    FatDirEntry* entry = find_file(name);
    if (!entry) return 0;
    
    uint16_t cluster = entry->cluster_low;
    while (cluster < 0xFFF8) {
        uint16_t next = fat_table[cluster];
        fat_table[cluster] = 0;
        cluster = next;
    }
    
    entry->name[0] = 0xE5;
    return 1;
}

// 执行命令
void execute_command(const char* cmd) {
    char command[MAX_CMD_LEN];
    char args[MAX_CMD_LEN] = {0};
    
    strcpy(command, cmd);
    char* space = strchr(command, ' ');
    if (space) {
        *space = '\0';
        strcpy(args, space + 1);
    }
    
    if (strcmp(command, "help") == 0) {
        puts("Available commands:", COLOR_WHITE, COLOR_BLACK);
        puts("help      - Show this help", COLOR_WHITE, COLOR_BLACK);
        puts("clear     - Clear screen", COLOR_WHITE, COLOR_BLACK);
        puts("ls        - List files", COLOR_WHITE, COLOR_BLACK);
        puts("cat <file>- Show file content", COLOR_WHITE, COLOR_BLACK);
        puts("write <file> <text> - Write text to file", COLOR_WHITE, COLOR_BLACK);
        puts("delete <file> - Delete file", COLOR_WHITE, COLOR_BLACK);
    } 
    else if (strcmp(command, "clear") == 0) {
        clear_screen(COLOR_BLACK, COLOR_WHITE);
    }
    else if (strcmp(command, "ls") == 0) {
        puts("Files:", COLOR_CYAN, COLOR_BLACK);
        for (uint16_t i = 0; i < boot_sector->root_entries; i++) {
            if (root_dir[i].name[0] == 0xE5 || root_dir[i].name[0] == 0) continue;
            
            char name[12];
            memcpy(name, root_dir[i].name, 8);
            name[8] = '.';
            memcpy(name + 9, root_dir[i].ext, 3);
            name[12] = '\0';
            
            puts(" - ", COLOR_WHITE, COLOR_BLACK);
            puts(name, COLOR_LGREEN, COLOR_BLACK);
            putchar('\n', COLOR_WHITE, COLOR_BLACK);
        }
    }
    else if (strcmp(command, "cat") == 0) {
        FatDirEntry* file = find_file(args);
        if (!file) {
            print_error("File not found");
            return;
        }
        
        uint8_t* buffer = (uint8_t*)0x100000;
        int size = read_file(file, buffer);
        
        puts("File content:", COLOR_CYAN, COLOR_BLACK);
        for (int i = 0; i < size && i < 1024; i++) {
            putchar(buffer[i], COLOR_WHITE, COLOR_BLACK);
            if (i % COLS == COLS - 1) putchar('\n', COLOR_WHITE, COLOR_BLACK);
        }
        putchar('\n', COLOR_WHITE, COLOR_BLACK);
    }
    else if (strcmp(command, "write") == 0) {
        char* filename = strtok(args, " ");
        char* text = strtok(NULL, "");
        
        if (!filename || !text) {
            print_error("Usage: write <file> <text>");
            return;
        }
        
        if (write_file(filename, text, strlen(text))) {
            print_success("File written successfully");
        } else {
            print_error("Failed to write file");
        }
    }
    else if (strcmp(command, "delete") == 0) {
        if (delete_file(args)) {
            print_success("File deleted successfully");
        } else {
            print_error("Failed to delete file");
        }
    }
    else {
        print_error("Unknown command");
    }
}

// Shell
void shell() {
    char input[MAX_CMD_LEN + 1];
    int pos = 0;
    
    puts("TOS Shell - Type 'help' for commands", COLOR_LGREEN, COLOR_BLACK);
    
    while (1) {
        puts(current_prompt, COLOR_YELLOW, COLOR_BLACK);
        
        // 读取输入
        pos = 0;
        while (1) {
            char c = getchar();
            
            if (c == '\n') {
                putchar('\n', COLOR_WHITE, COLOR_BLACK);
                input[pos] = '\0';
                break;
            } else if (c == '\b') {
                if (pos > 0) {
                    pos--;
                    putchar('\b', COLOR_WHITE, COLOR_BLACK);
                    putchar(' ', COLOR_WHITE, COLOR_BLACK);
                    putchar('\b', COLOR_WHITE, COLOR_BLACK);
                }
            } else if (pos < MAX_CMD_LEN) {
                putchar(c, COLOR_WHITE, COLOR_BLACK);
                input[pos++] = c;
            }
        }
        
        // 执行命令
        if (pos > 0) {
            execute_command(input);
        }
    }
}

// 获取键盘输入
char getchar() {
    while (1) {
        if (inb(0x64) & 0x01) {
            uint8_t c = inb(0x60);
            if (c == 0x1C) return '\n';  // Enter
            if (c == 0x0E) return '\b';   // Backspace
            if (c >= 0x10 && c <= 0x1C) return "qwertyuiop"[c - 0x10];
            if (c >= 0x1E && c <= 0x26) return "asdfghjkl"[c - 0x1E];
            if (c >= 0x2C && c <= 0x32) return "zxcvbnm"[c - 0x2C];
            if (c == 0x39) return ' ';    // Space
        }
    }
}

// 端口输出
void outb(uint16_t port, uint8_t value) {
    asm volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

// 端口输入
uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
