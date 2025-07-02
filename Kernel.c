/* kernel.c - TOS 的内核 */
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
uint64_t read_file(FatDirEntry* file, void* buffer);
uint64_t write_file(const char* name, const void* data, uint64_t size);
uint64_t delete_file(const char* name);
void execute_command(const char* cmd);
void shell();
char getchar();
void outb(uint16_t port, uint8_t value);
uint8_t inb(uint16_t port);

// 内核入口 (64位)
void _start() {
    // 设置内核签名
    asm volatile (
        "mov $0x4F54534F, [0x100000] \n"  // "OSTOS"签名
    );
    
    clear_screen(COLOR_BLACK, COLOR_WHITE);
    puts("TOS Kernel v2.0 (64-bit)", COLOR_LGREEN, COLOR_BLACK);
    puts("Initializing...", COLOR_WHITE, COLOR_BLACK);
    
    init_fs();
    shell();
}

// 清屏
void clear_screen(Color bg, Color fg) {
    uint16_t attr = (bg << 12) | (fg << 8);
    uint16_t blank = attr | ' ';
    for (uint64_t i = 0; i < COLS * ROWS; i++) {
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
        for (uint64_t i = 0; i < (ROWS - 1) * COLS; i++) {
            video_mem[i] = video_mem[i + COLS];
        }
        for (uint64_t i = (ROWS - 1) * COLS; i < ROWS * COLS; i++) {
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

// 读取磁盘扇区 (64位版本)
void read_sectors(uint32_t lba, uint16_t count, void* buffer) {
    asm volatile (
        "mov %0, %%rdi \n"
        "mov %1, %%ecx \n"
        "mov %2, %%rbx \n"
        "push %%rbx \n"
        "push %%rcx \n"
        "push %%rdi \n"
        
        "1: \n"
        "mov $0x42, %%ah \n"
        "mov $0x80, %%dl \n"
        "mov %%ecx, %%esi \n"
        "int $0x13 \n"
        "jc 2f \n"
        
        "pop %%rdi \n"
        "add $512, %%rdi \n"
        "inc %%ecx \n"
        "push %%rdi \n"
        
        "dec %%bx \n"
        "jnz 1b \n"
        
        "jmp 3f \n"
        
        "2: \n"
        "mov $0x0F450F520F450F44, %%rax \n"  // "DISK ERROR"
        "mov %%rax, 0xB8000 \n"
        "hlt \n"
        
        "3: \n"
        "pop %%rdi \n"
        "pop %%rcx \n"
        "pop %%rbx \n"
        : 
        : "r"(buffer), "r"(lba), "r"(count)
        : "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "memory"
    );
}

// 写入磁盘扇区
void write_sectors(uint32_t lba, uint16_t count, const void* buffer) {
    asm volatile (
        "mov %0, %%rdi \n"
        "mov %1, %%ecx \n"
        "mov %2, %%rbx \n"
        "push %%rbx \n"
        "push %%rcx \n"
        "push %%rdi \n"
        
        "1: \n"
        "mov $0x43, %%ah \n"
        "mov $0x80, %%dl \n"
        "mov %%ecx, %%esi \n"
        "int $0x13 \n"
        "jc 2f \n"
        
        "pop %%rdi \n"
        "add $512, %%rdi \n"
        "inc %%ecx \n"
        "push %%rdi \n"
        
        "dec %%bx \n"
        "jnz 1b \n"
        
        "jmp 3f \n"
        
        "2: \n"
        "mov $0x0F450F520F450F44, %%rax \n"  // "DISK ERROR"
        "mov %%rax, 0xB8000 \n"
        "hlt \n"
        
        "3: \n"
        "pop %%rdi \n"
        "pop %%rcx \n"
        "pop %%rbx \n"
        : 
        : "r"(buffer), "r"(lba), "r"(count)
        : "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "memory"
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
uint64_t read_file(FatDirEntry* file, void* buffer) {
    uint16_t cluster = file->cluster_low;
    uint64_t size = file->file_size;
    uint8_t* ptr = (uint8_t*)buffer;
    uint64_t read = 0;
    
    while (cluster < 0xFFF8 && read < size) {
        uint32_t sector = boot_sector->reserved_sectors + 
                         (boot_sector->fat_count * boot_sector->sectors_per_fat) +
                         ((cluster - 2) * boot_sector->sectors_per_cluster);
        
        for (int i = 0; i < boot_sector->sectors_per_cluster; i++) {
            uint8_t sector_buf[SECTOR_SIZE];
            read_sectors(sector + i, 1, sector_buf);
            
            uint64_t to_copy = SECTOR_SIZE;
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
uint64_t write_file(const char* name, const void* data, uint64_t size) {
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
        uint64_t base_len = dot - name;
        if (base_len > 8) base_len = 8;
        memcpy(base, name, base_len);
        
        uint64_t ext_len = strlen(dot + 1);
        if (ext_len > 3) ext_len = 3;
        memcpy(ext, dot + 1, ext_len);
    } else {
        uint64_t name_len = strlen(name);
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
    uint64_t written = 0;
    
    while (cluster < 0xFFF8 && written < size) {
        uint32_t sector = boot_sector->reserved_sectors + 
                         (boot_sector->fat_count * boot_sector->sectors_per_fat) +
                         ((cluster - 2) * boot_sector->sectors_per_cluster);
        
        for (int i = 0; i < boot_sector->sectors_per_cluster; i++) {
            uint8_t sector_buf[SECTOR_SIZE];
            uint64_t to_write = SECTOR_SIZE;
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
uint64_t delete_file(const char* name) {
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
    static char script_buffer[4096];
    static uint16_t current_cluster = 0;
    
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
        puts("rm <file> - Delete file", COLOR_WHITE, COLOR_BLACK);
        puts("mkdir <dir> - Create directory", COLOR_WHITE, COLOR_BLACK);
        puts("cd <dir> - Change directory", COLOR_WHITE, COLOR_BLACK);
        puts("reboot   - Reboot system", COLOR_WHITE, COLOR_BLACK);
        puts("turnoff  - Power off system", COLOR_WHITE, COLOR_BLACK);
        puts("echo <text> - Print text", COLOR_WHITE, COLOR_BLACK);
        puts("run <file.sh> - Execute shell script", COLOR_WHITE, COLOR_BLACK);
        puts("nano <file> - Text editor", COLOR_WHITE, COLOR_BLACK);

    } 
    else if (strcmp(command, "nano") == 0) {
    if (strlen(args) == 0) {
        print_error("Usage: nano <filename>");
        return;
    }
    
        nano(args);
    }
    else if (strcmp(command, "clear") == 0) {
        clear_screen(COLOR_BLACK, COLOR_WHITE);
    }
    else if (strcmp(command, "ls") == 0) {
        list_files(current_cluster);
    }
    else if (strcmp(command, "cat") == 0) {
        if (strlen(args) == 0) {
            print_error("Usage: cat <filename>");
            return;
        }
        view_file(args, current_cluster);
    }
    else if (strcmp(command, "write") == 0) {
        char* filename = strtok(args, " ");
        char* text = strtok(NULL, "");
        
        if (!filename || !text) {
            print_error("Usage: write <file> <text>");
            return;
        }
        
        if (write_to_file(filename, text, strlen(text), current_cluster)) {
            print_success("File written successfully");
        } else {
            print_error("Failed to write file");
        }
    }
    else if (strcmp(command, "rm") == 0) {
        if (strlen(args) == 0) {
            print_error("Usage: rm <filename>");
            return;
        }
        
        if (remove_file(args, current_cluster)) {
            print_success("File deleted successfully");
        } else {
            print_error("Failed to delete file");
        }
    }
    else if (strcmp(command, "mkdir") == 0) {
        if (strlen(args) == 0) {
            print_error("Usage: mkdir <dirname>");
            return;
        }
        
        if (create_directory(args, current_cluster)) {
            print_success("Directory created");
        } else {
            print_error("Failed to create directory");
        }
    }
    else if (strcmp(command, "cd") == 0) {
        if (strlen(args) == 0) {
            snprintf(current_dir, MAX_PATH_LEN, "/");
            snprintf(current_prompt, MAX_PATH_LEN + 4, "/ $ ");
            current_cluster = 0;
            return;
        }
        
        uint16_t new_cluster = change_directory(args, current_cluster);
        if (new_cluster != 0xFFFF) {
            current_cluster = new_cluster;
            update_prompt();
        } else {
            print_error("Directory not found");
        }
    }
    else if (strcmp(command, "reboot") == 0) {
        puts("Rebooting system...", COLOR_YELLOW, COLOR_BLACK);
        outb(0x64, 0xFE);
        while(1);
    }
    else if (strcmp(command, "turnoff") == 0) {
        puts("Powering off...", COLOR_YELLOW, COLOR_BLACK);
        // ACPI shutdown
        outw(0x604, 0x2000);
        while(1);
    }
    else if (strcmp(command, "echo") == 0) {
        puts(args, COLOR_WHITE, COLOR_BLACK);
        putchar('\n', COLOR_WHITE, COLOR_BLACK);
    }
    else if (strcmp(command, "run") == 0) {
        if (strlen(args) == 0) {
            print_error("Usage: run <script.sh>");
            return;
        }
        
        if (strstr(args, ".sh") == NULL) {
            print_error("Only .sh scripts are supported");
            return;
        }
        
        execute_script(args, current_cluster);
    }
    else {
        print_error("Unknown command");
    }
}
void execute_script(const char* filename, uint16_t current_cluster) {
    FatDirEntry* file = find_file_in_cluster(filename, current_cluster);
    if (!file) {
        print_error("Script not found");
        return;
    }
    
    uint8_t* buffer = (uint8_t*)0x200000;
    uint64_t size = read_file_from_cluster(file, buffer, current_cluster);
    buffer[size] = '\0';
    
    char* lines[256];
    uint16_t line_count = 0;
    
    // Split into lines
    char* line = strtok(buffer, "\n");
    while (line && line_count < 256) {
        lines[line_count++] = line;
        line = strtok(NULL, "\n");
    }
    
    // Execute lines
    for (uint16_t i = 0; i < line_count; i++) {
        char* cmd = lines[i];
        while (*cmd == ' ' || *cmd == '\t') cmd++; // Skip leading whitespace
        
        // Skip comments
        if (*cmd == '#' || *cmd == '\0') continue;
        
        // Handle control structures
        if (strncmp(cmd, "if ", 3) == 0) {
            // Simplified if implementation
            char condition[256];
            char then_part[256];
            sscanf(cmd + 3, "%[ then ] %[^\n]", condition, then_part);
            
            if (check_condition(condition)) {
                execute_command(then_part);
            }
        } 
        else if (strncmp(cmd, "for ", 4) == 0) {
            // Simplified for implementation
            char var[32], range[32], do_part[256];
            sscanf(cmd + 4, "%s in %[ do ] %[^\n]", var, range, do_part);
            
            int start, end;
            sscanf(range, "%d..%d", &start, &end);
            
            for (int i = start; i <= end; i++) {
                char expanded_cmd[256];
                snprintf(expanded_cmd, sizeof(expanded_cmd), "%s=%d %s", var, i, do_part);
                execute_command(expanded_cmd);
            }
        }
        else if (strncmp(cmd, "def ", 4) == 0) {
            // Function definition (stored in memory)
            char func_name[32];
            char func_body[256];
            sscanf(cmd + 4, "%s %[^\n]", func_name, func_body);
            store_function(func_name, func_body);
        }
        else if (strncmp(cmd, "while ", 6) == 0) {
            // Simplified while implementation
            char condition[256];
            char do_part[256];
            sscanf(cmd + 6, "%[ do ] %[^\n]", condition, do_part);
            
            while (check_condition(condition)) {
                execute_command(do_part);
            }
        }
        else {
            // Regular command
            execute_command(cmd);
        }
    }
}
int create_directory(const char* name, uint16_t current_cluster) {
    // Check for invalid characters
    if (strchr(name, '/') || strchr(name, '\\') || strchr(name, ':') || 
        strchr(name, '*') || strchr(name, '?') || strchr(name, '"') || 
        strchr(name, '<') || strchr(name, '>') || strchr(name, '|')) {
        return 0;
    }
    
    // Find free directory entry
    FatDirEntry* entry = find_free_entry(current_cluster);
    if (!entry) return 0;
    
    // Parse directory name
    char base[9], ext[4];
    memset(base, ' ', 8);
    memset(ext, ' ', 3);
    
    const char* dot = strchr(name, '.');
    if (dot) {
        uint64_t base_len = dot - name;
        if (base_len > 8) base_len = 8;
        memcpy(base, name, base_len);
        
        uint64_t ext_len = strlen(dot + 1);
        if (ext_len > 3) ext_len = 3;
        memcpy(ext, dot + 1, ext_len);
    } else {
        uint64_t name_len = strlen(name);
        if (name_len > 8) name_len = 8;
        memcpy(base, name, name_len);
    }
    
    // Create directory entry
    memcpy(entry->name, base, 8);
    memcpy(entry->ext, ext, 3);
    entry->attributes = 0x10; // Directory attribute
    entry->file_size = 0;
    
    // Allocate cluster for directory
    uint16_t new_cluster = allocate_cluster();
    if (new_cluster == 0) {
        entry->name[0] = 0xE5;
        return 0;
    }
    
    entry->cluster_low = new_cluster;
    fat_table[new_cluster] = 0xFFFF;
    
    // Initialize directory with . and .. entries
    FatDirEntry dot_entry, dotdot_entry;
    memset(&dot_entry, 0, sizeof(FatDirEntry));
    memset(&dotdot_entry, 0, sizeof(FatDirEntry));
    
    memcpy(dot_entry.name, ".       ", 8);
    dot_entry.attributes = 0x10;
    dot_entry.cluster_low = new_cluster;
    
    memcpy(dotdot_entry.name, "..      ", 8);
    dotdot_entry.attributes = 0x10;
    dotdot_entry.cluster_low = current_cluster;
    
    uint32_t sector = cluster_to_sector(new_cluster);
    FatDirEntry init_entries[2] = {dot_entry, dotdot_entry};
    write_sectors(sector, 1, init_entries);
    
    return 1;

int create_directory(const char* name, uint16_t current_cluster) {
    // Check for invalid characters
    if (strchr(name, '/') || strchr(name, '\\') || strchr(name, ':') || 
        strchr(name, '*') || strchr(name, '?') || strchr(name, '"') || 
        strchr(name, '<') || strchr(name, '>') || strchr(name, '|')) {
        return 0;
    }
    
    // Find free directory entry
    FatDirEntry* entry = find_free_entry(current_cluster);
    if (!entry) return 0;
    
    // Parse directory name
    char base[9], ext[4];
    memset(base, ' ', 8);
    memset(ext, ' ', 3);
    
    const char* dot = strchr(name, '.');
    if (dot) {
        uint64_t base_len = dot - name;
        if (base_len > 8) base_len = 8;
        memcpy(base, name, base_len);
        
        uint64_t ext_len = strlen(dot + 1);
        if (ext_len > 3) ext_len = 3;
        memcpy(ext, dot + 1, ext_len);
    } else {
        uint64_t name_len = strlen(name);
        if (name_len > 8) name_len = 8;
        memcpy(base, name, name_len);
    }
    
    // Create directory entry
    memcpy(entry->name, base, 8);
    memcpy(entry->ext, ext, 3);
    entry->attributes = 0x10; // Directory attribute
    entry->file_size = 0;
    
    // Allocate cluster for directory
    uint16_t new_cluster = allocate_cluster();
    if (new_cluster == 0) {
        entry->name[0] = 0xE5;
        return 0;
    }
    
    entry->cluster_low = new_cluster;
    fat_table[new_cluster] = 0xFFFF;
    
    // Initialize directory with . and .. entries
    FatDirEntry dot_entry, dotdot_entry;
    memset(&dot_entry, 0, sizeof(FatDirEntry));
    memset(&dotdot_entry, 0, sizeof(FatDirEntry));
    
    memcpy(dot_entry.name, ".       ", 8);
    dot_entry.attributes = 0x10;
    dot_entry.cluster_low = new_cluster;
    
    memcpy(dotdot_entry.name, "..      ", 8);
    dotdot_entry.attributes = 0x10;
    dotdot_entry.cluster_low = current_cluster;
    
    uint32_t sector = cluster_to_sector(new_cluster);
    FatDirEntry init_entries[2] = {dot_entry, dotdot_entry};
    write_sectors(sector, 1, init_entries);
    
    return 1;
}
uint16_t change_directory(const char* name, uint16_t current_cluster) {
    if (strcmp(name, "..") == 0) {
        if (current_cluster == 0) return 0; // Already at root
        
        // Find parent cluster from .. entry
        uint32_t sector = cluster_to_sector(current_cluster);
        FatDirEntry entries[16];
        read_sectors(sector, 1, entries);
        
        for (int i = 0; i < 16; i++) {
            if (strncmp(entries[i].name, "..      ", 8) == 0) {
                return entries[i].cluster_low;
            }
        }
        return 0xFFFF;
    }
    
    FatDirEntry* dir = find_file_in_cluster(name, current_cluster);
    if (!dir || !(dir->attributes & 0x10)) {
        return 0xFFFF;
    }
    
    return dir->cluster_low;
}
uint16_t change_directory(const char* name, uint16_t current_cluster) {
    if (strcmp(name, "..") == 0) {
        if (current_cluster == 0) return 0; // Already at root
        
        // Find parent cluster from .. entry
        uint32_t sector = cluster_to_sector(current_cluster);
        FatDirEntry entries[16];
        read_sectors(sector, 1, entries);
        
        for (int i = 0; i < 16; i++) {
            if (strncmp(entries[i].name, "..      ", 8) == 0) {
                return entries[i].cluster_low;
            }
        }
        return 0xFFFF;
    }
    
    FatDirEntry* dir = find_file_in_cluster(name, current_cluster);
    if (!dir || !(dir->attributes & 0x10)) {
        return 0xFFFF;
    }
    
    return dir->cluster_low;
}
int remove_file(const char* name, uint16_t current_cluster) {
    FatDirEntry* entry = find_file_in_cluster(name, current_cluster);
    if (!entry) return 0;
    
    // Free clusters
    uint16_t cluster = entry->cluster_low;
    while (cluster < 0xFFF8) {
        uint16_t next = fat_table[cluster];
        fat_table[cluster] = 0;
        cluster = next;
    }
    
    // Mark entry as deleted
    entry->name[0] = 0xE5;
    
    // Write back directory sector
    uint32_t sector = cluster_to_sector(current_cluster);
    write_sectors(sector, 1, (void*)((uint64_t)entry & ~0x1FF));
    
    return 1;
}
void update_prompt() {
    if (strcmp(current_dir, "/") == 0) {
        snprintf(current_prompt, MAX_PATH_LEN + 4, "/ $ ");
        return;
    }
    
    // Get current directory name by walking up the cluster chain
    char temp_dir[MAX_PATH_LEN] = "";
    uint16_t cluster = current_cluster;
    
    while (cluster != 0) {
        uint32_t sector = cluster_to_sector(cluster);
        FatDirEntry entries[16];
        read_sectors(sector, 1, entries);
        
        for (int i = 0; i < 16; i++) {
            if (strncmp(entries[i].name, "..      ", 8) == 0) {
                cluster = entries[i].cluster_low;
                break;
            }
        }
        
        for (int i = 0; i < 16; i++) {
            if (entries[i].cluster_low == current_cluster && 
                strncmp(entries[i].name, ".       ", 8) != 0 &&
                strncmp(entries[i].name, "..      ", 8) != 0) {
                char name[12];
                memcpy(name, entries[i].name, 8);
                name[8] = '\0';
                strcat(temp_dir, "/");
                strcat(temp_dir, name);
                break;
            }
        }
    }
    
    if (strlen(temp_dir) == 0) {
        strcpy(current_dir, "/");
    } else {
        strcpy(current_dir, temp_dir);
    }
    
    snprintf(current_prompt, MAX_PATH_LEN + 4, "%s $ ", current_dir);
}
int check_condition(const char* condition) {
    // Simple condition checking for if/while statements
    char var[32], op[3], value[32];
    sscanf(condition, "%s %s %s", var, op, value);
    
    // TODO: Implement proper variable lookup
    int var_val = 0;
    int cmp_val = atoi(value);
    
    if (strcmp(op, "==") == 0) {
        return var_val == cmp_val;
    } else if (strcmp(op, "!=") == 0) {
        return var_val != cmp_val;
    } else if (strcmp(op, "<") == 0) {
        return var_val < cmp_val;
    } else if (strcmp(op, ">") == 0) {
        return var_val > cmp_val;
    } else if (strcmp(op, "<=") == 0) {
        return var_val <= cmp_val;
    } else if (strcmp(op, ">=") == 0) {
        return var_val >= cmp_val;
    }
    
    return 0;
}
void store_function(const char* name, const char* body) {
    // TODO: Implement proper function storage
    // For now just print the definition
    char msg[256];
    snprintf(msg, sizeof(msg), "Defined function %s: %s", name, body);
    print_info(msg);
}
// Helper to find file in specific cluster
FatDirEntry* find_file_in_cluster(const char* name, uint16_t cluster) {
    uint32_t sector = cluster_to_sector(cluster);
    FatDirEntry entries[16];
    read_sectors(sector, 1, entries);
    
    for (int i = 0; i < 16; i++) {
        if (entries[i].name[0] == 0xE5 || entries[i].name[0] == 0) continue;
        
        char fullname[12];
        memcpy(fullname, entries[i].name, 8);
        fullname[8] = '.';
        memcpy(fullname + 9, entries[i].ext, 3);
        fullname[12] = '\0';
        
        if (strcmp(fullname, name) == 0) {
            return &entries[i];
        }
    }
    return NULL;
}

// Helper to read file from specific cluster
uint64_t read_file_from_cluster(FatDirEntry* file, void* buffer, uint16_t cluster) {
    // Same as original read_file but respects cluster parameter
    uint16_t file_cluster = file->cluster_low;
    uint64_t size = file->file_size;
    uint8_t* ptr = (uint8_t*)buffer;
    uint64_t read = 0;
    
    while (file_cluster < 0xFFF8 && read < size) {
        uint32_t sector = cluster_to_sector(file_cluster);
        
        for (int i = 0; i < boot_sector->sectors_per_cluster; i++) {
            uint8_t sector_buf[SECTOR_SIZE];
            read_sectors(sector + i, 1, sector_buf);
            
            uint64_t to_copy = SECTOR_SIZE;
            if (read + to_copy > size) {
                to_copy = size - read;
            }
            
            memcpy(ptr, sector_buf, to_copy);
            ptr += to_copy;
            read += to_copy;
            
            if (read >= size) break;
        }
        
        file_cluster = fat_table[file_cluster];
    }
    
    return read;
}

// Helper to convert cluster to sector
uint32_t cluster_to_sector(uint16_t cluster) {
    return boot_sector->reserved_sectors + 
           (boot_sector->fat_count * boot_sector->sectors_per_fat) +
           ((cluster - 2) * boot_sector->sectors_per_cluster);
}

// Helper to allocate new cluster
uint16_t allocate_cluster() {
    for (uint16_t i = 2; i < 0xFFF0; i++) {
        if (fat_table[i] == 0) {
            fat_table[i] = 0xFFFF;
            return i;
        }
    }
    return 0;
}

// Helper to find free directory entry
FatDirEntry* find_free_entry(uint16_t cluster) {
    uint32_t sector = cluster_to_sector(cluster);
    FatDirEntry entries[16];
    read_sectors(sector, 1, entries);
    
    for (int i = 0; i < 16; i++) {
        if (entries[i].name[0] == 0xE5 || entries[i].name[0] == 0) {
            return &entries[i];
        }
    }
    return NULL;
}
void nano(const char* filename) {
    #define NANO_ROWS (ROWS - 2)
    #define NANO_COLS COLS
    
    uint16_t original_pos = cursor_pos;
    Color original_fg = COLOR_WHITE;
    Color original_bg = COLOR_BLACK;
    
    // 加载文件内容
    FatDirEntry* file = find_file_in_cluster(filename, current_cluster);
    char* buffer = (char*)0x300000;
    uint64_t file_size = 0;
    
    if (file) {
        file_size = read_file_from_cluster(file, buffer, current_cluster);
        buffer[file_size] = '\0';
    } else {
        buffer[0] = '\0';
    }
    
    // 初始化编辑状态
    uint16_t cursor_x = 0;
    uint16_t cursor_y = 0;
    uint16_t offset = 0;
    uint16_t lines = 0;
    char modified = 0;
    
    // 计算行数
    for (uint64_t i = 0; i < file_size; i++) {
        if (buffer[i] == '\n') lines++;
    }
    if (file_size > 0 && buffer[file_size-1] != '\n') lines++;
    
    // 主编辑循环
    clear_screen(COLOR_BLACK, COLOR_LGRAY);
    puts("TOS Nano Editor - Ctrl+S: Save | Ctrl+X: Exit", COLOR_BLACK, COLOR_WHITE);
    
    while (1) {
        // 显示文本内容
        uint16_t display_lines = 0;
        uint64_t line_start = 0;
        
        for (uint64_t i = 0; i < file_size && display_lines < NANO_ROWS; ) {
            uint64_t line_end = i;
            while (line_end < file_size && buffer[line_end] != '\n') line_end++;
            
            if (display_lines >= offset) {
                uint16_t row = display_lines - offset + 1;
                uint16_t col = 0;
                
                // 清除行
                for (col = 0; col < NANO_COLS; col++) {
                    video_mem[row * COLS + col] = (COLOR_BLACK << 12) | (COLOR_LGRAY << 8) | ' ';
                }
                
                // 显示行内容
                col = 0;
                for (uint64_t j = i; j < line_end && col < NANO_COLS; j++, col++) {
                    video_mem[row * COLS + col] = (COLOR_BLACK << 12) | (COLOR_LGRAY << 8) | buffer[j];
                }
            }
            
            if (line_end < file_size) line_end++;
            i = line_end;
            display_lines++;
        }
        
        // 显示状态栏
        char status[COLS];
        snprintf(status, COLS, "File: %s - Lines: %d - %s", 
                filename, lines + 1, modified ? "Modified" : "");
        for (int i = 0; i < COLS; i++) {
            video_mem[(ROWS - 1) * COLS + i] = (COLOR_WHITE << 12) | (COLOR_BLACK << 8) | 
                                              (i < strlen(status) ? status[i] : ' ');
        }
        
        // 设置光标位置
        uint16_t cursor_screen_pos = (cursor_y - offset + 1) * COLS + cursor_x;
        if (cursor_screen_pos < COLS * ROWS) {
            uint16_t* cursor_cell = &video_mem[cursor_screen_pos];
            *cursor_cell = (*cursor_cell & 0xFF00) | 0x5F; // 下划线光标
            set_cursor(cursor_screen_pos);
        }
        
        // 处理输入
        char c = getchar();
        
        // 清除光标效果
        if (cursor_screen_pos < COLS * ROWS) {
            uint16_t* cursor_cell = &video_mem[cursor_screen_pos];
            *cursor_cell = (*cursor_cell & 0xFF00) | buffer[cursor_y * COLS + cursor_x];
        }
        
        // 处理控制键
        if (c == 0x1D) { // Ctrl
            c = getchar();
            switch (c) {
                case 's': // Ctrl+S 保存
                    if (write_to_file(filename, buffer, strlen(buffer), current_cluster)) {
                        modified = 0;
                        print_info("File saved successfully");
                    } else {
                        print_error("Failed to save file");
                    }
                    continue;
                case 'x': // Ctrl+X 退出
                    clear_screen(original_bg, original_fg);
                    set_cursor(original_pos);
                    return;
                case 'k': // Ctrl+K 删除行
                    // 实现删除行逻辑
                    continue;
            }
        }
        
        // 处理普通键
        switch (c) {
            case '\n': // 回车
                // 实现换行逻辑
                break;
            case '\b': // 退格
                if (cursor_x > 0 || cursor_y > 0) {
                    // 实现退格逻辑
                    modified = 1;
                }
                break;
            case 0x1B: // ESC
                // 处理方向键
                c = getchar(); // 跳过[
                c = getchar();
                switch (c) {
                    case 'A': // 上
                        if (cursor_y > 0) cursor_y--;
                        break;
                    case 'B': // 下
                        if (cursor_y < lines) cursor_y++;
                        break;
                    case 'C': // 右
                        if (cursor_x < NANO_COLS - 1) cursor_x++;
                        break;
                    case 'D': // 左
                        if (cursor_x > 0) cursor_x--;
                        break;
                }
                break;
            default: // 普通字符
                if (c >= 32 && c <= 126) {
                    // 实现字符插入
                    modified = 1;
                }
                break;
        }
        
        // 调整偏移
        if (cursor_y < offset) {
            offset = cursor_y;
        } else if (cursor_y >= offset + NANO_ROWS) {
            offset = cursor_y - NANO_ROWS + 1;
        }
    }
}

}

// Shell
void shell() {
    char input[MAX_CMD_LEN + 1];
    uint64_t pos = 0;
    
    puts("TOS (C) 2025 Tongshun - Type 'help' for commands", COLOR_LGREEN, COLOR_BLACK);
    
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
