; boot.asm - 兼容64位内核的引导程序
[bits 16]
[org 0x7C00]

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    ; 显示加载信息
    mov si, loading_msg
    call print

    ; 检查长模式支持
    call check_long_mode
    jc .no_long_mode

    ; 设置临时GDT
    lgdt [gdt_ptr]

    ; 启用PAE
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax

    ; 配置页表
    mov edi, 0x9000
    mov cr3, edi
    xor eax, eax
    mov ecx, 6 * 4096 / 4
    rep stosd
    
    ; 设置4级分页
    mov dword [0x9000], 0xA003  ; PML4
    mov dword [0xA000], 0xB003  ; PDP
    mov dword [0xB000], 0xC003  ; PD
    mov dword [0xC000], 0x83    ; 2MB大页

    ; 启用长模式
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr

    ; 启用分页和保护模式
    mov eax, cr0
    or eax, 1 << 31 | 1 << 0
    mov cr0, eax

    ; 跳转到64位代码
    jmp 0x08:long_mode_entry

.no_long_mode:
    mov si, no_long_mode_msg
    call print
    hlt

check_long_mode:
    ; 检查CPUID支持
    pushfd
    pop eax
    mov ecx, eax
    xor eax, 1 << 21
    push eax
    popfd
    pushfd
    pop eax
    xor eax, ecx
    jz .no_cpuid

    ; 检查扩展功能
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode

    ; 检查长模式位
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .no_long_mode
    clc
    ret

.no_cpuid:
.no_long_mode:
    stc
    ret

print:
    mov ah, 0x0E
.print_loop:
    lodsb
    or al, al
    jz .done
    int 0x10
    jmp .print_loop
.done:
    ret

[bits 64]
long_mode_entry:
    ; 设置段寄存器
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov rsp, 0x7C00

    ; 加载内核 (从第2扇区开始)
    mov edi, 0x100000    ; 内核加载地址
    mov ecx, 1           ; 起始扇区
    mov ebx, 127         ; 扇区数

.load_kernel:
    mov eax, ecx
    call read_sector
    add edi, 512
    inc ecx
    dec ebx
    jnz .load_kernel

    ; 验证内核签名
    cmp dword [0x100000], 0x4F54534F ; "OSTOS"
    jne .invalid_kernel

    ; 跳转到内核
    jmp 0x100008

.invalid_kernel:
    mov dword [0xB8000], 0x4F204F49 ; "IN"
    mov dword [0xB8004], 0x4F4C4F56 ; "VA"
    mov dword [0xB8008], 0x4F444F4C ; "LI"
    mov dword [0xB800C], 0x4F204F44 ; "D "
    hlt

[bits 32]
read_sector:
    ; 设置LBA包
    mov dword [lba_packet.lba_low], eax
    mov word [lba_packet.offset], di
    mov word [lba_packet.segment], 0

    ; 读取扇区
    mov ah, 0x42
    mov dl, 0x80
    mov si, lba_packet
    int 0x13
    jc .disk_error
    ret

.disk_error:
    mov dword [0xB8000], 0x4F444F44 ; "DI"
    mov dword [0xB8004], 0x4F4B4F53 ; "SK"
    mov dword [0xB8008], 0x4F524F45 ; "ER"
    mov dword [0xB800C], 0x4F524F52 ; "RO"
    hlt

; 数据区
loading_msg db "Loading 64-bit kernel...", 0
no_long_mode_msg db "No 64-bit support!", 0

lba_packet:
    db 0x10        ; 包大小
    db 0           ; 保留
    dw 1           ; 扇区数
.offset: dw 0      ; 偏移
.segment: dw 0     ; 段
.lba_low: dd 0     ; LBA低32位
.lba_high: dd 0    ; LBA高32位

gdt:
    dq 0x0000000000000000    ; 空描述符
    dq 0x00AF9A000000FFFF    ; 64位代码段
    dq 0x00AF92000000FFFF    ; 64位数据段
gdt_ptr:
    dw $ - gdt - 1           ; GDT界限
    dd gdt                   ; GDT地址

times 510-($-$$) db 0
dw 0xAA55
