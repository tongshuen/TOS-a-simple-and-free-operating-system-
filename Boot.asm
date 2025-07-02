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

    ; 加载内核到1MB地址(0x100000)
    mov edi, 0x100000    
    mov ecx, 1           ; 从第2扇区开始
    mov ebx, 255         ; 加载255个扇区(127.5KB)
.load_loop:
    mov eax, ecx
    call read_sector
    add edi, 512
    inc ecx
    dec ebx
    jnz .load_loop

    ; 启用A20线
    call enable_a20

    ; 加载临时GDT
    lgdt [gdt_ptr]

    ; 进入保护模式
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    ; 远跳转清空流水线
    jmp 0x08:protected_mode

[bits 32]
protected_mode:
    ; 设置段寄存器
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; 设置栈指针
    mov esp, 0x7C00

    ; 检查CPU是否支持长模式
    call check_long_mode
    jc .no_long_mode

    ; 设置页表 (简化版4级分页)
    call setup_paging

    ; 启用长模式
    mov ecx, 0xC0000080
    rdmsr
    or eax, 0x100
    wrmsr

    ; 启用分页
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax

    ; 加载64位GDT
    lgdt [gdt64_ptr]

    ; 跳转到64位内核
    jmp 0x08:0x100000

.no_long_mode:
    mov esi, no_long_mode_msg
    call print32
    hlt

[bits 32]
enable_a20:
    ; 尝试多种A20启用方法
    mov ax, 0x2401
    int 0x15
    jc .kb_controller
    ret
.kb_controller:
    in al, 0x64
    test al, 0x02
    jnz .kb_controller
    mov al, 0xD1
    out 0x64, al
.kb_controller_wait:
    in al, 0x64
    test al, 0x02
    jnz .kb_controller_wait
    mov al, 0xDF
    out 0x60, al
    ret

check_long_mode:
    ; 检查CPUID是否可用
    pushfd
    pop eax
    mov ecx, eax
    xor eax, 0x200000
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

    ; 检查长模式支持
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

setup_paging:
    ; 清零页表区域 (0x8000-0x9000)
    mov edi, 0x8000
    mov ecx, 0x1000/4
    xor eax, eax
    rep stosd

    ; 设置PML4 (0x8000)
    mov dword [0x8000], 0x9000 | 0x03  ; 指向PDPT
    mov dword [0x8004], 0

    ; 设置PDPT (0x9000)
    mov dword [0x9000], 0xA000 | 0x03  ; 指向PD
    mov dword [0x9004], 0

    ; 设置PD (0xA000)
    mov dword [0xA000], 0xB000 | 0x03  ; 指向PT
    mov dword [0xA004], 0

    ; 设置PT (0xB000) - 映射前2MB
    mov edi, 0xB000
    mov eax, 0x00000003
    mov ecx, 512
.set_pt:
    stosd
    add eax, 0x1000
    loop .set_pt

    ; 设置CR3
    mov eax, 0x8000
    mov cr3, eax
    ret

print32:
    mov edi, 0xB8000
.print_loop:
    lodsb
    or al, al
    jz .done
    mov [edi], al
    add edi, 2
    jmp .print_loop
.done:
    ret

[bits 16]
read_sector:
    mov dword [lba_packet.lba_low], eax
    mov word [lba_packet.offset], di
    mov word [lba_packet.segment], 0

    mov ah, 0x42
    mov dl, 0x80
    mov si, lba_packet
    int 0x13
    jc disk_error
    ret

disk_error:
    mov si, disk_error_msg
    call print
    hlt

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

; 数据区
loading_msg db "TOS boot loader (C) 2025 Tongshun. Booting TOS...", 0
disk_error_msg db "Disk error!", 0
no_long_mode_msg db "ERROR: CPU does not support long mode", 0

; 32位GDT
gdt:
    dq 0
    dw 0xFFFF, 0
    db 0, 0x9A, 0xCF, 0  ; 代码段
    dw 0xFFFF, 0
    db 0, 0x92, 0xCF, 0  ; 数据段
gdt_ptr:
    dw $ - gdt - 1
    dd gdt

; 64位GDT
gdt64:
    dq 0
    dq 0x0020980000000000  ; 代码段
    dq 0x0000920000000000  ; 数据段
gdt64_ptr:
    dw $ - gdt64 - 1
    dd gdt64

lba_packet:
    db 0x10        ; 包大小
    db 0           ; 保留
    dw 1           ; 扇区数
.offset: dw 0      ; 偏移
.segment: dw 0     ; 段
.lba_low: dd 0     ; LBA低32位
.lba_high: dd 0    ; LBA高32位

times 510-($-$$) db 0
dw 0xAA55

