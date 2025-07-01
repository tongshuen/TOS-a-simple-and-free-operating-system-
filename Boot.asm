; boot.asm - TOS 的引导程序
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
    mov ebx, 127         ; 加载127个扇区(63.5KB)
.load_loop:
    mov eax, ecx
    call read_sector
    add edi, 512
    inc ecx
    dec ebx
    jnz .load_loop

    ; 直接跳转到内核入口
    jmp 0x100000

; 读取扇区(LBA)
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
loading_msg db "Loading kernel...", 0
disk_error_msg db "Disk error!", 0

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

