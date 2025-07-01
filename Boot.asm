; boot.asm - 简单引导程序
[bits 16]
[org 0x7C00]

; 设置栈和段寄存器
start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    ; 设置视频模式
    mov ax, 0x0003
    int 0x10

    ; 显示加载信息
    mov si, loading_msg
    call print

    ; 加载内核 (从第2个扇区开始，加载127个扇区=63.5KB)
    mov ah, 0x02
    mov al, 127
    mov ch, 0
    mov cl, 2
    mov dh, 0
    mov bx, 0x7E00
    int 0x13
    jc disk_error

    ; 检查内核签名
    cmp word [0x7E00], 0x4F54  ; 'TO'签名
    jne kernel_error

    ; 跳转到内核
    jmp 0x7E00

; 磁盘错误处理
disk_error:
    mov si, disk_error_msg
    call print
    hlt

; 内核错误处理
kernel_error:
    mov si, kernel_error_msg
    call print
    hlt

; 打印字符串
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
loading_msg db "Loading TOS...", 0x0D, 0x0A, 0
disk_error_msg db "Disk error!", 0
kernel_error_msg db "Invalid kernel!", 0

; 填充引导扇区
times 510-($-$$) db 0
dw 0xAA55
