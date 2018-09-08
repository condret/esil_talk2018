format ELF executable
segment readable executable

SYS_OPEN=5
SYS_WRITE=4
SYS_READ=3

STDIN=0

entry $
	xor eax, eax
	add eax, SYS_READ
	xor ebx, ebx
	mov ecx, buffer
	mov edx, 4
	int 0x80

segment readable writeable
buffer:
    db 0,0,0,0,0

