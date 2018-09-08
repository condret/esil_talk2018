format ELF executable
segment readable executable

SYS_OPEN=5
SYS_WRITE=4

entry $
	xor eax, eax
	add eax, SYS_OPEN
	mov ebx, ffile
	mov ecx, 6
	mov edx, 420
	int 0x80
	mov ebx, eax
	mov eax, SYS_WRITE
	mov ecx, string
	mov edx, 6
	int 0x80

segment readable
ffile:
    db "testfile",0
string:
    db "workz",0xa,0

