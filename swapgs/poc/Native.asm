.code
	
	__native__swapgs PROC
			swapgs
			ret
	__native__swapgs ENDP

	__native__read_gs_base PROC
			rdgsbase rax
			ret
	__native__read_gs_base ENDP

	__native__set_gs_base PROC
			wrgsbase rcx
			ret
	__native__set_gs_base ENDP

	__native__read_ss PROC
			xor eax, eax
			mov ax, ss
			ret
	__native__read_ss ENDP

	__native__ud2 PROC
			ud2
			ret
	__native__ud2 ENDP

	__native_train PROC
			test byte ptr[rcx], 1
			jne exit
			mov r10, qword ptr[rcx]
			ret
		exit:
			ret
	__native_train ENDP

	__native_train_is_done PROC
			test byte ptr[rcx], 1
			jne exit
			mov cl, byte ptr[rdx]
			ret
		exit:
			ret
	__native_train_is_done ENDP
end