# PWN Challenges CTF

### Getting Started
```powershell
file CodeFile  #Check File Type
gcc CodeFile.c -o CodeFile -fno-stack-protector -z execstack -no-pie -m32  #Compile a code
checksec --file CodeFile  #Protection Check
```

### Compile a code
```powershell
gcc CodeFile.c -o CodeFile -fstack-protector-all  #Compile a 64-bits with all protection enabled
gcc CodeFile.c -o CodeFile -fno-stack-protector -z execstack -no-pie -m32  #Compile a 32-bits code with no protections
```

### Checksec
```powershell
checksec --file CodeFile
	Arch:	64-bit/32-bit
	RELRO:	Partial RELRO
	Stack:	Canary Found
	NX:	NX enabled (no execution enabled)
	PIE:	PIE enabled
```

### load the File
```powershell
file CodeFile  #Load the file
info functions  #existing functions in the code
```
```powershell
#Output
0x08049000  _init
0x08049030  __libc_start_main@plt
0x08049040  gets@plt
0x08049050  puts@plt
0x08049060  _start
0x0804908d  __wrap_main
0x080490a0  _dl_relocate_static_pie
0x080490b0  __x86.get_pc_thunk.bx
0x080490c0  deregister_tm_clones
0x08049100  register_tm_clones
0x08049140  __do_global_dtors_aux
0x08049170  frame_dummy
0x08049176  main
0x080491c4  _fini
```

### Disassembler
```powershell
disassemble main
break main  #Adding a break point
run  #run the code and stop at the break point
n  #for next (goes to the next instraction)
c  #for continue (run the program)
delete breakpoints
```
![image](https://github.com/user-attachments/assets/c7ffea14-d292-47ba-b137-428f8f3d35b7)




