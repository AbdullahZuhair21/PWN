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
# info function output
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
```powershell
# disassemble main output
(gdb) disassemble main
Dump of assembler code for function main:
   0x08049176 <+0>:     lea    0x4(%esp),%ecx
   0x0804917a <+4>:     and    $0xfffffff0,%esp
   0x0804917d <+7>:     push   -0x4(%ecx)
   0x08049180 <+10>:    push   %ebp
   0x08049181 <+11>:    mov    %esp,%ebp
   0x08049183 <+13>:    push   %ebx
   0x08049184 <+14>:    push   %ecx
   0x08049185 <+15>:    sub    $0x10,%esp
   0x08049188 <+18>:    call   0x80490b0 <__x86.get_pc_thunk.bx>
   0x0804918d <+23>:    add    $0x2e67,%ebx
   0x08049193 <+29>:    sub    $0xc,%esp
   0x08049196 <+32>:    lea    -0x1fec(%ebx),%eax
   0x0804919c <+38>:    push   %eax
   0x0804919d <+39>:    call   0x8049050 <puts@plt>
   0x080491a2 <+44>:    add    $0x10,%esp
   0x080491a5 <+47>:    sub    $0xc,%esp
   0x080491a8 <+50>:    lea    -0x18(%ebp),%eax
   0x080491ab <+53>:    push   %eax
   0x080491ac <+54>:    call   0x8049040 <gets@plt>
   0x080491b1 <+59>:    add    $0x10,%esp
   0x080491b4 <+62>:    mov    $0x0,%eax
   0x080491b9 <+67>:    lea    -0x8(%ebp),%esp
   0x080491bc <+70>:    pop    %ecx
   0x080491bd <+71>:    pop    %ebx
   0x080491be <+72>:    pop    %ebp
   0x080491bf <+73>:    lea    -0x4(%ecx),%esp
   0x080491c2 <+76>:    ret
End of assembler dump.

```



