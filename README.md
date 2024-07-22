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
![image](https://github.com/user-attachments/assets/15b877b7-01b6-4f44-8073-833e762331c9)

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




