Today I come with a new library that I have programmed for C/C++, this one has the function firstly, to demonstrate some concepts of Hooking, for now they only serve for the same process of the application in which it is executed, with the objective to redirect functions, to optimize memory gaps, and something more.

In the future it will be expanded along with another mix of functions and remote hooks/injections, for now I will only demonstrate the following concepts that the library can do:
[+] Hooke a function to jump to another one.
[+] Unhook to restore the function.
[+] Completely disassemble a function and read it in opcodes.
[+] Get the exact size of a function.
[+] NOP a function (Detect RET, i.e. it can exit without errors or access violations).
[+] Write in an exact memory address, one or as many values as you want (dangerous operations).

This library is 100% made by me, it does not contain rips, since its objective is to first understand and realize the features described above, and then be able to adapt it to another level.

NOTE: On the internet I found a lot of generic code, and many rips but I have not seen anyone implement this method nor in concepts, I guess many start with remote injections without first knowing how hooks, jumps, memory overwrite etc... works.

Code:
```C
#include <windows.h>

#ifndef __NVK_OPS__
    #define NOP()__asm__ volatile("nop;");
    #define SaveMemoryContext(FADDRESS, SAVE_LABEL) \
        BYTE SAVE_LABEL[0x6]; \
        SaveMemoryContextEx(FADDRESS, SAVE_LABEL);

    int SizeMemoryAddress(int* FAddress);
    void ReadDisassembleMemory(int *FAddress, BYTE *PByteBuffer);
    void HookMemoryAddress(int *FAddress, int *HijackAddr);
    void SaveMemoryContextEx(int *FAddress, BYTE SaveBuffer[]);
    void UnhookMemoryAddress(int* FAddress, BYTE UnhookBytes[]);
    void PoolNOPAddress(int *FAddress);
    void WriteMemory(int *FAddress, int BeginPointer, BYTE writeByte[]);

#endif // __NVK_OPS__

int SizeMemoryAddress(int* FAddress)
{
    BYTE *TotalBytes;
    for(int readBytes=0;;readBytes++)
    {
        TotalBytes= (BYTE *)malloc(readBytes +sizeof(BYTE));
        MoveMemory((BYTE *)&TotalBytes[readBytes], (void *)FAddress+readBytes, 0x1);
        if(TotalBytes[readBytes]==0xc3)
            return(readBytes);
    }
    free(TotalBytes);

    return 0;
}

void ReadDisassembleMemory(int *FAddress, BYTE *PByteBuffer)
{
    for(int readBytes=0;;readBytes++)
    {
        MoveMemory((BYTE *)&PByteBuffer[readBytes], (void *)FAddress+readBytes, 0x1);
        if(PByteBuffer[readBytes]==0xc3)
            break;
    }
}

void HookMemoryAddress(int *FAddress, int *HijackAddr)
{
    DWORD lpflOldProtect;
    BYTE jmp[] = {
        0xe9,                       // JMP
        0x00, 0x00, 0x00, 0x00,     // Futura direccion de la funcion a saltar.
        0xc3                        // RETN
    };

    int funcSize= SizeMemoryAddress((int *)FAddress);
    DWORD jmp_size= ((DWORD)HijackAddr - (DWORD)FAddress); // tecnica de hijack clasica.
    jmp_size -= 0x05;

    if(VirtualProtect((void *)FAddress, funcSize, PAGE_EXECUTE_READWRITE, &lpflOldProtect))
    {
        CopyMemory(&jmp[1], (DWORD *)&jmp_size, 0x04); //for(int d=0; d<sizeof(jmp); d++)printf("jmp buffer: 0x%x \t+%d \n", jmp[d], d);
        MoveMemory((DWORD *)FAddress, (BYTE *)jmp , sizeof(jmp) );
    }
}

void SaveMemoryContextEx(int *FAddress, BYTE SaveBuffer[])
{
    BYTE UnhookBytes [] =
    {
        // Re-configurar stack frame.
        0x55,               /// - PUSH EBP
        0x89, 0xE5,         /// - MOV EBP,ESP
        0x00, 0x00, 0x00
    };
    BYTE saveOriginalFunc[6];

    CopyMemory((BYTE *)&saveOriginalFunc, (DWORD *)FAddress, sizeof(saveOriginalFunc)); // 004016b9
    MoveMemory((BYTE *)&UnhookBytes[3], (BYTE *)&saveOriginalFunc[3] , 3); // - 3 bytes despues del stack frame.
    CopyMemory((BYTE *)SaveBuffer, (BYTE *)UnhookBytes, sizeof(UnhookBytes)); //for(int x=0; x<6; x++) printf("-0x%x\n", UnhookBytes[x]); // Para debug.
}

void UnhookMemoryAddress(int* FAddress, BYTE UnhookBytes[])
{
    __asm__
    (
        "sub $0x18, %%esp;"
        "movl $0x6, 0x8(%%esp);" // longitud 6
        //"mov 0xc(%%ebp), %%eax;"

        "mov %%eax, 0x4(%%esp);"
        "mov 0x8(%%ebp), %%eax;"
        "mov %%eax, (%%esp);"
        "call _memmove;"
        "leave;"
        "ret;"

        ::"a"((BYTE *)&UnhookBytes[0])
    );
}

void PoolNOPAddress(int *FAddress)
{
    DWORD lpflOldProtect;
    int funcSize= SizeMemoryAddress((int *)FAddress);
    BYTE NOPS[funcSize];

    memset(&NOPS, 0x90, sizeof(NOPS)); // llenar el array de nops
    if(VirtualProtect((void *)FAddress, funcSize, PAGE_EXECUTE_READWRITE, &lpflOldProtect))
        MoveMemory((DWORD *)FAddress, (BYTE *)NOPS, sizeof(NOPS));
}

void WriteMemory(int *FAddress, int BeginPointer, BYTE writeByte[])
{
    DWORD lpflOldProtect;
    int funcSize= SizeMemoryAddress((int *)FAddress);
    int align_size_array= (sizeof(writeByte)/sizeof(writeByte[0]))-0x1;

    if(VirtualProtect((void *)FAddress, funcSize, PAGE_EXECUTE_READWRITE, &lpflOldProtect))
    {
        if(align_size_array>1)
            MoveMemory((DWORD *)FAddress + BeginPointer, (BYTE *)writeByte , align_size_array );
        else
            *(DWORD *)(FAddress + BeginPointer)= *(BYTE *)writeByte;
    }
}
```

Some examples:

Hook function
```C
// Funcion a hookear.
int xprintf()
{
    printf("[!]Funcion original.\n");
    return 0;
}

// Funcion sobreescrita.
int xwrite()
{
    for(int x=0; x<3; x++)
        printf("[+]Funcion hookeada!\n");
}

// Hook
int main()
{
	printf("Direccion funcion original -> 0x%p\n\n", & xprintf);
	
  xprintf();

  HookMemoryAddress((int *)&xprintf, (int*)&xwrite);

  xprintf();
}
```

Hook and Unhook.

```C
printf("Direccion funcion original -> 0x%p\n\n", & xprintf);

SaveMemoryContext((int*)&xprintf, SaveBuffer);

xprintf();

HookMemoryAddress((int *)&xprintf, (int*)&xwrite);

xprintf();

UnhookMemoryAddress((int *)&xprintf, SaveBuffer);

xprintf();
```

Disassemble the function.

```C
printf("Direccion funcion original -> 0x%p\n\n", & xprintf);
// Size of the function
int funcSize= SizeMemoryAddress((int *)xprintf);
BYTE disBuf[funcSize];

printf("Tam de la funcion: %d\n", funcSize);
	
// Function disassembly and looping.
ReadDisassembleMemory((int *)&xprintf , disBuf);
for (int bytes=0; bytes<=funcSize; bytes++)
  printf("-0x%x\n", disBuf[bytes]);
```

Write a memory area.

```C
// Write a NOP(ampersand required) byte.
BYTE writeBuff = 0x90;
WriteMemory((int *)&xprintf, 0, (BYTE *)&writeBuff);

// Write several bytes.
// Write 3 nops starting at position 3 of the function (not ampersand, but in an array).
BYTE writeBuff[]= {0x90, 0x90, 0x90};
WriteMemory((int *)&xprintf, 3, (BYTE *)writeBuff);
```

NOP the entire function up to RET(autodetect).
```C
printf("Direccion funcion a nopear -> 0x%p\n\n", & xprintf);
PoolNOPAddress((int *)&xprintf);
```
