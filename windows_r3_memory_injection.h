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
