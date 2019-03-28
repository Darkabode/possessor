#ifndef __POSSESSOR_UTILS_H_
#define __POSSESSOR_UTILS_H_

/*
#define ALIGN_DOWN(x, align)(x &~ (align - 1))
#define ALIGN_UP(x, align)((x & (align - 1))?ALIGN_DOWN(x, align) + align:x)
#define RtlOffsetToPointer(B,O) ((PCHAR)(((PCHAR)(B)) + ((ULONG_PTR)(O))))
#define RtlPointerToOffset(B,P) ((ULONG_PTR)(((PCHAR)(P)) - ((PCHAR)(B))))
#define FlagOn(x, f) ((x) & (f))
#define MAKE_PTR(B, O, T) ((T)RtlOffsetToPointer(B, O))


#define IFMT32 "0x%.8x"
#define IFMT64 "0x%.16I64x"

#define IFMT32_W L"0x%.8x"
#define IFMT64_W L"0x%.16I64x"

#ifndef _WIN64
#define IFMT IFMT32
#define IFMT_W IFMT32_W
#else
#define IFMT IFMT64
#define IFMT_W IFMT64_W
#endif

    int xwcsicmp(wchar_t *s1, wchar_t *s2);
    int xstrcmp(char *s1, char *s2);
    size_t xstrlen(char *org);
    VOID xRtlInitAnsiString(PANSI_STRING DestinationString, PCHAR SourceString);
//     PCHAR UtiStrNCpyM(PCHAR pcSrc, DWORD_PTR dwLen);
//     VOID UtiStrNCpy(PCHAR pcDst, PCHAR pcSrc, DWORD_PTR dwLen);

    int utils_pe_set_dll_flag(const wchar_t* lpPath);
    
    DWORD RvaToOffset(PIMAGE_NT_HEADERS pPE,DWORD dwRva);

//     VOID DeleteFileReboot(PCHAR pcFilePath);

    VOID GetRandomString(PCHAR lpszBuf, DWORD cbBuf);
    HANDLE utils_create_check_mutex(DWORD id, PCHAR sign);
//     BOOL utils_check_mutex(DWORD id, PCHAR sign);

//     DWORD GetProcessIntegrityLevel();
//     BOOL CheckAdmin();
//     BOOL CheckUAC();
//     VOID GetWindowsVersion(PCHAR pcBuffer, DWORD dwSize);

//     VOID GetParrentProcessName(PCHAR FileName, DWORD Size);
    DWORD GetProcessIdByName(PCHAR ProcessName, PDWORD Processes, DWORD Max);

    NTSTATUS utils_map_section(PWCHAR SectionName, PHANDLE SectionHandle, PVOID *BaseAddress, DWORD_PTR *ViewSize);
    int utils_create_zmodule_mapping(char* name, const uint8_t* pImageBase, uint32_t imageSize, HANDLE* phCurrentImageSection, int needRelocate);

    LONG utils_reg_read_valueA(HKEY RootKeyHandle, const char* SubKeyName, const char* ValueName, DWORD Type, PVOID Buffer, DWORD Len);
    LONG utils_reg_read_valueW(HKEY RootKeyHandle, const wchar_t* SubKeyName, const wchar_t* ValueName, DWORD Type, PVOID Buffer, DWORD Len, int onlyWow64);
    
    BOOLEAN ReplaceIAT(PCHAR ModuleName, PCHAR Current, PVOID New, HMODULE Module);
//     BOOLEAN StringTokenBreak(PCHAR *ppcSrc, PCHAR pcToken, PCHAR *ppcBuffer);
//     BOOL SetPrivilege(char* SeNamePriv, BOOL EnableTF);
    
//     VOID RestartModuleShellExec(PCHAR FilePath);
//     BOOL StartExe(LPSTR lpFilePath);
//     BOOLEAN WriteFileAndExecute(PVOID File, DWORD Size);

//     DWORD_PTR ExecExportProcedure(PVOID ModuleBase, PCHAR pcProcedure, PCHAR pcParameters);

//     PVOID UtiCryptRc4M(PCHAR pcKey, DWORD dwKey, PVOID pvBuffer, DWORD dwBuffer);
//     VOID UtiCryptRc4(PCHAR pcKey, DWORD dwKey, PVOID pvDst, PVOID pvSrc, DWORD dwLen);


    DWORD SearchBytesInMemory(PVOID RegionCopy, DWORD_PTR RegionSize, PVOID Bytes, DWORD Length);
    DWORD SearchDwordInMemory(PVOID RegionCopy, DWORD_PTR RegionSize, DWORD Dword);
    DWORD SearchBytesInReadedMemory(HANDLE ProcessHandle, PVOID BaseAddress, DWORD_PTR Size, PVOID Bytes, DWORD Length);
    PVOID SearchBytesInProcessMemory(HANDLE ProcessHandle, PVOID Bytes, DWORD Length);
    DWORD SearchCodeInProcessModules(HANDLE ProcessHandle, PVOID Bytes, DWORD Length);

    HANDLE utils_file_lock(const wchar_t* lpFile, DWORD dwAccess, DWORD dwDisposition);
    void utils_file_unlock(HANDLE hFile);

    int utils_lzma_decompress(pvoid_t inStream, DWORD inSize, pvoid_t* outStream, PDWORD poutSize);
    void check_priveleges();
#ifndef _WIN64
    uint32_t util_get_hash_from_istr_a(const char* pszString);

    void util_initialize_list_head(PLIST_ENTRY pListHead);
    bool_t util_is_list_empty(const PLIST_ENTRY pListHead);
    bool_t util_remove_entry_list(PLIST_ENTRY pEntry);
    void util_insert_tail_list(PLIST_ENTRY pListHead, PLIST_ENTRY pEntry);

#endif // _WIN64

    void utils_fix_32value(uint8_t* pData, uint32_t size, uint32_t oldValue, uint32_t newValue);
    void utils_fix_64value(uint8_t* pData, uint32_t size, uint64_t oldValue, uint64_t newValue);


    void utils_get_temp_name(wchar_t* tempFileName, int maxSize);

    uint32_t utils_get_current_unixtime();
// 
// typedef struct _WINET_LOADURL
// {
//     PCHAR pcUrl;
//     PCHAR pcMethod;
//     PCHAR pcHeaders;
//     DWORD dwHeaders;
//     PVOID pvPstData;
//     DWORD dwPstData;
//     DWORD dwStatus;
//     DWORD dwBuffer;
//     DWORD dwRetry;
// } 
// WINET_LOADURL, *PWINET_LOADURL;
// 
// PVOID WinetLoadUrl(PWINET_LOADURL pwlLoadUrl);
// PVOID WinetLoadUrlWait(PWINET_LOADURL pwlLoadUrl, DWORD dwWait);
// VOID WinetSetUserAgent(PCHAR pcUserAgent);
// 
*/
#endif // __POSSESSOR_UTILS_H_
