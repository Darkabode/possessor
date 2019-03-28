#include "common.h"
#include "utils.h"

/*
DWORD RvaToOffset(PIMAGE_NT_HEADERS pPE,DWORD dwRva)
{
    WORD i;
    PIMAGE_SECTION_HEADER pSEC = IMAGE_FIRST_SECTION(pPE);

    for (i = 0; i < pPE->FileHeader.NumberOfSections; ++i) {
        if (dwRva >= pSEC->VirtualAddress && dwRva < (pSEC->VirtualAddress + pSEC->Misc.VirtualSize)) {
            return dwRva + ALIGN_DOWN(pSEC->PointerToRawData, pPE->OptionalHeader.FileAlignment) - pSEC->VirtualAddress;
        }

        pSEC++;
    }

    return 0;
}

int utils_pe_set_dll_flag(const wchar_t* lpPath)
{
    int ret = 0;
    PIMAGE_NT_HEADERS pNtHdr;
    DWORD dwFileSize;
    PVOID pMap;

    if (pMap = utils_map_file(lpPath,FILE_ALL_ACCESS, FILE_FLAG_WRITE_THROUGH, PAGE_READWRITE, FILE_MAP_ALL_ACCESS, 0, &dwFileSize)) {
        if (pNtHdr = fn_RtlImageNtHeader(pMap)) {
            DWORD HeaderSum, CheckSum;

            pNtHdr->FileHeader.Characteristics |= IMAGE_FILE_DLL;

            if (fn_CheckSumMappedFile(pMap,dwFileSize,&HeaderSum,&CheckSum)) {
                pNtHdr->OptionalHeader.CheckSum = CheckSum;

                ret = 1;
            }
        }

        fn_FlushViewOfFile(pMap,dwFileSize);
        fn_UnmapViewOfFile(pMap);
    }

    return ret;
}

// //----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// int __cdecl _purecall()
// {
//     return 0;
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------

int xwcsicmp(wchar_t *s1, wchar_t *s2)
{
    wchar_t f, l;

    do {
        f = ((*s1 <= 'Z') && (*s1 >= 'A')) ? *s1 + 'a' - 'A' : *s1;
        l = ((*s2 <= 'Z') && (*s2 >= 'A')) ? *s2 + 'a' - 'A' : *s2;

        s1++;
        s2++;
    } while ((f) && (f == l));

    return (int)(f - l);
}

//----------------------------------------------------------------------------------------------------------------------------------------------------

int xstrcmp(char *s1, char *s2)
{
    unsigned c1, c2;

    for (;;) 
    {
        c1 = *s1++;
        c2 = *s2++;

        if (c1 != c2) 
        {
            if (c1 > c2) return 1;

            return -1;
        }

        if (c1 == 0) return 0;
    }
}

//----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// PCHAR UtiStrNCpyM(PCHAR pcSrc, DWORD_PTR dwLen)
// {
//     PCHAR pcResult;
// 
//     pcResult = (PCHAR)utils_malloc(dwLen + 1);
//     if (pcResult) lstrcpyn(pcResult, pcSrc, (int)dwLen + 1);
// 
//     return pcResult;
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------

// VOID UtiStrNCpy(PCHAR pcDst, PCHAR pcSrc, DWORD_PTR dwLen)
// {
//     strncpy(pcDst, pcSrc, dwLen);
//     *RtlOffsetToPointer(pcDst, dwLen) = '\0';
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------

size_t xstrlen(char *org)
{
    char *s = org;

    while (*s++);

    return --s - org;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------

VOID xRtlInitAnsiString(PANSI_STRING DestinationString, PCHAR SourceString)
{
    SIZE_T DestSize;

    if (SourceString)
    {
        DestSize = xstrlen(SourceString);
        DestinationString->Length = (USHORT)DestSize;
        DestinationString->MaximumLength = (USHORT)DestSize + sizeof(CHAR);
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PCHAR)SourceString;
}

VOID GetRandomString(PCHAR lpszBuf, DWORD cbBuf)
{
    DWORD i;
    DWORD g_dwSeed = fn_GetTickCount();
    
    for (i = 0; i < cbBuf; i++) lpszBuf[i] = (CHAR)('a' + (CHAR)(fn_RtlRandomEx(&g_dwSeed) % ('z'-'a')));
    lpszBuf[i] = '\0';
}

// Utils
//----------------------------------------------------------------------------------------------------------------------------------------------------

LONG utils_reg_read_valueA(HKEY RootKeyHandle, const char* SubKeyName, const char* ValueName, DWORD Type, PVOID Buffer, DWORD Len)
{
    HKEY keyHandle;
    LONG errorCode;

    errorCode = fn_RegOpenKeyExA(RootKeyHandle, SubKeyName, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &keyHandle);
    if (errorCode != ERROR_SUCCESS) {
        errorCode = fn_RegOpenKeyExA(RootKeyHandle, SubKeyName, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &keyHandle);
    }
    if (errorCode == ERROR_SUCCESS) {
        errorCode = fn_RegQueryValueExA(keyHandle, ValueName, 0, &Type, (LPBYTE)Buffer, &Len);
        fn_RegCloseKey(keyHandle);
    }

    return errorCode;
}

LONG utils_reg_read_valueW(HKEY RootKeyHandle, const wchar_t* SubKeyName, const wchar_t* ValueName, DWORD Type, PVOID Buffer, DWORD Len, int onlyWow64)
{
    HKEY keyHandle;
    LONG errorCode;

    errorCode = fn_RegOpenKeyExW(RootKeyHandle, SubKeyName, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &keyHandle);
    if (errorCode != ERROR_SUCCESS && !onlyWow64) {
        errorCode = fn_RegOpenKeyExW(RootKeyHandle, SubKeyName, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &keyHandle);
    }
    if (errorCode == ERROR_SUCCESS) {
        errorCode = fn_RegQueryValueExW(keyHandle, ValueName, 0, &Type, (LPBYTE)Buffer, &Len);
        fn_RegCloseKey(keyHandle);
    }

    return errorCode;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------

DWORD GetProcessIdByName(PCHAR ProcessName, PDWORD Processes, DWORD Max)
{
    DWORD Count = 0;
    PROCESSENTRY32 ProcessEntry;
    HANDLE hSnap;

    __stosb((uint8_t*)&ProcessEntry, 0, sizeof(ProcessEntry));

    hSnap = fn_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        ProcessEntry.dwSize = sizeof(ProcessEntry);
        if (fn_Process32FirstW(hSnap, &ProcessEntry)) {
            do {
                if (!fn_lstrcmpiA(ProcessName, fn_PathFindFileNameA(ProcessEntry.szExeFile))) {
                    if (Count < Max) {
                        Processes[Count] = ProcessEntry.th32ProcessID;
                        Count++;
                    } 
                    else {
                        break;
                    }
                }
            } while (fn_Process32NextW(hSnap, &ProcessEntry));
        }
        fn_CloseHandle(hSnap);
    }

    return Count;
}

HANDLE utils_file_lock(const wchar_t* lpFile, DWORD dwAccess, DWORD dwDisposition)
{
    HANDLE hFile;
    OVERLAPPED oOverlapped;
    __stosb((uint8_t*)&oOverlapped, 0, sizeof(oOverlapped));

    hFile = fn_CreateFileW(lpFile, dwAccess, 0, NULL, dwDisposition, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile != INVALID_HANDLE_VALUE) {
        fn_LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, -1, -1, &oOverlapped);
    }

    return hFile;
}


void utils_file_unlock(HANDLE hFile)
{
    OVERLAPPED oOverlapped;
    __stosb((uint8_t*)&oOverlapped, 0, sizeof(oOverlapped));
    fn_UnlockFileEx(hFile, 0, -1, -1, &oOverlapped);
    fn_CloseHandle(hFile);
}

//----------------------------------------------------------------------------------------------------------------------------------------------------
#ifndef _WIN64
//----------------------------------------------------------------------------------------------------------------------------------------------------

DWORD SearchBytesInMemory(PVOID RegionCopy, DWORD_PTR RegionSize, PVOID Bytes, DWORD Length)
{
    DWORD Result = 0;
    DWORD i = 0;

    if (RegionSize >= Length) {
        for ( ; ; ) {
            PVOID Pointer = RtlOffsetToPointer(RegionCopy, i);

            if (fn_RtlCompareMemory(Pointer, Bytes, Length) == Length) {
                Result = i;
                break;
            }

            i++;

            if (Length + i > RegionSize) {
                break;
            }
        }
    }

    return Result;
}


DWORD SearchDwordInMemory(PVOID RegionCopy, DWORD_PTR RegionSize, DWORD Dword)
{
    return (DWORD)RtlOffsetToPointer(RegionCopy, SearchBytesInMemory(RegionCopy, RegionSize, (PVOID)&Dword, 4));
}

NTSTATUS utils_map_section(const wchar_t* sectionName, PHANDLE pSectionHandle, PVOID* pBaseAddress, DWORD_PTR* pViewSize)
{
    NTSTATUS ntStatus;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uSectionName;

    fn_RtlInitUnicodeString(&uSectionName, sectionName);
    InitializeObjectAttributes(&objAttr, &uSectionName, OBJ_OPENIF, 0, NULL);
    ntStatus = fn_ZwOpenSection(pSectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &objAttr);
    if (NT_SUCCESS(ntStatus)) {
        *pBaseAddress = NULL;
        *pViewSize = 0;

        ntStatus = fn_ZwMapViewOfSection(*pSectionHandle, NtCurrentProcess(), pBaseAddress, 0, 0, NULL, pViewSize, ViewUnmap, 0, PAGE_READWRITE);
        if (!NT_SUCCESS(ntStatus)) {
            DbgMsg(__FUNCTION__": ZwMapViewOfSection failed: 0x%x\n", ntStatus);
        }
    }
    else {
        DbgMsg(__FUNCTION__": ZwOpenSection failed: 0x%x\n", ntStatus);
    }

    return ntStatus;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------

DWORD SearchBytesInReadedMemory(HANDLE ProcessHandle, PVOID BaseAddress, DWORD_PTR Size, PVOID Bytes, DWORD Length)
{
    DWORD Result = 0;

    PVOID RegionCopy = fn_VirtualAlloc(NULL, Size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (RegionCopy)
    {
        SIZE_T t;
        if (fn_ReadProcessMemory(ProcessHandle, BaseAddress, RegionCopy, Size, &t)) {
            Result = SearchBytesInMemory(RegionCopy, Size, Bytes, Length);
        }

        fn_VirtualFree(RegionCopy, 0, MEM_RELEASE);
    }

    return Result;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------

PVOID SearchBytesInProcessMemory(HANDLE ProcessHandle, PVOID Bytes, DWORD Length)
{
    PVOID Result = NULL;
    PVOID BaseAddress = NULL;
    MEMORY_BASIC_INFORMATION Mbi;
    DWORD Index;

    for ( ; ; ) {
        if (fn_VirtualQueryEx(ProcessHandle, BaseAddress, &Mbi, sizeof(Mbi))) {
            Index = SearchBytesInReadedMemory(ProcessHandle, BaseAddress, Mbi.RegionSize, Bytes, Length);
            if (Index) {
                Result = RtlOffsetToPointer(Mbi.AllocationBase, Index);
            }
        }
        else {
            break;
        }

        if (Result) {
            break;
        }

        BaseAddress = RtlOffsetToPointer(BaseAddress, Mbi.RegionSize);
    }

    return Result;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------

DWORD SearchCodeInProcessModules(HANDLE ProcessHandle, PVOID Bytes, DWORD Length)
{
    DWORD Result = 0;
    BOOL bOk = FALSE;
    HMODULE *ProcessModules;
    DWORD Needed;

    ProcessModules = (HMODULE*)memalloc(sizeof(HMODULE)*260);
    if (ProcessModules) {
        if (fn_EnumProcessModules(ProcessHandle, ProcessModules, sizeof(HMODULE)*260, &Needed)) {
            if (Needed > sizeof(HMODULE)*260) {
                ProcessModules = (HMODULE *)memrealloc(ProcessModules, Needed);
                if (ProcessModules) {
                    bOk = fn_EnumProcessModules(ProcessHandle, ProcessModules, sizeof(HMODULE)*260, &Needed);
                }
            }
            else bOk = TRUE;
        }

        if (bOk) {
            PUCHAR ModuleHeader = (PUCHAR)memalloc(0x400);
            if (ModuleHeader) {
                DWORD i;
                for (i = 0; i < Needed/sizeof(HMODULE); ++i) {
                    SIZE_T t;
                    if (fn_ReadProcessMemory(ProcessHandle, ProcessModules[i], ModuleHeader, 0x400, &t)) {
                        PIMAGE_NT_HEADERS NtHeaders = PeImageNtHeader(ModuleHeader);
                        if (NtHeaders) {
                            WORD j;
                            PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);

                            for (j = 0; j < NtHeaders->FileHeader.NumberOfSections; ++j) {
                                if (!fn_lstrcmpA((PCHAR)SectionHeader[j].Name, ".text") && FlagOn(SectionHeader[j].Characteristics, IMAGE_SCN_MEM_EXECUTE)) {
                                    PVOID BaseAddress = RtlOffsetToPointer(ProcessModules[i], SectionHeader[j].VirtualAddress);
                                    DWORD Index = SearchBytesInReadedMemory(ProcessHandle, BaseAddress, SectionHeader[j].Misc.VirtualSize, Bytes, Length);
                                    if (Index) {
                                        Result = MAKE_PTR(BaseAddress, Index, DWORD);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if (Result) {
                        break;
                    }
                }
                memfree(ModuleHeader);
            }
        }

        memfree(ProcessModules);
    }

    return Result;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------
#endif

int utils_create_zmodule_mapping(char* name, const uint8_t* pCurrentImageBase, uint32_t currentImageSize, HANDLE* phCurrentImageSection, int needRelocate)
{
    int ret = FALSE;
    uint8_t* pMapping;

    *phCurrentImageSection = fn_CreateFileMappingA(0, NULL, PAGE_EXECUTE_READWRITE|SEC_COMMIT, 0, currentImageSize, name);
    if (*phCurrentImageSection != NULL) {
        pMapping = fn_MapViewOfFile(*phCurrentImageSection, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (pMapping != NULL) {
            __movsb(pMapping, pCurrentImageBase, currentImageSize);

            if (needRelocate) {
                ret = zmodule_process_relocs(pMapping, zmodule_get_image_base(pMapping) - (uint64_t)pCurrentImageBase);
            }
            else {
                ret = TRUE;
            }

            fn_UnmapViewOfFile(pMapping);
        }
    }

    return ret;
}

BOOLEAN ReplaceIAT(PCHAR ModuleName, PCHAR Current, PVOID New, HMODULE Module)
{
    BOOLEAN Result = FALSE;
    PIMAGE_IMPORT_DESCRIPTOR pImport;
    PDWORD_PTR thunkRef, funcRef;
    DWORD Old;

    pImport = (PIMAGE_IMPORT_DESCRIPTOR)PeImageDirectoryEntryToData((PVOID)Module, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, NULL, FALSE);
    if (pImport)
    {
        for (; pImport->Name; pImport++) 
        {
            if (!fn_lstrcmpiA(ModuleName, RtlOffsetToPointer(Module, pImport->Name)))
            {
                break;
            }
        }

        if (pImport->Name)
        {
            if (pImport->OriginalFirstThunk) {
                thunkRef = MAKE_PTR(Module, pImport->OriginalFirstThunk, PDWORD_PTR); 
                funcRef = MAKE_PTR(Module, pImport->FirstThunk, PDWORD_PTR);
            }
            else {
                thunkRef = MAKE_PTR(Module, pImport->FirstThunk, PDWORD_PTR); 
                funcRef = MAKE_PTR(Module, pImport->FirstThunk , PDWORD_PTR);      
            }

            for (; *thunkRef; thunkRef++, funcRef++) {
                if (!IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                    if (!fn_lstrcmpA((PCHAR)&((PIMAGE_IMPORT_BY_NAME)RtlOffsetToPointer(Module, *thunkRef))->Name, Current)) {
                        if (fn_VirtualProtect(funcRef, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &Old)) {
                            if (fn_WriteProcessMemory(NtCurrentProcess(), funcRef, &New, sizeof(New), NULL)) {
                                Result = TRUE;
                            }
                            else {
                                DbgMsg(__FUNCTION__"(): WriteProcessMemory failed: %08X\n", fn_GetLastError());
                            }

                            fn_FlushInstructionCache(NtCurrentProcess(), &New, sizeof(New));

                            fn_VirtualProtect(funcRef, sizeof(PVOID), Old, &Old);
                        }
                        else {
                            DbgMsg(__FUNCTION__"(): VirtualProtect failed: %08X\n", fn_GetLastError());
                        }
                    }
                }
            }
        }
    }

    return Result;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// DWORD GetProcessIntegrityLevel()
// {
//     HANDLE hToken;
//     DWORD dwLengthNeeded;
//     PTOKEN_MANDATORY_LABEL pTIL;
//     DWORD dwIntegrityLevel = 0;
// 
//     if (fn_OpenProcessToken(fn_GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
//         if (!fn_GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded)) {
//             if (fn_GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
//                 pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
//                 if (pTIL != NULL) {
//                     if (fn_GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {
//                         dwIntegrityLevel = *fn_GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*fn_GetSidSubAuthorityCount(pTIL->Label.Sid)-1));
//                     }
// 
//                     LocalFree(pTIL);
//                 }
//             }
//         }
// 
//         fn_CloseHandle(hToken);
//     }
// 
//     return dwIntegrityLevel;
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------

// BOOL CheckAdmin()
// {
//     BOOL Ret;
//     SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
//     PSID AdministratorsGroup; 
// 
//     if (Ret = fn_AllocateAndInitializeSid(&NtAuthority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&AdministratorsGroup))
//     {
//         if (!CheckTokenMembership(NULL,AdministratorsGroup,&Ret))
//         {
//             Ret = FALSE;
//         }
// 
//         fn_FreeSid(AdministratorsGroup);
//     }
// 
//     return Ret;
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------

// BOOL CheckUAC()
// {
//     BOOL fIsElevated = FALSE;
//     HANDLE hToken = NULL;
// 
//     if (fn_OpenProcessToken(fn_GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
//         TOKEN_ELEVATION elevation;
//         DWORD dwSize;
// 
//         if (fn_GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
//             fIsElevated = !elevation.TokenIsElevated;
//         }
// 
//         fn_CloseHandle(hToken);
//     }
// 
//     return fIsElevated;
// }
// 
//----------------------------------------------------------------------------------------------------------------------------------------------------

// VOID UtiCryptRc4(PCHAR pcKey, DWORD dwKey, PVOID pvDst, PVOID pvSrc, DWORD dwLen)
// {
//     DWORD i = 0, j = 0, k = 0;
//     UCHAR ucKey[256];
//     UCHAR ucTemp;
// 
//     for (i = 0; i < sizeof(ucKey); i++) ucKey[i] = (CHAR)i;
// 
//     for (i = j = 0 ; i < sizeof(ucKey); i++)
//     {
//         j = (j + pcKey[i % dwKey] + ucKey[i]) % 256;
// 
//         ucTemp = ucKey[i];
//         ucKey[i] = ucKey[j];
//         ucKey[j] = ucTemp;
//     }
// 
//     for (i = j = 0, k = 0; k < dwLen; k++)
//     {
//         i = (i + 1) % 256;
//         j = (j + ucKey[i]) % 256;
//         ucTemp = ucKey[i];
//         ucKey[i] = ucKey[j];
//         ucKey[j] = ucTemp;
// 
//         *RtlOffsetToPointer(pvDst, k) = *RtlOffsetToPointer(pvSrc, k) ^ ucKey[(ucKey[i] + ucKey[j]) % 256];
//     }
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------

// PVOID UtiCryptRc4M(PCHAR pcKey, DWORD dwKey, PVOID pvBuffer, DWORD dwBuffer)
// {
//     PVOID pvResult;
// 
//     pvResult = utils_malloc(dwBuffer);
//     if (pvResult)
//     {
//         UtiCryptRc4(pcKey, dwKey, pvResult, pvBuffer, dwBuffer);
//     }
// 
//     return pvResult;
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------

// BOOLEAN StringTokenBreak(PCHAR *ppcSrc, PCHAR pcToken, PCHAR *ppcBuffer)
// {
//     DWORD_PTR dwLen;
//     PCHAR pcNext;
//     DWORD_PTR dwToken = fn_lstrlenA(pcToken);
// 
//     if (*ppcSrc != NULL && (*ppcSrc)[0] != '\0')
//     {
//         *ppcBuffer = NULL;
// 
//         pcNext = StrStrI(*ppcSrc, pcToken);
//         if (!pcNext)
//         {
//             dwLen = fn_lstrlenA(*ppcSrc);
//             *ppcBuffer = UtiStrNCpyM(*ppcSrc, dwLen);
// 
//             *ppcSrc = pcNext;
//         }
//         else 
//         {
//             dwLen = pcNext - *ppcSrc;
//             *ppcBuffer = UtiStrNCpyM(*ppcSrc, dwLen);
// 
//             *ppcSrc = &pcNext[dwToken];
//         }
// 
//         if (*ppcBuffer) return TRUE;
//     }
// 
//     return FALSE;
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// VOID GetWindowsVersion(PCHAR pcBuffer, DWORD dwSize)
// {
//     typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
//     OSVERSIONINFOEX osVerInfo = {0};
//     SYSTEM_INFO si;
//     PGNSI pGNSI;
// 
//     osVerInfo.dwOSVersionInfoSize = sizeof(osVerInfo);
//     GetVersionEx((LPOSVERSIONINFO)&osVerInfo);
// 
//     pGNSI = (PGNSI) PeGetProcAddress(GetModuleHandle("kernel32.dll"), "GetNativeSystemInfo", FALSE);
//     if (NULL != pGNSI) pGNSI(&si); else GetSystemInfo(&si);
// 
//     _snprintf(pcBuffer, dwSize, "%1d.%1d %04d sp%1d.%1d %s", 
//         osVerInfo.dwMajorVersion, 
//         osVerInfo.dwMinorVersion, 
//         osVerInfo.dwBuildNumber, 
//         osVerInfo.wServicePackMajor, 
//         osVerInfo.wServicePackMinor,
//         si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "64bit" : "32bit");
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// VOID GetParrentProcessName(PCHAR FileName, DWORD Size)
// {
//     PROCESS_BASIC_INFORMATION ProcessInfo;
//     HANDLE ProcessHandle;
//     DWORD Length;
// 
//     __stosb(FileName, 0, Size);
//     NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &ProcessInfo, sizeof(ProcessInfo), &Length);
//     ProcessHandle = fn_OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)ProcessInfo.InheritedFromUniqueProcessId);
//     if (ProcessHandle != NULL)
//     {
//         GetModuleFileNameEx(ProcessHandle, NULL, FileName, Size);
// 
//         fn_CloseHandle(ProcessHandle);
//     }
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------

// BOOL SetPrivilege(char* SeNamePriv, BOOL EnableTF)
// {
//     HANDLE hToken;
//     LUID SeValue;
//     TOKEN_PRIVILEGES tp;
// 
//     if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,&hToken))
//     {
//         return FALSE;
//     }
// 
//     if (!LookupPrivilegeValue(NULL, SeNamePriv, &SeValue)) 
//     {
//         fn_CloseHandle(hToken);
//         return FALSE;
//     }
// 
//     tp.PrivilegeCount = 1;
//     tp.Privileges[0].Luid = SeValue;
//     tp.Privileges[0].Attributes = EnableTF ? SE_PRIVILEGE_ENABLED : 0;
// 
//     fn_AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
// 
//     fn_CloseHandle(hToken);
//     return TRUE;
// }
// 
// //----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// BOOL utils_check_mutex(DWORD id, PCHAR sign)
// {
//     CHAR MutexName[MAX_PATH];
//     HANDLE MutexHandle;
// 
//     fn_wsprintfA(MutexName, "Global\\%s%x", sign, id);//_snprintf(MutexName, RTL_NUMBER_OF(MutexName), "Global\\%s%x", Sign, Id);
//     if (MutexHandle = fn_OpenMutexA(MUTEX_MODIFY_STATE, FALSE, MutexName)) {
//         fn_CloseHandle(MutexHandle);
// 
//         return FALSE;
//     }
// 
//     return TRUE;
// }

// VOID RestartModuleShellExec(PCHAR FilePath)
// {
//     SHELLEXECUTEINFO sei = {0};
//     CHAR TempPath[MAX_PATH];
//     CHAR TempName[MAX_PATH];
//     PVOID Buffer;
//     DWORD Size;
// 
//     if (!StrStrI(FilePath, ".exe"))
//     {
//         GetTempPath(RTL_NUMBER_OF(TempPath), TempPath);
//         GetTempFileName(TempPath, NULL, 0, TempName);
//         lstrcat(TempName, ".exe");
// 
//         if (Buffer = FileRead(FilePath, &Size))
//         {
//             if (FileWrite(TempName, CREATE_ALWAYS, Buffer, Size, FILE_BEGIN))
//             {
//                 FilePath = TempName;
//             }
//         }
//     }
// 
//     sei.cbSize = sizeof(sei);
//     sei.lpFile = FilePath;
//     sei.lpVerb = "runas";
//     sei.hwnd = GetForegroundWindow();
//     while (!ShellExecuteEx(&sei))
//     {
//         DbgMsg(__FUNCTION__"(): ShellExecuteEx error: %x\n", fn_GetLastError());
// 
//         fn_Sleep(3000);
//     }
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// BOOL StartExe(wchar_t* lpFilePath)
// {
//     STARTUPINFO si = {0};
//     PROCESS_INFORMATION pi = {0};
//     BOOL bRet;
// 
//     si.cb = sizeof(si);
// 
//     bRet = CreateProcessW(NULL, lpFilePath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
//     if (bRet) {
//         fn_CloseHandle(pi.hThread);
//         fn_CloseHandle(pi.hProcess);
//     }
// 
//     return bRet;
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// BOOLEAN WriteFileAndExecute(PVOID File, DWORD Size)
// {
//     CHAR chTempPath[MAX_PATH];
//     CHAR chTempName[MAX_PATH];
// 
//     GetTempPathA(sizeof(chTempPath), chTempPath);
//     GetTempFileNameA(chTempPath, NULL, 0, chTempName);
//     lstrcatA(chTempName, ".exe");
// 
//     if (FileWrite(chTempName, CREATE_ALWAYS, File, Size, FILE_BEGIN))
//     {
//         return StartExe(chTempName);
//     }
// 
//     return FALSE;
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// VOID DeleteFileReboot(PCHAR pcFilePath)
// {
//     CHAR chTempPath[MAX_PATH];
//     CHAR chTempName[MAX_PATH];
// 
//     GetTempPath(RTL_NUMBER_OF(chTempPath), chTempPath);
//     GetTempFileName(chTempPath, NULL, 0, chTempName);
// 
//     if (!MoveFileEx(pcFilePath, chTempName, MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))
//     {
//         DbgMsg(__FUNCTION__"(): MoveFileEx error 0x%x\n", fn_GetLastError());
//     }
// 
//     if (!MoveFileEx(chTempName, NULL, MOVEFILE_DELAY_UNTIL_REBOOT|MOVEFILE_WRITE_THROUGH))
//     {
//         DbgMsg(__FUNCTION__"(): MoveFileEx error 0x%x\n", fn_GetLastError());
//     }
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// DWORD_PTR ExecExportProcedure(PVOID ModuleBase, PCHAR pcProcedure, PCHAR pcParameters)
// {
//     DWORD_PTR Result = 0;
//     DWORD dwWCStrings = 0;
//     DWORD_PTR dwParameterLength;
//     PCHAR pcParameter = pcParameters;
//     WCHAR wcStrings[12][MAX_PATH] = {0};
//     PDWORD_PTR pdwpParameters = (PDWORD_PTR)alloca(12*sizeof(DWORD_PTR));
//     PCHAR pcParameterEnd;
//     CHAR cEnd;
//     BOOLEAN bWideChar;
// #ifdef _WIN64
//     typedef DWORD_PTR (WINAPI *FPPROC)(DWORD_PTR, DWORD_PTR, DWORD_PTR, DWORD_PTR, DWORD_PTR, DWORD_PTR);
//     PDWORD_PTR pStart = pdwpParameters;
//     FPPROC fpProcedure;
// #else
//     FARPROC fpProcedure;
// #endif
//     DWORD dwScaned;
//     DWORD dwLength;
// 
//     ZeroMemory(pdwpParameters, 12*sizeof(DWORD_PTR));
//     while (*pcParameter)
//     {
//         if (*pcParameter == '\"' || *pcParameter=='\'' || *(PWORD)pcParameter=='\"L')
//         {
//             bWideChar = FALSE;
// 
//             if (*pcParameter=='L')
//             {
//                 pcParameter++;
//                 bWideChar = TRUE;
//             }
// 
//             cEnd = *pcParameter;
//             pcParameter++;
//             pcParameterEnd = strchr(pcParameter, cEnd);            
//             if (!pcParameterEnd) break; else *pcParameterEnd = '\0';
// 
//             if (bWideChar)
//             {
//                 if (dwWCStrings == 12) break;
// 
//                 *pdwpParameters = (DWORD_PTR)wcStrings[dwWCStrings];
//                 if (_snwprintf(wcStrings[dwWCStrings++], RTL_NUMBER_OF(wcStrings[0])-1, L"%S", pcParameter) == -1) break;
//             }
//             else *pdwpParameters = (DWORD_PTR)pcParameter;
// 
//             pcParameterEnd++;
//             if (*pcParameterEnd == ',') pcParameterEnd++; else if (*pcParameterEnd != '\0') break;
// 
//             dwParameterLength = (DWORD_PTR)(pcParameterEnd - pcParameter);
//         }
//         else
//         {
//             pcParameterEnd = strchr(pcParameter, ',');
//             if (pcParameterEnd)
//             {
//                 *pcParameterEnd = '\0';
//                 dwParameterLength = (DWORD_PTR)(pcParameterEnd - pcParameter) + 1;
//             }
//             else 
//             {
//                 dwParameterLength = fn_lstrlenA(pcParameter);
//             }
// 
//             dwLength = fn_lstrlenA(pcParameter);
//             if (dwLength > 2 && *(PWORD)pcParameter == 'x0')
//             {
//                 dwScaned = sscanf(pcParameter, "%x", pdwpParameters);
//             }
//             else
//             {
//                 dwScaned = sscanf(pcParameter, strchr(pcParameter, '.') ? "%f" : "%d", pdwpParameters);
//             }
// 
//             if (dwScaned != 1) break;
//         }
// 
//         pcParameter += dwParameterLength;
//         pdwpParameters++;
//     }
// 
// #ifdef _WIN64
//     if (fpProcedure = (FPPROC)PeGetProcAddress(ModuleBase, pcProcedure, FALSE)) 
//     {
//         Result = fpProcedure(pStart[0], pStart[1], pStart[2], pStart[3], pStart[4], pStart[5]);
//     }
// #else
//     if (fpProcedure = (FARPROC)PeGetProcAddress(ModuleBase, pcProcedure, FALSE)) 
//     {
//         Result = fpProcedure();
//     }
// #endif
// 
//     return Result;
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------

// PVOID WinetLoadUrl(PWINET_LOADURL pwlLoadUrl)
// {
//     PVOID pvBuffer = NULL;
//     DWORD dwSize;
//     CHAR chUserAgentStr[MAX_PATH];
//     URL_COMPONENTS ucUrlComp = {0};
//     HINTERNET hInternet;
//     HINTERNET hConnect;
//     HINTERNET hRequest;
//     DWORD dwSecFlags;
//     DWORD dwFlags;
//     DWORD dwReaded;
//     PVOID pvTemp;
// 
//     WinetGetUserAgentStr(chUserAgentStr, RTL_NUMBER_OF(chUserAgentStr));
//     hInternet = InternetOpen(chUserAgentStr, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
//     if (hInternet)
//     {
//         ucUrlComp.dwStructSize = sizeof(URL_COMPONENTS);
//         ucUrlComp.dwHostNameLength = MAX_PATH;
//         ucUrlComp.lpszHostName = (PCHAR)alloca(ucUrlComp.dwHostNameLength);
//         ucUrlComp.dwUrlPathLength = fn_lstrlenA(pwlLoadUrl->pcUrl)*2;
//         ucUrlComp.lpszUrlPath = (PCHAR)alloca(ucUrlComp.dwUrlPathLength);
// 
//         if (InternetCrackUrl(pwlLoadUrl->pcUrl, ucUrlComp.dwUrlPathLength, ICU_ESCAPE, &ucUrlComp))
//         {
//             hConnect = InternetConnect(hInternet, ucUrlComp.lpszHostName, ucUrlComp.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
//             if (hConnect)
//             {
//                 dwFlags = INTERNET_FLAG_NO_COOKIES|INTERNET_FLAG_RELOAD|INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_PRAGMA_NOCACHE;
//                 if (ucUrlComp.nScheme == INTERNET_SCHEME_HTTPS) dwFlags |= INTERNET_FLAG_SECURE|INTERNET_FLAG_IGNORE_CERT_CN_INVALID|INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
// 
//                 hRequest = HttpOpenRequest(hConnect, pwlLoadUrl->pcMethod, ucUrlComp.lpszUrlPath, NULL, NULL, NULL, dwFlags, 0);
//                 if (hRequest)
//                 {
//                     dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_REVOCATION|SECURITY_FLAG_IGNORE_WRONG_USAGE|SECURITY_FLAG_IGNORE_REDIRECT_TO_HTTPS;
//                     InternetSetOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(DWORD));
// 
//                     if (HttpSendRequest(hRequest, pwlLoadUrl->pcHeaders, pwlLoadUrl->dwHeaders, pwlLoadUrl->pvPstData, pwlLoadUrl->dwPstData))
//                     {
//                         dwSize = sizeof(DWORD);
//                         if (!HttpQueryInfo(hRequest, HTTP_QUERY_STATUS_CODE|HTTP_QUERY_FLAG_NUMBER, &pwlLoadUrl->dwStatus, &dwSize, NULL))
//                         {
//                             pwlLoadUrl->dwStatus = -1;
// 
//                             DbgMsg(__FUNCTION__"(): HttpQueryInfo fails; last error: %x\n", fn_GetLastError());
//                         }
// 
//                         dwSize = 0;
//                         pvTemp = alloca(MAX_PATH*4);
//                         for (;;)
//                         {
//                             if (InternetReadFile(hRequest, pvTemp, MAX_PATH*4, &dwReaded) && dwReaded)
//                             {
//                                 if (!pvBuffer) pvBuffer = malloc(dwReaded + 1); else pvBuffer = realloc(pvBuffer, dwSize + dwReaded + 1);
//                                 if (pvBuffer)
//                                 {
//                                     CopyMemory(RtlOffsetToPointer(pvBuffer, dwSize), pvTemp, dwReaded);
//                                     *RtlOffsetToPointer(pvBuffer, dwSize + dwReaded) = '\0';
// 
//                                     dwSize += dwReaded;
//                                 } 
//                                 else break;
//                             }
//                             else 
//                             {
//                                 if (!dwSize && pvBuffer)
//                                 {
//                                     free(pvBuffer);
//                                 }
// 
//                                 pwlLoadUrl->dwBuffer = dwSize;
// 
//                                 break;
//                             }
//                         }
//                     }
//                     else
//                     {
//                         //DbgMsg(__FUNCTION__"(): HttpSendRequest fails; last error: %x\n", fn_GetLastError());
//                     }
// 
//                     InternetCloseHandle(hRequest);
//                 }
//                 else
//                 {
//                     DbgMsg(__FUNCTION__"(): HttpOpenRequest fails; last error: %x\n", fn_GetLastError());
//                 }
// 
//                 InternetCloseHandle(hConnect);
//             }
//             else
//             {
//                 DbgMsg(__FUNCTION__"(): InternetConnect fails; last error: %x\n", fn_GetLastError());
//             }
//         }
//         else
//         {
//             DbgMsg(__FUNCTION__"(): InternetCrackUrl fails; last error: %x\n", fn_GetLastError());
//         }
// 
//         InternetCloseHandle(hInternet);
//     }
//     else
//     {
//         DbgMsg(__FUNCTION__"(): InternetOpen fails; last error: %x\n", fn_GetLastError());
//     }
// 
//     return pvBuffer;
// }
// 
// //----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// PVOID WinetLoadUrlThread(PWINET_LOADURL pwiLoad)
// {
//     PVOID pvResult;
//     DWORD i;
// 
//     for (i = 0; i < pwiLoad->dwRetry; i++)
//     {
//         pvResult = WinetLoadUrl(pwiLoad);
//         if (pvResult) break;
//     }
// 
//     return pvResult;
// }
// 
// //----------------------------------------------------------------------------------------------------------------------------------------------------
// 
// PVOID WinetLoadUrlWait(PWINET_LOADURL pwlLoadUrl, DWORD dwWait)
// {
//     return (PVOID)ThreadCreate(WinetLoadUrlThread, pwlLoadUrl, NULL, dwWait);
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------

#include "..\..\shared\lzma.h"

#define USE_LZMA_DECOMPRESSOR 1
#include "..\..\shared\lzma.c"


int utils_lzma_decompress(pvoid_t inStream, DWORD inSize, pvoid_t* outStream, PDWORD poutSize)
{
    size_t outSize, origOutSize;
    int ret = 1;
    ELzmaStatus st;

    do {
        outSize = inSize;
        do {
            if (*outStream != NULL) {
                memfree(*outStream);
            }
            outSize *= 2;
            origOutSize = outSize;
            *outStream = memalloc(outSize);
            ret = lzma_decode((uint8_t*)*outStream, &outSize, (uint8_t*)inStream, inSize, &st);
        } while (ret == ERR_OK && outSize == origOutSize);

        *poutSize = outSize;
    } while (0);

    return ret;
}

#ifndef _WIN64



uint32_t util_get_hash_from_istr_a(const char* pszString)
{
    uint32_t i, sz = fn_lstrlenA(pszString);
    char lowerStr[1024];

    __stosb(lowerStr, 0, sizeof(lowerStr));
    for (i = 0; i < sz; ++i) {
        lowerStr[i] = pszString[i] | 0x20;
    }
    return utils_get_hash_a(lowerStr);
}



void util_initialize_list_head(PLIST_ENTRY pListHead)
{
    pListHead->Flink = pListHead->Blink = pListHead;
}

bool_t util_is_list_empty(const PLIST_ENTRY pListHead)
{
    return (bool_t)(pListHead->Flink == pListHead);
}

bool_t util_remove_entry_list(PLIST_ENTRY pEntry)
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = pEntry->Flink;
    Blink = pEntry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (bool_t)(Flink == Blink);
}

void util_insert_tail_list(PLIST_ENTRY pListHead, PLIST_ENTRY pEntry)
{
    PLIST_ENTRY Blink;

    Blink = pListHead->Blink;
    pEntry->Flink = pListHead;
    pEntry->Blink = Blink;
    Blink->Flink = pEntry;
    pListHead->Blink = pEntry;
}

#endif // _WIN64

void utils_fix_32value(uint8_t* pData, uint32_t size, uint32_t oldValue, uint32_t newValue)
{
    uint32_t p = 0;
    uint32_t* pDD;
    while (p < size) {
        pDD = (uint32_t*)(pData + p);
        if (*pDD == oldValue) {
            __stosd(pDD, newValue, 1);
            //*pDD = newValue;
        }
        ++p;
    }
}

void utils_fix_64value(uint8_t* pData, uint32_t size, uint64_t oldValue, uint64_t newValue)
{
    uint32_t p = 0;
    uint64_t* pDD;
    while (p < size) {
        pDD = (uint64_t*)(pData + p);
        if (*pDD == oldValue) {
            __movsd((uint32_t*)pDD, (const uint32_t*)&newValue, 2);
            //*pDD = newValue;
        }
        ++p;
    }
}

void utils_get_temp_name(wchar_t* tempFileName, int maxSize)
{
    ULONG rndSeed = fn_GetTickCount();
    uint32_t n;
    wchar_t filePath[MAX_PATH];

    n = fn_GetTempPathW(MAX_PATH, filePath);

    do {
        if (n > 0) {
            n = fn_GetLongPathNameW(filePath, filePath, maxSize);
            if (n > 0) {
                if (filePath[fn_lstrlenW(filePath) - 1] != L'\\') {
                    fn_lstrcatW(filePath, L"\\");
                }
                break;
            }    
        }
        fn_lstrcpyW(filePath, L"C:\\Windows\\temp");
    } while (0);

    fn_GetTempFileNameW(filePath, L"abcdefghijklmnopq", 3 + (fn_RtlRandomEx(&rndSeed) % 256256), tempFileName);
}

*/