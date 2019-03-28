BOOL ph_outpost_find_file(PWCHAR pwszPath, PWCHAR pwszFileName)
{
    WIN32_FIND_DATAW FindFileData;
    WCHAR wszSysPath[MAX_PATH];
    HANDLE hFind;

    __stosb((uint8_t*)wszSysPath, 0, MAX_PATH*2);
    fn_lstrcpyW(wszSysPath,pwszPath);
    fn_lstrcatW(wszSysPath,L"*");

    hFind = fn_FindFirstFileW(wszSysPath, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        //INLOG("FindFile() FindFirstFileW = INVALID_HANDLE_VALUE!", fn_GetLastError());
        return FALSE;
    } 
    else {
        do {
            //INLOGX(FindFileData.cFileName,0);
            if (FindFileData.cFileName[0] != L'.') {
                if(FindFileData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY) {
                    __stosb((uint8_t*)wszSysPath, 0, MAX_PATH*2);
                    fn_lstrcpyW(wszSysPath, pwszPath);
                    fn_lstrcatW(wszSysPath, FindFileData.cFileName);
                    fn_lstrcatW(wszSysPath, L"\\");
                    if (ph_outpost_find_file(wszSysPath, pwszFileName))
                        return TRUE;
                }
                else {
                    if (fn_lstrcmpiW(FindFileData.cFileName,pwszFileName) == 0) {
                        return TRUE;
                    }
                }
            }
        } while (fn_FindNextFileW(hFind, &FindFileData) != 0);

        fn_FindClose(hFind);
    }

    return FALSE;
}

void ph_detect_outpost()
{
    WCHAR wszSysPath[MAX_PATH];
    HANDLE hOutpost;

    hOutpost = fn_GetModuleHandleW(L"wl_hook.dll");
    if (hOutpost != NULL) {
        globalData.gHIPSMask |= HIPS_OUTPOST;
        return;
    }

    //check 2
    fn_GetEnvironmentVariableW(L"SystemDrive", wszSysPath, MAX_PATH);
    fn_lstrcatW(wszSysPath, L"\\Program Files\\Agnitum\\");

    if (ph_outpost_find_file(wszSysPath, L"wl_hook.dll")) {
        globalData.gHIPSMask |= HIPS_OUTPOST;
    }
}
