#include "common.h"
#include "wmi.h"
#include "stre"
/* Maximum number of arguments for a member */
#define DH_MAX_ARGS 25

/* Maximum length of a member string */
#define DH_MAX_MEMBER 512

HRESULT __cdecl wmi_extract_arg(VARIANT* pvArg, char vType, BOOL* pbFreeArg, va_list* marker)
{
    HRESULT hr = NOERROR;

    *pbFreeArg = FALSE;

    switch (vType) {
        case 'w':
            V_VT(pvArg) = VT_UI2;
            V_UI2(pvArg) = va_arg(*marker, WORD);
            break;
        case 'd':
            V_VT(pvArg) = VT_I4;
            V_I4(pvArg) = va_arg(*marker, LONG);
            break;
        case 'u':
            V_VT(pvArg) = VT_UI4;
            V_UI4(pvArg) = va_arg(*marker, ULONG);
            break;
        case 'q':
            V_VT(pvArg) = VT_UI8;
            V_UI8(pvArg) = va_arg(*marker, ULONG64);
            break;
        case 'e':
            V_VT(pvArg) = VT_R8;
            V_R8(pvArg) = va_arg(*marker, DOUBLE);
            break;
        case 'b':
            V_VT(pvArg) = VT_BOOL;
            V_BOOL(pvArg) = ( va_arg(*marker, BOOL) ? VARIANT_TRUE : VARIANT_FALSE );
            break;
        case 'm':
            V_VT(pvArg) = VT_ERROR;
            V_ERROR(pvArg) = DISP_E_PARAMNOTFOUND;
            break;
        case 'S':
            {
                LPOLESTR szTemp = va_arg(*marker, LPOLESTR);

                V_VT(pvArg) = VT_BSTR;
                V_BSTR(pvArg) = fn_SysAllocString(szTemp);

                if (V_BSTR(pvArg) == NULL && szTemp != NULL) hr = E_OUTOFMEMORY;

                *pbFreeArg = TRUE;
                break;
            }
        case 'o':
            V_VT(pvArg) = VT_DISPATCH;
            V_DISPATCH(pvArg) = va_arg(*marker, IDispatch *);
            break;
        case 'p':
#ifndef _WIN64
            V_VT(pvArg) = VT_I4;
            V_I4(pvArg) = (LONG) va_arg(*marker, LPVOID);
#else
            V_VT(pvArg) = VT_I8;
            V_I8(pvArg) = (LONGLONG) va_arg(*marker, LPVOID);
#endif
            break;
        default:
            hr = E_INVALIDARG;
            break;
    }

    return hr;
}

HRESULT __cdecl wmi_get_value(char vType, void* pResult, IDispatch* pDisp, LPCOLESTR szMember, ...)
{
    HRESULT hr = NOERROR;
    va_list marker;
    VARIANT vtResult;
    VARTYPE returnType;
    WCHAR szCopy[DH_MAX_MEMBER];
    LPWSTR szTemp = szCopy;
    SIZE_T cchDest = ARRAYSIZE(szCopy);
    VARIANT vtArgs[DH_MAX_ARGS];
    BOOL bFreeList[DH_MAX_ARGS];
    UINT cArgs, iArg = DH_MAX_ARGS;
    BOOL bInArguments = FALSE;
    DISPPARAMS dp  = { 0 };
    DISPID dispID;
    UINT uiArgErr;

    va_start(marker, szMember);

    if (pResult == NULL || pDisp == NULL || szMember == NULL) {
        return E_INVALIDARG;
    }

    switch (vType) {
        case 'w': returnType = VT_UI2; break;
        case 'd': returnType = VT_I4; break;
        case 'u': returnType = VT_UI4; break;
        case 'q': returnType = VT_UI8; break;
        case 'e': returnType = VT_R8; break;
        case 'b': returnType = VT_BOOL; break;
        case 'S': returnType = VT_BSTR; break;
        case 'o': returnType = VT_DISPATCH; break;
#ifndef _WIN64
        case 'p': returnType = VT_I4; break;
#else
        case 'p': returnType = VT_I8; break;
#endif
        default:
            return E_INVALIDARG;
    }

    do {
        if (cchDest-- == 0) {
            return E_INVALIDARG;
        }
    } while (*szTemp++ = *szMember++);

    pDisp->lpVtbl->AddRef(pDisp);

    for (szTemp = szCopy; *szTemp; ++szTemp) {
        if (!bInArguments && (*szTemp == L'(' || *szTemp == L' ' || *szTemp == L'=') ) {
            bInArguments = TRUE;

            *szTemp = L'\0';
        }
        else if  (*szTemp == L'%') {
            if (!bInArguments) {
                bInArguments = TRUE;
                *szTemp = L'\0';
            }

            if (--iArg == -1) {
                hr = E_INVALIDARG;
                break;
            }

            ++szTemp;

            hr = wmi_extract_arg(&vtArgs[iArg], (char)*szTemp, &bFreeList[iArg], &marker);

            if (FAILED(hr)) {
                break;
            }
        }
    }

    if (SUCCEEDED(hr)) {
        cArgs = DH_MAX_ARGS - iArg;
        szTemp = szCopy;
        hr = pDisp->lpVtbl->GetIDsOfNames(pDisp, &IID_NULL, (LPOLESTR*)&szTemp, 1, LOCALE_USER_DEFAULT, &dispID);

        if (SUCCEEDED(hr)) {
            fn_VariantInit(&vtResult);

            dp.cArgs  = cArgs;
            dp.rgvarg = &vtArgs[DH_MAX_ARGS - cArgs];

            hr = pDisp->lpVtbl->Invoke(pDisp, dispID, &IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET|DISPATCH_METHOD, &dp, &vtResult, NULL, &uiArgErr);
        }

        for (iArg = DH_MAX_ARGS - cArgs; iArg < DH_MAX_ARGS; ++iArg) {
            if (bFreeList[iArg]) {
                fn_VariantClear(&vtArgs[iArg]);
            }
        }

        if (SUCCEEDED(hr) && vtResult.vt != returnType && returnType != VT_EMPTY) {
            hr = fn_VariantChangeType(&vtResult, &vtResult, 16 , returnType);
            if (FAILED(hr)) {
                fn_VariantClear(&vtResult);
            }
        }
    }
    else {
        for (++iArg; iArg < DH_MAX_ARGS; ++iArg) {
            if (bFreeList[iArg]) {
                fn_VariantClear(&vtArgs[iArg]);
            }
        }
    }

    pDisp->lpVtbl->Release(pDisp);

    if (FAILED(hr)) {
        return hr;
    }

    switch (vType) {
        case 'w':
            *((WORD*)pResult) = V_UI2(&vtResult);
            break;
        case 'd':
            *((LONG*) pResult) = V_I4(&vtResult);
            break;
        case 'u':
            *((ULONG*)pResult) = V_UI4(&vtResult);
            break;
        case 'q':
            *((ULONG64*)pResult) = V_UI8(&vtResult);
            break;
        case 'e':
            *((DOUBLE*) pResult) = V_R8(&vtResult);
            break;
        case 'b':
            *((BOOL*) pResult) = V_BOOL(&vtResult);
            break;
        case 'S':
            *((LPWSTR*) pResult) = V_BSTR(&vtResult);
            break;
        case 'o':
            *((IDispatch**) pResult) = V_DISPATCH(&vtResult);
            if (V_DISPATCH(&vtResult) == NULL) hr = E_NOINTERFACE;
            break;
        case 'p':
#ifndef _WIN64
            *((LPVOID *) pResult) = (LPVOID) V_I4(&vtResult);
#else
            *((LPVOID *) pResult) = (LPVOID) V_I8(&vtResult);
#endif
            break;
    }

    va_end(marker);

    return hr;
}

HRESULT wmi_enum_begin(IEnumVARIANT** ppEnum, IDispatch* pDisp)
{
    HRESULT hr;
    DISPPARAMS dp = {0};
    VARIANT vtResult;

    if (pDisp == NULL) {
        return E_INVALIDARG;
    }

    hr = pDisp->lpVtbl->Invoke(pDisp, DISPID_NEWENUM, &IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD | DISPATCH_PROPERTYGET, &dp, &vtResult, NULL, NULL);

    if (FAILED(hr)) {
        return hr;
    }

    if (vtResult.vt == VT_DISPATCH) {
        hr = vtResult.pdispVal->lpVtbl->QueryInterface(vtResult.pdispVal, &IID_IEnumVARIANT, (void **) ppEnum);
    }
    else if (vtResult.vt == VT_UNKNOWN) {
        hr = vtResult.punkVal->lpVtbl->QueryInterface(vtResult.punkVal, &IID_IEnumVARIANT, (void **) ppEnum);
    }
    else {
        hr = E_NOINTERFACE;
    }

    fn_VariantClear(&vtResult);

    return hr;
}

HRESULT wmi_enum_next(IEnumVARIANT* pEnum, IDispatch** ppDisp)
{
    VARIANT vtResult;
    HRESULT hr;

    if (pEnum == NULL) {
        return E_INVALIDARG;
    }

    hr = pEnum->lpVtbl->Next(pEnum, 1, &vtResult, NULL);

    if (hr == S_OK) {
        if (vtResult.vt == VT_DISPATCH) {
            *ppDisp = vtResult.pdispVal;
        }
        else {
            hr = fn_VariantChangeType(&vtResult, &vtResult, 0, VT_DISPATCH);
            if (SUCCEEDED(hr)) {
                *ppDisp = vtResult.pdispVal;
            }
            else {
                fn_VariantClear(&vtResult);
            }
        }
    }

    return hr;
}

typedef struct _wmi_class_property
{
    char identifierType;
    void* pResult;
    wchar_t* propertyName;
} wmi_class_property_t;

typedef int (*FnPropertiesFormatter)(wchar_t* buffer, int bufferSize);

typedef struct _wmi_class_info
{
    wchar_t className[32];
    void* pStruct;
    uint32_t structSize;
    FnPropertiesFormatter fnPropertiesFormatter;
    wmi_class_property_t* pClassProperties;
} wmi_class_info_t;

// Информация о материнской плате
struct _wmi_motherboard_info
{
    wchar_t* Manufacturer;
    wchar_t* Name;
    wchar_t* Product;
    wchar_t* SerialNumber;
    wchar_t* Version;
} wmiMotherboardInfo;

wmi_class_property_t motherboardProps[] = {
    {'S', &wmiMotherboardInfo.Manufacturer, L"Manufacturer"},
    {'S', &wmiMotherboardInfo.Name, L"Name"},
    {'S', &wmiMotherboardInfo.Product, L"Product"},
    {'S', &wmiMotherboardInfo.SerialNumber, L"SerialNumber"},
    {'S', &wmiMotherboardInfo.Version, L"Version"},
    {0, NULL, NULL}
};

int fnMotherboardFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%s|%s",
        wmiMotherboardInfo.Manufacturer, wmiMotherboardInfo.Name, wmiMotherboardInfo.Product, wmiMotherboardInfo.SerialNumber, wmiMotherboardInfo.Version);
}


// Информация о BIOS
struct _wmi_bios_info
{
    wchar_t* Manufacturer;
    wchar_t* Caption;
    wchar_t* BuildNumber;
    wchar_t* ListOfLanguages;
    wchar_t* CurrentLanguage;
    wchar_t* Version;
    BOOL PrimaryBIOS;
    BOOL SMBIOSPresent;
    wchar_t* SMBIOSBIOSVersion;
    uint16_t SMBIOSMajorVersion;
    uint16_t SMBIOSMinorVersion;
} wmiBIOSInfo;

wmi_class_property_t biosProps[] = {
    {'S', &wmiBIOSInfo.Manufacturer, L"Manufacturer"},
    {'S', &wmiBIOSInfo.Caption, L"Caption"},
    {'S', &wmiBIOSInfo.BuildNumber, L"BuildNumber"},
    {'S', &wmiBIOSInfo.ListOfLanguages, L"ListOfLanguages"},
    {'S', &wmiBIOSInfo.CurrentLanguage, L"CurrentLanguage"},
    {'S', &wmiBIOSInfo.Version, L"Version"},
    {'b', &wmiBIOSInfo.PrimaryBIOS, L"PrimaryBIOS"},
    {'b', &wmiBIOSInfo.SMBIOSPresent, L"SMBIOSPresent"},
    {'S', &wmiBIOSInfo.SMBIOSBIOSVersion, L"SMBIOSBIOSVersion"},
    {'w', &wmiBIOSInfo.SMBIOSMajorVersion, L"SMBIOSMajorVersion"},
    {'w', &wmiBIOSInfo.SMBIOSMinorVersion, L"SMBIOSMinorVersion"},
    {0, NULL, NULL}
};

int fnBIOSFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%s|%s|%s|%d|%d|%s|%hu|%hu",
        wmiBIOSInfo.Manufacturer, wmiBIOSInfo.Caption, wmiBIOSInfo.BuildNumber, wmiBIOSInfo.ListOfLanguages,
        wmiBIOSInfo.CurrentLanguage, wmiBIOSInfo.Version, (wmiBIOSInfo.PrimaryBIOS ? 1 : 0), (wmiBIOSInfo.SMBIOSPresent ? 1 : 0),
        wmiBIOSInfo.SMBIOSBIOSVersion, wmiBIOSInfo.SMBIOSMajorVersion, wmiBIOSInfo.SMBIOSMinorVersion);
}

// Информация о процессоре
struct _wmi_processor_info
{
    wchar_t* Manufacturer;
    wchar_t* Name;
    wchar_t* Caption;
    wchar_t* ProcessorId;
    wchar_t* SocketDesignation;
    wchar_t* Role;
    uint16_t ProcessorType;
    uint16_t Family;
    uint16_t AddressWidth;
    uint16_t DataWidth;
    uint32_t NumberOfCores;
    uint32_t NumberOfLogicalProcessors;
    uint32_t L2CacheSize;
    uint32_t L3CacheSize;
} wmiProcessorInfo;

wmi_class_property_t processorProps[] = {
    {'S', &wmiProcessorInfo.Manufacturer, L"Manufacturer"},
    {'S', &wmiProcessorInfo.Name, L"Name"},
    {'S', &wmiProcessorInfo.Caption, L"Caption"},
    {'S', &wmiProcessorInfo.ProcessorId, L"ProcessorId"},
    {'S', &wmiProcessorInfo.SocketDesignation, L"SocketDesignation"},
    {'S', &wmiProcessorInfo.Role, L"Role"},
    {'w', &wmiProcessorInfo.ProcessorType, L"ProcessorType"},
    {'w', &wmiProcessorInfo.Family, L"Family"},
    {'w', &wmiProcessorInfo.AddressWidth, L"AddressWidth"},
    {'w', &wmiProcessorInfo.DataWidth, L"DataWidth"},
    {'u', &wmiProcessorInfo.NumberOfCores, L"NumberOfCores"},
    {'u', &wmiProcessorInfo.NumberOfLogicalProcessors, L"NumberOfLogicalProcessors"},
    {'u', &wmiProcessorInfo.L2CacheSize, L"L2CacheSize"},
    {'u', &wmiProcessorInfo.L3CacheSize, L"L3CacheSize"},
    {0, NULL, NULL}
};

int fnProcessorFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%s|%s|%s|%hu|%hu|%hu|%hu|%u|%u|%u|%u",
        wmiProcessorInfo.Manufacturer, wmiProcessorInfo.Name, wmiProcessorInfo.Caption, wmiProcessorInfo.ProcessorId, wmiProcessorInfo.SocketDesignation, wmiProcessorInfo.Role,
        wmiProcessorInfo.ProcessorType, wmiProcessorInfo.Family, wmiProcessorInfo.AddressWidth, wmiProcessorInfo.DataWidth,
        wmiProcessorInfo.NumberOfCores, wmiProcessorInfo.NumberOfLogicalProcessors, wmiProcessorInfo.L2CacheSize, wmiProcessorInfo.L3CacheSize);
}

// Информация о физической памяти.
struct _wmi_physmemory_info
{
    wchar_t* BankLabel;
    wchar_t* PartNumber;
    wchar_t* DeviceLocator;
    wchar_t* Manufacturer;
    uint64_t Capacity;
    uint16_t DataWidth;
    uint16_t FormFactor;
    BOOL HotSwappable;
    BOOL Replaceable;
    uint32_t Speed;
    uint16_t TypeDetail;
} wmiPhysMemoryInfo;

wmi_class_property_t physMemoryProps[] = {
    {'S', &wmiPhysMemoryInfo.BankLabel, L"BankLabel"},
    {'S', &wmiPhysMemoryInfo.PartNumber, L"PartNumber"},
    {'S', &wmiPhysMemoryInfo.DeviceLocator, L"DeviceLocator"},
    {'S', &wmiPhysMemoryInfo.Manufacturer, L"Manufacturer"},
    {'q', &wmiPhysMemoryInfo.Capacity, L"Capacity"},
    {'w', &wmiPhysMemoryInfo.DataWidth, L"DataWidth"},
    {'w', &wmiPhysMemoryInfo.FormFactor, L"FormFactor"},
    {'b', &wmiPhysMemoryInfo.HotSwappable, L"HotSwappable"},
    {'b', &wmiPhysMemoryInfo.Replaceable, L"Replaceable"},
    {'u', &wmiPhysMemoryInfo.Speed, L"Speed"},
    {'w', &wmiPhysMemoryInfo.TypeDetail, L"TypeDetail"},
    {0, NULL, NULL}
};

int fnPhysMemoryFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%s|%I64u|%hu|%hu|%d|%d|%u|%hu",
        wmiPhysMemoryInfo.PartNumber, wmiPhysMemoryInfo.BankLabel, wmiPhysMemoryInfo.DeviceLocator, wmiPhysMemoryInfo.Manufacturer,
        wmiPhysMemoryInfo.Capacity, wmiPhysMemoryInfo.DataWidth, wmiPhysMemoryInfo.FormFactor,
        (wmiPhysMemoryInfo.HotSwappable ? 1 : 0), (wmiPhysMemoryInfo.Replaceable ? 1 : 0), wmiPhysMemoryInfo.Speed, wmiPhysMemoryInfo.TypeDetail);
}

// Информация о шине
struct _wmi_usbcontroller_info
{
    wchar_t* Caption;
    wchar_t* Manufacturer;
} wmiUSBControllerInfo;

wmi_class_property_t usbControllerProps[] = {
    {'S', &wmiUSBControllerInfo.Caption, L"Caption"},
    {'S', &wmiUSBControllerInfo.Manufacturer, L"Manufacturer"},
    {0, NULL, NULL}
};

int fnUSBControllerFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s",
        wmiUSBControllerInfo.Caption, wmiUSBControllerInfo.Manufacturer);
}


// Информация о жёстком диске.
struct _wmi_diskdrive_info
{
    wchar_t* Caption;
    wchar_t* Manufacturer;
    wchar_t* Model;
    wchar_t* Name;
    wchar_t* SerialNumber;
    wchar_t* InterfaceType;
    uint64_t Size;
    uint32_t TotalHeads;
    uint64_t TotalSectors;
    uint64_t TotalTracks;
    uint64_t TotalCylinders;
    uint32_t BytesPerSector;
    uint32_t TracksPerCylinder;
    uint32_t Partitions;
    uint32_t SCSIBus;
    uint16_t SCSILogicalUnit;
    uint16_t SCSIPort;
    uint16_t SCSITargetId;
} wmiDiskDriveInfo;

wmi_class_property_t diskDriveProps[] = {
    {'S', &wmiDiskDriveInfo.Caption, L"Caption"},
    {'S', &wmiDiskDriveInfo.Manufacturer, L"Manufacturer"},
    {'S', &wmiDiskDriveInfo.Model, L"Model"},
    {'S', &wmiDiskDriveInfo.Name, L"Name"},
    {'S', &wmiDiskDriveInfo.SerialNumber, L"SerialNumber"},
    {'S', &wmiDiskDriveInfo.InterfaceType, L"InterfaceType"},
    {'u', &wmiDiskDriveInfo.Partitions, L"Partitions"},
    {'q', &wmiDiskDriveInfo.Size, L"Size"},
    {'u', &wmiDiskDriveInfo.TotalHeads, L"TotalHeads"},
    {'q', &wmiDiskDriveInfo.TotalSectors, L"TotalSectors"},
    {'q', &wmiDiskDriveInfo.TotalTracks, L"TotalTracks"},
    {'q', &wmiDiskDriveInfo.TotalCylinders, L"TotalCylinders"},
    {'u', &wmiDiskDriveInfo.BytesPerSector, L"BytesPerSector"},
    {'u', &wmiDiskDriveInfo.TracksPerCylinder, L"TracksPerCylinder"},
    {'u', &wmiDiskDriveInfo.SCSIBus, L"SCSIBus"},
    {'w', &wmiDiskDriveInfo.SCSILogicalUnit, L"SCSILogicalUnit"},
    {'w', &wmiDiskDriveInfo.SCSIPort, L"SCSIPort"},
    {'w', &wmiDiskDriveInfo.SCSITargetId, L"SCSITargetId"},
    {0, NULL, NULL}
};

int fnDiskDriveFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%s|%s|%s|%u|%I64u|%u|%I64u|%I64u|%I64u|%u|%u|%u|%hu|%hu|%hu",
        wmiDiskDriveInfo.Caption, wmiDiskDriveInfo.Manufacturer, wmiDiskDriveInfo.Model, wmiDiskDriveInfo.Name,
        wmiDiskDriveInfo.SerialNumber, wmiDiskDriveInfo.InterfaceType, wmiDiskDriveInfo.Partitions, wmiDiskDriveInfo.Size, wmiDiskDriveInfo.TotalHeads,
        wmiDiskDriveInfo.TotalSectors, wmiDiskDriveInfo.TotalTracks, wmiDiskDriveInfo.TotalCylinders, wmiDiskDriveInfo.BytesPerSector,
        wmiDiskDriveInfo.TracksPerCylinder, wmiDiskDriveInfo.SCSIBus, wmiDiskDriveInfo.SCSILogicalUnit, wmiDiskDriveInfo.SCSIPort, wmiDiskDriveInfo.SCSITargetId);
}

// Информация о сетевом устройстве.
struct _wmi_netconf_info
{
    uint32_t InterfaceIndex;
    wchar_t* AdapterType;
    wchar_t* ProductName;
    wchar_t* Manufacturer;
    wchar_t* ServiceName;
    wchar_t* NetConnectionID;
    wchar_t* MACAddress;
    BOOL NetEnabled;
    BOOL PhysicalAdapter;
    uint64_t Speed;
    uint64_t MaxSpeed;
    uint16_t NetConnectionStatus;
} wmiNetConfInfo;

wmi_class_property_t netConfProps[] = {
    {'u', &wmiNetConfInfo.InterfaceIndex, L"InterfaceIndex"},
    {'S', &wmiNetConfInfo.AdapterType, L"AdapterType"},
    {'S', &wmiNetConfInfo.ProductName, L"ProductName"},
    {'S', &wmiNetConfInfo.Manufacturer, L"Manufacturer"},
    {'S', &wmiNetConfInfo.ServiceName, L"ServiceName"},
    {'S', &wmiNetConfInfo.NetConnectionID, L"NetConnectionID"},
    {'S', &wmiNetConfInfo.MACAddress, L"MACAddress"},
    {'b', &wmiNetConfInfo.NetEnabled, L"NetEnabled"},
    {'b', &wmiNetConfInfo.PhysicalAdapter, L"PhysicalAdapter"},
    {'q', &wmiNetConfInfo.Speed, L"Speed"},
    {'w', &wmiNetConfInfo.NetConnectionStatus, L"NetConnectionStatus"},
    {0, NULL, L"IP"},
    {0, NULL, L"Mask"},
    {0, NULL, L"Gateway"},
    {0, NULL, L"DHCPServer"},
    {0, NULL, NULL}
};

static IP_ADAPTER_INFO* pAdapterList = NULL;

int fnNetConfFormatter(wchar_t* buffer, int bufferSize)
{
    IP_ADAPTER_INFO* pAdapter = NULL;
    ULONG ulBufLen = 0;
    DWORD err;
    int ret = 0;

    if (pAdapterList == NULL) {
        err = fn_GetAdaptersInfo(pAdapterList, &ulBufLen);
        if (err == ERROR_BUFFER_OVERFLOW) {
            pAdapterList = (IP_ADAPTER_INFO*)fn_memalloc(ulBufLen);
            if (pAdapterList == NULL) {
                return 0;
            }
            err = fn_GetAdaptersInfo(pAdapterList, &ulBufLen);
        }

        if (err != ERROR_SUCCESS) {
            fn_memfree(pAdapterList);
            return 0;
        }
    }

    pAdapter = pAdapterList;
    while (pAdapter != NULL) {
        if (pAdapter->Index == wmiNetConfInfo.InterfaceIndex) {
            break;
        }
        pAdapter = pAdapter->Next;
    }

    if (pAdapter != NULL) {
        wchar_t* sVal;
        ret = fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%s|%s|%s|%d|%d|%I64u|%I64u|%hu",
            wmiNetConfInfo.AdapterType, wmiNetConfInfo.ProductName, wmiNetConfInfo.Manufacturer, wmiNetConfInfo.ServiceName, wmiNetConfInfo.NetConnectionID, wmiNetConfInfo.MACAddress,
            (wmiNetConfInfo.NetEnabled ? 1 : 0), (wmiNetConfInfo.PhysicalAdapter ? 1 : 0), wmiNetConfInfo.Speed, wmiNetConfInfo.NetConnectionStatus);

        sVal = fn_utils_ansi2wide(pAdapter->IpAddressList.IpAddress.String);
        fn_lstrcatW(buffer, L"|"); fn_lstrcatW(buffer, sVal); fn_memfree(sVal);
        sVal = fn_utils_ansi2wide(pAdapter->IpAddressList.IpMask.String);
        fn_lstrcatW(buffer, L"|"); fn_lstrcatW(buffer, sVal); fn_memfree(sVal);
        fn_lstrcatW(buffer, L"|");
        if (fn_lstrlenA(pAdapter->GatewayList.IpAddress.String) > 0) {
            sVal = fn_utils_ansi2wide(pAdapter->GatewayList.IpAddress.String);
            fn_lstrcatW(buffer, sVal); fn_memfree(sVal);
        }
        else {
            fn_lstrcatW(buffer, L"(null)");
        }
        fn_lstrcatW(buffer, L"|");
        if (pAdapter->DhcpEnabled) {
            sVal = fn_utils_ansi2wide(pAdapter->DhcpServer.IpAddress.String);
            fn_lstrcatW(buffer, sVal); fn_memfree(sVal);
        }
        else {
            fn_lstrcatW(buffer, L"(null)");
        }
    }

    return ret;
}

// Информация о видео контроллере.
struct _wmi_videocontroller_info
{
    wchar_t* Caption;
    wchar_t* DriverVersion;
    wchar_t* VideoModeDescription;
    wchar_t* VideoProcessor;
    uint32_t AdapterRAM;
    uint32_t CurrentHorizontalResolution;
    uint32_t CurrentVerticalResolution;
    uint32_t CurrentBitsPerPixel;
    uint32_t CurrentRefreshRate;
    uint16_t ProtocolSupported;
    uint16_t VideoArchitecture;
    uint16_t VideoMemoryType;
} wmiVideoControllerInfo;

wmi_class_property_t videoControllerProps[] = {
    {'S', &wmiVideoControllerInfo.Caption, L"Caption"},
    {'S', &wmiVideoControllerInfo.DriverVersion, L"DriverVersion"},
    {'S', &wmiVideoControllerInfo.VideoModeDescription, L"VideoModeDescription"},
    {'S', &wmiVideoControllerInfo.VideoProcessor, L"VideoProcessor"},
    {'u', &wmiVideoControllerInfo.AdapterRAM, L"AdapterRAM"},
    {'u', &wmiVideoControllerInfo.CurrentHorizontalResolution, L"CurrentHorizontalResolution"},
    {'u', &wmiVideoControllerInfo.CurrentVerticalResolution, L"CurrentVerticalResolution"},
    {'u', &wmiVideoControllerInfo.CurrentBitsPerPixel, L"CurrentBitsPerPixel"},
    {'u', &wmiVideoControllerInfo.CurrentRefreshRate, L"CurrentRefreshRate"},
    {'w', &wmiVideoControllerInfo.ProtocolSupported, L"ProtocolSupported"},
    {'w', &wmiVideoControllerInfo.VideoArchitecture, L"VideoArchitecture"},
    {'w', &wmiVideoControllerInfo.VideoMemoryType, L"VideoMemoryType"},
    {0, NULL, NULL}
};

int fnVideoControllerFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%s|%u|%u|%u|%u|%u|%hu|%hu|%hu",
        wmiVideoControllerInfo.Caption, wmiVideoControllerInfo.DriverVersion, wmiVideoControllerInfo.VideoModeDescription, wmiVideoControllerInfo.VideoProcessor,
        wmiVideoControllerInfo.AdapterRAM, wmiVideoControllerInfo.CurrentHorizontalResolution, wmiVideoControllerInfo.CurrentVerticalResolution,
        wmiVideoControllerInfo.CurrentBitsPerPixel, wmiVideoControllerInfo.CurrentRefreshRate, wmiVideoControllerInfo.ProtocolSupported,
        wmiVideoControllerInfo.VideoArchitecture, wmiVideoControllerInfo.VideoMemoryType);
}

// Информация о мониторе.
struct _wmi_monitor_info
{
    wchar_t* Caption;
    wchar_t* MonitorManufacturer;
    wchar_t* MonitorType;
    wchar_t* VideoProcessor;
    uint32_t ScreenWidth;
    uint32_t ScreenHeight;
} wmiMonitorInfo;

wmi_class_property_t monitorProps[] = {
    {'S', &wmiMonitorInfo.Caption, L"Caption"},
    {'S', &wmiMonitorInfo.MonitorManufacturer, L"MonitorManufacturer"},
    {'S', &wmiMonitorInfo.MonitorType, L"MonitorType"},
    {'u', &wmiMonitorInfo.ScreenWidth, L"ScreenWidth"},
    {'u', &wmiMonitorInfo.ScreenHeight, L"ScreenHeight"},
    {0, NULL, NULL}
};

int fnMonitorFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%u|%u",
        wmiMonitorInfo.Caption, wmiMonitorInfo.MonitorManufacturer, wmiMonitorInfo.MonitorType, wmiMonitorInfo.ScreenWidth, wmiMonitorInfo.ScreenHeight);
}

// Информация о звуковом устройстве.
struct _wmi_sounddevice_info
{
    wchar_t* Caption;
    wchar_t* Manufacturer;
} wmiSoundDeviceInfo;

wmi_class_property_t sounddeviceProps[] = {
    {'S', &wmiSoundDeviceInfo.Caption, L"Caption"},
    {'S', &wmiSoundDeviceInfo.Manufacturer, L"Manufacturer"},
    {0, NULL, NULL}
};

int fnSoundDeviceFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s",
        wmiSoundDeviceInfo.Caption, wmiSoundDeviceInfo.Manufacturer);
}

// Информация о клавиатуре.
struct _wmi_keyboard_info
{
    wchar_t* Caption;
    wchar_t* Layout;
} wmiKeyboardInfo;

wmi_class_property_t keyboardProps[] = {
    {'S', &wmiKeyboardInfo.Caption, L"Caption"},
    {'S', &wmiKeyboardInfo.Layout, L"Layout"},
    {0, NULL, NULL}
};

int fnKeyboardFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s",
        wmiKeyboardInfo.Caption, wmiKeyboardInfo.Layout);
}

// Информация о томах.
struct _wmi_volume_info
{
    wchar_t* Caption;
    wchar_t* Label;
    wchar_t* FileSystem;
    uint64_t Capacity;
    uint64_t FreeSpace;
    uint64_t BlockSize;
    uint32_t DriveType;
    BOOL Automount;
    BOOL BootVolume;
    BOOL SystemVolume;
} wmiVolumeInfo;

wmi_class_property_t volumeProps[] = {
    {'S', &wmiVolumeInfo.Caption, L"Caption"},
    {'S', &wmiVolumeInfo.Label, L"Label"},
    {'S', &wmiVolumeInfo.FileSystem, L"FileSystem"},
    {'q', &wmiVolumeInfo.Capacity, L"Capacity"},
    {'q', &wmiVolumeInfo.FreeSpace, L"FreeSpace"},
    {'q', &wmiVolumeInfo.BlockSize, L"BlockSize"},
    {'b', &wmiVolumeInfo.DriveType, L"DriveType"},
    {'b', &wmiVolumeInfo.Automount, L"Automount"},
    {'b', &wmiVolumeInfo.BootVolume, L"BootVolume"},
    {'b', &wmiVolumeInfo.SystemVolume, L"SystemVolume"},
    {0, NULL, NULL}
};

int fnVolumeFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%I64u|%I64u|%I64u|%u|%d|%d|%d",
        wmiVolumeInfo.Caption, wmiVolumeInfo.Label, wmiVolumeInfo.FileSystem, wmiVolumeInfo.Capacity, wmiVolumeInfo.FreeSpace, wmiVolumeInfo.BlockSize,
        wmiVolumeInfo.DriveType, (wmiVolumeInfo.Automount ? 1 : 0), (wmiVolumeInfo.BootVolume ? 1 : 0), (wmiVolumeInfo.SystemVolume ? 1 : 0));
}

// Информация об аккаунте пользователя.
struct _wmi_useraccount_info
{
    wchar_t* Caption;
    wchar_t* FullName;
    wchar_t* Description;
    wchar_t* SID;
    BOOL LocalAccount;
    BOOL Disabled;
    BOOL Lockout;
    BOOL PasswordRequired;
    BOOL PasswordChangeable;
    BOOL PasswordExpires;
} wmiUserAccountInfo;

wmi_class_property_t useraccountProps[] = {
    {'S', &wmiUserAccountInfo.Caption, L"Caption"},
    {'S', &wmiUserAccountInfo.FullName, L"FullName"},
    {'S', &wmiUserAccountInfo.Description, L"Description"},
    {'S', &wmiUserAccountInfo.SID, L"SID"},
    {'b', &wmiUserAccountInfo.LocalAccount, L"LocalAccount"},
    {'b', &wmiUserAccountInfo.Disabled, L"Disabled"},
    {'b', &wmiUserAccountInfo.Lockout, L"Lockout"},
    {'b', &wmiUserAccountInfo.PasswordRequired, L"PasswordRequired"},
    {'b', &wmiUserAccountInfo.PasswordChangeable, L"PasswordChangeable"},
    {'b', &wmiUserAccountInfo.PasswordExpires, L"PasswordExpires"},
    {0, NULL, NULL}
};

int fnUserAccountFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%s|%d|%d|%d|%d|%d|%d",
        wmiUserAccountInfo.Caption, (wmiUserAccountInfo.FullName[0] ? wmiUserAccountInfo.FullName : L"(null)"),
        (wmiUserAccountInfo.Description[0] ? wmiUserAccountInfo.Description : L"(null)"), wmiUserAccountInfo.SID,
        (wmiUserAccountInfo.LocalAccount ? 1 : 0), (wmiUserAccountInfo.Disabled ? 1 : 0), (wmiUserAccountInfo.Lockout ? 1 : 0),
        (wmiUserAccountInfo.PasswordRequired ? 1 : 0), (wmiUserAccountInfo.PasswordChangeable ? 1 : 0), (wmiUserAccountInfo.PasswordExpires ? 1 : 0));
}


// Информация о группе.
struct _wmi_group_info
{
    wchar_t* Caption;
    wchar_t* Description;
    wchar_t* SID;
    BOOL LocalAccount;
} wmiGroupInfo;

wmi_class_property_t groupProps[] = {
    {'S', &wmiGroupInfo.Caption, L"Caption"},
    {'S', &wmiGroupInfo.Description, L"Description"},
    {'S', &wmiGroupInfo.SID, L"SID"},
    {'b', &wmiGroupInfo.LocalAccount, L"LocalAccount"},
    {0, NULL, NULL}
};

int fnGroupFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s|%d",
        wmiGroupInfo.Caption, wmiGroupInfo.Description, wmiGroupInfo.SID, (wmiGroupInfo.LocalAccount ? 1 : 0));
}

// Информация о шаре.
struct _wmi_share_info
{
    wchar_t* Caption;
    wchar_t* Name;
    wchar_t* Path;
} wmiShareInfo;

wmi_class_property_t shareProps[] = {
    {'S', &wmiShareInfo.Caption, L"Caption"},
    {'S', &wmiShareInfo.Name, L"Name"},
    {'S', &wmiShareInfo.Path, L"Path"},
    {0, NULL, NULL}
};

int fnShareFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s",
        wmiShareInfo.Caption, wmiShareInfo.Name, (wmiShareInfo.Path[0] ? wmiShareInfo.Path : L"(null)"));
}


// Информация об обновлении.
struct _wmi_hotfix_info
{
    LPWSTR szDescription;
    LPWSTR szHotFixID;
    LPWSTR szInstalledBy;
} wmiHotFixInfo;

wmi_class_property_t hotfixProps[] = {
    {'S', &wmiHotFixInfo.szDescription, L"Description"},
    {'S', &wmiHotFixInfo.szHotFixID, L"HotFixID"},
    {'S', &wmiHotFixInfo.szInstalledBy, L"InstalledBy"},
    {0, NULL, NULL}
};

int fnHotFixFormatter(wchar_t* buffer, int bufferSize)
{
    return fn_wnsprintfW(buffer, bufferSize, L"%s|%s|%s",
        wmiHotFixInfo.szDescription, wmiHotFixInfo.szHotFixID, wmiHotFixInfo.szInstalledBy);
}


wmi_class_info_t classes[] = {
    {L"Win32_BaseBoard", &wmiMotherboardInfo, sizeof(wmiMotherboardInfo), fnMotherboardFormatter, motherboardProps},
    {L"Win32_BIOS", &wmiBIOSInfo, sizeof(wmiBIOSInfo), fnBIOSFormatter, biosProps},
    {L"Win32_Processor", &wmiProcessorInfo, sizeof(wmiProcessorInfo), fnProcessorFormatter, processorProps},
    {L"Win32_PhysicalMemory", &wmiPhysMemoryInfo, sizeof(wmiPhysMemoryInfo), fnPhysMemoryFormatter, physMemoryProps},
    {L"Win32_DiskDrive", &wmiDiskDriveInfo, sizeof(wmiDiskDriveInfo), fnDiskDriveFormatter, diskDriveProps},
    {L"Win32_NetworkAdapter", &wmiNetConfInfo, sizeof(wmiNetConfInfo), fnNetConfFormatter, netConfProps},
    {L"Win32_USBController", &wmiUSBControllerInfo, sizeof(wmiUSBControllerInfo), fnUSBControllerFormatter, usbControllerProps},
    {L"Win32_VideoController", &wmiVideoControllerInfo, sizeof(wmiVideoControllerInfo), fnVideoControllerFormatter, videoControllerProps},
    {L"Win32_DesktopMonitor", &wmiMonitorInfo, sizeof(wmiMonitorInfo), fnMonitorFormatter, monitorProps},
    {L"Win32_SoundDevice", &wmiSoundDeviceInfo, sizeof(wmiSoundDeviceInfo), fnSoundDeviceFormatter, sounddeviceProps},
    {L"Win32_Keyboard", &wmiKeyboardInfo, sizeof(wmiKeyboardInfo), fnKeyboardFormatter, keyboardProps},
//     Win32_OperatingSystem
//     Win32_NTDomain
//     Win32_LogicalDisk
    {L"Win32_Volume", &wmiVolumeInfo, sizeof(wmiVolumeInfo), fnVolumeFormatter, volumeProps},
    {L"Win32_UserAccount", &wmiUserAccountInfo, sizeof(wmiUserAccountInfo), fnUserAccountFormatter, useraccountProps},
    {L"Win32_Group", &wmiGroupInfo, sizeof(wmiGroupInfo), fnGroupFormatter, groupProps},
    {L"Win32_Share", &wmiShareInfo, sizeof(wmiShareInfo), fnShareFormatter, shareProps},
//     Win32_IP4RouteTable
//     Win32_Environment
//     {L"Win32_QuickFixEngineering", &wmiHotFixInfo, sizeof(wmiHotFixInfo), fnHotFixFormatter, hotfixProps},
    {L"", NULL, 0, NULL, NULL}
};

#define WMI_TRY(func) if (FAILED(func)) { goto cleanup; }

void wmi_grab(LPSTREAM pStream)
{
#define BUFFER_SIZE 4096
    uint32_t startPos;
    uint32_t totalSize = 0;
    wchar_t selectBuffer[128];
    wchar_t* buffer = NULL;
    wmi_class_info_t* pWmiClass = classes;
    IDispatch* pWmiService = NULL;
    IDispatch* pServiceLocator = NULL;
    int utf8Size;

    buffer = fn_memalloc(BUFFER_SIZE);

    startPos = stream_get_pos(pStream);
    stream_write_dword(pStream, 0); // Размер списка приложений.

    WMI_TRY(fn_CoGetObject(L"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2", NULL, &IID_IDispatch, &pWmiService));

    for ( ; pWmiClass->pStruct != NULL; ++pWmiClass) {
        IEnumVARIANT * pServiceEnumerator = NULL;
        IDispatch* pServiceItem = NULL;
        wmi_class_property_t* pClassPropInfo;

        fn_lstrcpyW(selectBuffer, L"SELECT * FROM ");
        fn_lstrcatW(selectBuffer, pWmiClass->className);
        WMI_TRY(wmi_get_value('o', &pServiceLocator, pWmiService, L"ExecQuery(%S)", selectBuffer));

        fn_lstrcpyW(buffer, pWmiClass->className);
        fn_lstrcatW(buffer, L"\n");
        for (pClassPropInfo = pWmiClass->pClassProperties; pClassPropInfo->propertyName != NULL; ++pClassPropInfo) {
            fn_lstrcatW(buffer, L"|");
            fn_lstrcatW(buffer, pClassPropInfo->propertyName);
        }
        fn_lstrcatW(buffer, L"\n\n");
        totalSize += stream_write_utf8_string(pStream, buffer);

        if (SUCCEEDED(wmi_enum_begin(&pServiceEnumerator, pServiceLocator))) {
            while (wmi_enum_next(pServiceEnumerator, &pServiceItem) == NOERROR) {
                __stosb((uint8_t*)pWmiClass->pStruct, 0, pWmiClass->structSize);

                for (pClassPropInfo = pWmiClass->pClassProperties; pClassPropInfo->identifierType != 0; ++pClassPropInfo) {
                    wmi_get_value(pClassPropInfo->identifierType, pClassPropInfo->pResult, pServiceItem, pClassPropInfo->propertyName);
                }

                pClassPropInfo = pWmiClass->pClassProperties;
                if (pWmiClass->fnPropertiesFormatter(buffer, BUFFER_SIZE) > 0) {
                    utf8Size = stream_write_utf8_string(pStream, buffer);
                    stream_write(pStream, "\n", 1);
                    totalSize += utf8Size + 1;
                }

                for ( ; pClassPropInfo->identifierType != 0; ++pClassPropInfo) {
                    if (pClassPropInfo->identifierType == 'S') {
                        fn_SysFreeString(*(BSTR*)pClassPropInfo->pResult);
                    }
                }

                pServiceItem->lpVtbl->Release(pServiceItem);
                pServiceItem = NULL;
            }
            if (pServiceItem != NULL) {
                pServiceItem->lpVtbl->Release(pServiceItem);
            }
            pServiceEnumerator->lpVtbl->Release(pServiceEnumerator);

            stream_write(pStream, "\n\n\n", 3);
            totalSize += 3;
        }
    }

cleanup:
    fn_memfree(buffer);
    if (pServiceLocator != NULL) {
        pServiceLocator->lpVtbl->Release(pServiceLocator);
    }
    if (pWmiService != NULL) {
        pWmiService->lpVtbl->Release(pWmiService);
    }

    if (pAdapterList != NULL) {
        fn_memfree(pAdapterList);
    }

    stream_seek_offset(pStream, startPos, STREAM_SEEK_SET);
    stream_write_dword(pStream, totalSize);
    stream_goto_end(pStream);
}
