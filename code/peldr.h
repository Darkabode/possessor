#ifndef _PELDR_H_
#define _PELDR_H_

DWORD64 PeGetImageBase(PVOID ImageBase);
PIMAGE_NT_HEADERS PeImageNtHeader(PVOID ImageBase);
PVOID LoadImageSections(PVOID ImageBaseRaw, DWORD *ImageSize);
PVOID PeImageDirectoryEntryToData(PVOID ImageBase, BOOLEAN ImageLoaded, ULONG Directory, PULONG Size, BOOLEAN RVA/* = FALSE*/);
PVOID PeGetProcAddress(PVOID ModuleBase, PCHAR lpProcName, BOOLEAN RVA /*= FALSE*/);
// BOOLEAN PeProcessImport(PVOID pMZ, BOOLEAN Ntdll64 /*= FALSE*/);

#ifndef _WIN64
PIMAGE_BASE_RELOCATION PeProcessRelocationBlock(ULONG_PTR uVA, ULONG uSizeOfBlock, PUSHORT puNextOffset, ULONGLONG lDelta);
#else
PIMAGE_BASE_RELOCATION PeProcessRelocationBlock(ULONG_PTR VA, ULONG SizeOfBlock, PUSHORT NextOffset, LONGLONG Diff) ;
#endif

PVOID PeGetNtdllImageBase();
DWORD_PTR FreeSpaceInHeader(PVOID ImageBase, PIMAGE_NT_HEADERS NtHeaders);
PIMAGE_SECTION_HEADER GetVirtualyLastSectionHeader(PIMAGE_NT_HEADERS NtHeaders);
PIMAGE_SECTION_HEADER GetPhysicalyLastSectionHeader(PIMAGE_NT_HEADERS NtHeaders);
// PVOID LoadPEImage(PVOID ImageBaseRaw);
PIMAGE_SECTION_HEADER PeSearchSection(PVOID ImageBase, PCHAR SectionName);

#endif
