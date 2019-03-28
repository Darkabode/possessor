#ifndef __DEFINES_H_
#define __DEFINES_H_

#pragma pack(push, 1)

typedef struct _shellcode_data
{
    uint32_t ordinal;
    uint32_t dataSize; // Размер дополнительных данных.
    char data[1];
} shellcode_data_t, *pshellcode_data_t;

#pragma pack(pop)

#endif // __DEFINES_H_
