#include "common.h"
#include "bundles.h"

const char* const _jsonPathFile = "/bundles.json";
char* _bundlesJson = NULL;

void bundles_load_config()
{
    pzfs_file_t zFile;

    if (zfs_open(_pZmoduleBlock->pZfsIo, &zFile, _jsonPathFile, ZFS_MODE_READ, 1) == 0) {
        if (zfs_seek(zFile, 0, ZFS_SEEK_END) == 0) {
            uint32_t fSize = zfs_tell(zFile);
            if (zfs_seek(zFile, 0, ZFS_SEEK_SET) == 0) {
                _bundlesJson = memory_alloc(fSize);
                char* ptr = _bundlesJson;
                uint32_t readed;

                while (fSize != 0) {
                    if (zfs_read(zFile, (uint8_t*)ptr, fSize, &readed) != 0) {
                        break;
                    }
                    fSize -= readed;
                    ptr += readed;
                }

                zfs_close(zFile);
                if (fSize != 0) {
                    memory_free(_bundlesJson);
                    _bundlesJson = NULL;
                }
            }
        }
    }
}

char* bundles_json()
{
    return _bundlesJson;
}