#include <Windows.h>
#include <shlwapi.h>
#include <Wininet.h>
#include <stdio.h>
#include <math.h>

#include "../../../shared/platform.h"
#include "../../../shared/types.h"
#include "../../../shared/native.h"
#include "../../../shared/utils.h"

#define URLS_IN_FILE "urls.in"
#define CONFIG_TEMP_FILE "config.temp"
#define CONFIG_OUT_FILE "code\\config_data.h"

char configBuffer[65536];

int main(int argc, char** argv)
{
    int ret = EXIT_FAILURE;
    uint8_t* urls = NULL;
    uint8_t* key = NULL;
    size_t sz;

    do {
        printf("Reading %s...", URLS_IN_FILE);
        if (utils_file_exists(URLS_IN_FILE) != ERR_OK) {
            printf("Failed: not exists\n\n");
            break;
        }

        if (utils_read_file(URLS_IN_FILE, &urls, &sz) != ERR_OK) {
            printf("Failed: cannot read\n\n");
            break;
        }

        printf("OK\nArchiving %s\:\n", CONFIG_TEMP_FILE);
        if (!utils_launch_and_verify("rc4_crypter.exe -i=\"" URLS_IN_FILE "\" -o=\"" CONFIG_TEMP_FILE "\"", NULL)) {
            printf(("Failed\n"));
            break;
        }

        printf("OK\nGenerating %s:\n", CONFIG_OUT_FILE);
        if (!utils_launch_and_verify("bin2hex.exe -i=\"" CONFIG_TEMP_FILE "\" -o=\"" CONFIG_OUT_FILE "\" -n=\"config_data\"", NULL)) {
            printf(("Failed\n"));
            break;
        }
        printf("OK\n");

        ret = EXIT_SUCCESS;
    } while (0);

    utils_remove(CONFIG_TEMP_FILE);

    if (urls != NULL) {
        free(urls);
    }

    if (key != NULL) {
        free(key);
    }

    return ret;
}

