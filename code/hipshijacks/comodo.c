#include "ComodoBin.c"

void ph_detect_comodo()
{
    uint8_t* moduleBase;

    moduleBase = (uint8_t*)fn_LoadLibraryW(L"guard32.dll");
    if (moduleBase != NULL) {
        globalData.gHIPSMask |= HIPS_COMODO;
        DbgMsg("COMODO detected!");
    }
}
