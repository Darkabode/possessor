// void ph_detect_osss()
// {
//     HKEY hKey;
//     INLOG("ph_detect_osss() start", 0);
// 
//     if (fnRegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Online Solutions\\osss_gui", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
//         INLOG("ph_detect_osss() OSSS present", 0);
//         gHIPSMask |= PROACTIVE_OSSS;
//     }
//     INLOG("ph_detect_osss() end", 0);
// }
