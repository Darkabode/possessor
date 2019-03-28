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
set TEST_BUILD=/D "_TEST_BUILD"
shift
goto parsecommandline

:log_on
rem echo LOG ON
set LOG_ON=/D "LOG_ON"
shift
goto parsecommandline

:use_exploits
rem echo USE_EXPLOITS ON
set USE_EXPLOITS=/D "USE_EXPLOITS"
shift
goto parsecommandline

:use_bootkit
rem echo USE_BOOTKIT ON
set USE_BOOTKIT=/D "USE_BOOTKIT"
shift
goto parsecommandline

:set_build_id
rem echo BUILD_ID
set BUILD_ID=/D "BUILD_ID=%2"
shift
shift
goto parsecommandline

:set_sub_id
rem echo SUB_ID
set SUB_ID=/D "SUB_ID=%2"
shift
shift
goto parsecommandline

:build

call d:\_______\bin\ms_compiler\bin\setenv.bat d:\_______\bin\ms_compiler\ fre x64 WIN7 no_oacr >NUL
set LIB=d:\_______\bin\ms_compiler\lib\win7\amd64;%LIB%
set INCLUDE=d:\_______\bin\ms_compiler\inc\crt;%INCLUDE%
set INCLUDE=c:\Program Files\Microsoft SDKs\Windows\v7.0\Include;%INCLUDE%

cd ..\..\0\dropper\code

cl.exe %TEST_BUILD% %USE_EXPLOITS% %USE_BOOTKIT% %LOG_ON% %BUILD_ID% %SUB_ID% /D "_WIN64" /D "WIN64" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /I "..\..\hde" /O1 /Ob1 /Oi /Os /GL /GF /FD /MT /GS- /Gy /Zp8 /EHs-c- /Zc:forScope- /GR- /W4 /nologo /c /Gz /TC /errorReport:prompt /Fo"..\autobuild\x64\\" dropper.c >compiler64.log
IF ERRORLEVEL 2 GOTO EXIT
IF ERRORLEVEL 1 GOTO EXIT
IF ERRORLEVEL 0 GOTO COMPILER_OK

:COMPILER_OK

cd "..\autobuild\x64"

link.exe /OUT:"..\dropper64.exe" /INCREMENTAL:NO /NOLOGO /LIBPATH:"..\..\..\shared\libs" /MANIFEST:NO /NODEFAULTLIB /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /DLL /LTCG /NOENTRY /SAFESEH:NO /DYNAMICBASE /NXCOMPAT /MACHINE:X64 /DEF:"..\..\code\dropper.def" chkstk64.obj uuid64.lib dropper.obj >linker64.log

IF ERRORLEVEL 2 GOTO EXIT
IF ERRORLEVEL 1 GOTO EXIT
IF ERRORLEVEL 0 GOTO LINKER_OK

:EXIT
ECHO failed

:LINKER_OK
del .\*.obj
del ..\*.exp
del ..\*.lib

cd ..\..

exit