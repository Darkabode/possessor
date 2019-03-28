call d:\_______\bin\ms_compiler\bin\setenv.bat d:\_______\bin\ms_compiler\ fre x86 WXP no_oacr
set LIB=d:\_______\bin\ms_compiler\lib\wxp\i386;%LIB%
set INCLUDE=d:\_______\bin\ms_compiler\inc\crt;%INCLUDE%

cd ..\..\0\dropper\shellcodes\std_sc\code

cl.exe @cl_x32.rsp main.c
link.exe @link_x32.rsp

exit