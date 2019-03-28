call d:\_______\bin\ms_compiler\bin\setenv.bat d:\_______\bin\ms_compiler\ fre x64 WIN7 no_oacr
set LIB=d:\_______\bin\ms_compiler\lib\win7\amd64;%LIB%
set INCLUDE=d:\_______\bin\ms_compiler\inc\crt;%INCLUDE%

cd ..\..\0\dropper\shellcodes\dllmem_sc\code

cl.exe @cl_x64.rsp main.c
link.exe @link_x64.rsp

exit