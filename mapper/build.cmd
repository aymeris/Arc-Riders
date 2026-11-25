@echo off
rem one-shot build — run from a "x64 Native Tools Command Prompt for VS"
cl /nologo /std:c++17 /W4 /permissive- /EHsc /O2 /DUNICODE /D_UNICODE ^
   /D_CRT_SECURE_NO_WARNINGS ^
   mapper_rt.cpp /link advapi32.lib
