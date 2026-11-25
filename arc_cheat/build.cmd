@echo off
setlocal
where cl >nul 2>&1 || (echo [-] cl.exe not on PATH. Launch "x64 Native Tools Command Prompt for VS" first. & exit /b 1)
cl /nologo /std:c++17 /W3 /O2 /GS- /Gy /Gw /GR- /Gs999999 /DUNICODE /D_UNICODE ^
   /DWIN32_LEAN_AND_MEAN /DNDEBUG main.cpp ^
   /LD /link /NODEFAULTLIB /SUBSYSTEM:WINDOWS /ENTRY:DllMain ^
   kernel32.lib user32.lib gdi32.lib /OUT:arc_cheat.dll
if errorlevel 1 exit /b 1
echo [+] arc_cheat.dll
