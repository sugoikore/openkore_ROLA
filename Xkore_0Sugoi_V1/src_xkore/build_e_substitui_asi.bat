@echo off

set RAGNAROK_PATH=C:\Gravity\Ragnarok
set MINGW_32_PATH=F:\Openkore\Ferramentas\mingw32\bin

if not exist "%MINGW_32_PATH%" (
    echo [ERROR] MinGW not found at %MINGW_32_PATH%
    echo [INFO] Please download MinGW from: https://github.com/niXman/mingw-builds-binaries/releases/download/15.2.0-rt_v13-rev0/i686-15.2.0-release-win32-dwarf-msvcrt-rt_v13-rev0.7z
    echo [INFO] Extract it and set the MINGW_32_PATH variable in this script to point to the 'bin' directory.
    pause
    exit /b 1
)

set CC=%MINGW_32_PATH%\gcc.exe
set CXX=%MINGW_32_PATH%\g++.exe
set PATH=%MINGW_32_PATH%;%PATH%
set GOOS=windows
set GOARCH=386
set CGO_ENABLED=1

if exist xkore1.asi del xkore1.asi
if exist xkore1.h del xkore1.h

if not exist go.mod (
    echo module cs>go.mod
    echo.>>go.mod
    echo go 1.25.0>>go.mod
    echo.>>go.mod
    echo require golang.org/x/sys v0.35.0>>go.mod
)

go mod tidy

go build -buildmode=c-shared -o xkore1.dll main.go

if exist xkore1.dll ren xkore1.dll xkore1.asi
if exist xkore1.h del xkore1.h

if exist xkore1.asi (
    copy xkore1.asi %RAGNAROK_PATH%
    echo [OK] xkore1.asi successfully moved to %RAGNAROK_PATH%.
) else (
    echo [ERROR] xkore1.asi does not exist.
)