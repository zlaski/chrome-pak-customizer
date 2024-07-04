@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "EVENT=%1"

if /i "%EVENT%" == "PreCleanStep" (
    echo PreCleanStep
    exit /b 0
)

if /i "%EVENT%" == "PreBuildEvent" (
    echo PreBuildEvent
    exit /b 0
)

if /i "%EVENT%" == "PreLinkEvent" (
    echo PreLinkEvent
    exit /b 0
)

if /i "%EVENT%" == "PostBuildEvent" (
    echo PostBuildEvent

    set O=%OutDir%
	set N=%OutDir%\%TargetFileName%

	copy /y "!N!" "!O!\pak-tool.exe"
	del /f "!N!"

    exit /b 0
)

if /i "%EVENT%" == "CustomBuildStep" (
    echo CustomBuildStep
    exit /b 0
)

if /i "%EVENT%" == "TestingStep" (
    echo TestingStep
    exit /b 0
)

echo ************** INVALID BUILD EVENT: %EVENT% ********************
exit /b 3
