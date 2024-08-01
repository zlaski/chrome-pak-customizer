@echo off

pushd "%TEMP%\shipped-paks"
for /f %%U in ('dir /a-d /a-l /s /b *.unknown') do call file-header /s "%%U"
popd

pushd "%TEMP%\built-paks"
for /f %%U in ('dir /a-d /a-l /s /b *.unknown') do call file-header /s "%%U"
popd

:: cygwin "%~dpn0.sh"