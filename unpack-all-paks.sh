#!/bin/bash -x
EXE="$PWD/.install/Win32-Debug/bin/pak-tool"

rm -rf "$TMP/shipped-paks" || exit 11
rm -rf "$TMP/built-paks" || exit 12

pushd 'C:\Program Files\BraveSoftware\Brave-Browser'
find -type f -name *.pak | while read PAK; do
    "$EXE" --force --extract "$PAK" "$TMP/shipped-paks/$PAK"
    if [ $? -gt 0 ]; then
        mkdir -p `dirname "$TMP/shipped-paks/$PAK"`
        cp -P "$PAK" "$TMP/shipped-paks/$PAK"
    fi
done
popd

pushd 'D:\dev\git\zlaski\brave-browser'
find -type f -name *.pak | while read PAK; do
    "$EXE" --force --extract "$PAK" "$TMP/built-paks/$PAK"
    if [ $? -gt 0 ]; then
        mkdir -p `dirname "$TMP/built-paks/$PAK"`
        cp -P "$PAK" "$TMP/built-paks/$PAK"
    fi
done
popd
