set "INPUT=%~1"
set "INP=%~dpn1"

for %%e in ( 7z xz bzip2 bz2 gzip tar tgz zip vim bz br apfs ar arj cab chm cpio cramfs dmg ext fat gpt hfs ihex iso lzh lzma mbr msi nsis ntfs qcow2 rar rpm squashfs udf uefi vdi vhd vhdx vmdk xar z ) do (
    copy /y "%INPUT%" "%INP%.%%e"
    7z l "%INP%.%%e"
)

