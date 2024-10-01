#include "pak_pack.h"

#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

#define BUF_COUNT 4

static char _strA[BUF_COUNT][PATH_MAX + 1];
static int _strAidx = 0;

static_assert(sizeof(_strA[0]) == PATH_MAX + 1, "wrong idx ordering");

static const char *str(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char* strAdata = _strA[_strAidx];
    vsnprintf(strAdata, PATH_MAX, fmt, args);
    _strAidx = (++_strAidx % BUF_COUNT);
    return strAdata;
}

static char *f_rd(const char* name, int *len) {
    FILE* t = fopen(name, "rb");
    if (!t) {
        return NULL;
    }
    struct stat s = { 0 };
    if (stat(name, &s)) {
        return NULL;
    }
    int trim = *len;
    *len = s.st_size;
    char *buf = (char *)calloc(1, *len + 1);
    int e = fread(buf, 1, *len, t);
    fclose(t);
    while (trim && *len && (buf[*len - 1] == '\r' || buf[*len - 1] == '\n')) {
        buf[--*len] = 0;
    }
    return buf;
}

static int f_wr(const char* name, const char* buf, int len) {
    FILE* t = fopen(name, "wb");
    int e = fwrite(buf, 1, len, t);
    fclose(t);

    return (e == len ? 1 : 0);
}

static int run(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    char cmdBuf[PATH_MAX * 2 + 1];
    vsnprintf(cmdBuf, PATH_MAX * 2, fmt, args);
    //printf("run: %s\n", cmdBuf);
    return system(cmdBuf);
}

char* winified(const char* path) {
    int rc = run("cygpath -w \"%s\" >\"%s\"", path, tmpFileName);
    rc = 1; // activate trim inside f_rd
    char *res =f_rd(tmpFileName, &rc);
    return res;
}

bool pakUnpack(uint8_t *buffer, char *outputPath) {
    MyPakHeader myHeader;
    if (!pakParseHeader(buffer, &myHeader)) {
        return false;
    }
    PakFile *files = pakGetFiles(buffer);
    if (files == NULL) {
        return false;
    }

    char fileNameBuf[FILENAME_MAX] = { 0 };
    char pathBuf[PATH_MAX + 2] = { 0 };

#ifdef _WIN32
    if (!CreateDirectoryA(outputPath, NULL)) {
        free(files);
        return false;
    }
#else
    mkdir(outputPath, 0777);
#endif
    char *pakIndexStr = calloc(PAK_BUFFER_BLOCK_SIZE, sizeof(char));
    if (pakIndexStr == NULL) {
        free(files);
        return false;
    }
    uint32_t offset = 0;
    uint32_t length = PAK_BUFFER_BLOCK_SIZE;
    offset +=
        sprintf(pakIndexStr + offset, PAK_INDEX_GLOBAL_TAG "\r\nversion=%u\r\n",
                myHeader.version);
    offset += sprintf(pakIndexStr + offset,
                      "encoding=%u\r\n\r\n" PAK_INDEX_RES_TAG "\r\n",
                      myHeader.encoding);
    for (uint32_t i = 0; i < myHeader.resource_count; i++) {
        sprintf(fileNameBuf, "%u%s", files[i].id, pakGetFileType(files[i]));
        offset += sprintf(pakIndexStr + offset, "%u=%s\r\n", files[i].id,
                          fileNameBuf);
        if (length - offset < PAK_BUFFER_MIN_FREE_SIZE) {
            pakIndexStr = realloc(pakIndexStr, length + PAK_BUFFER_BLOCK_SIZE);
            length += PAK_BUFFER_BLOCK_SIZE;
        }
        sprintf(pathBuf, "%s/%s", outputPath, fileNameBuf);
        writeFile(pathBuf, files[i]);
    }
    PakAlias *aliasBuf = NULL;
    if (myHeader.alias_count > 0) {
        offset +=
            sprintf(pakIndexStr + offset, "\r\n" PAK_INDEX_ALIAS_TAG "\r\n");
        aliasBuf = (PakAlias *)(buffer + myHeader.size +
                                (myHeader.resource_count + 1) * PAK_RESOURCE_SIZE);
    }
    for (unsigned int i = 0; i < myHeader.alias_count; i++) {
        offset += sprintf(pakIndexStr + offset, "%u=%u\r\n",
                          aliasBuf->resource_id, aliasBuf->entry_index);
        aliasBuf++;
        if (length - offset < PAK_BUFFER_MIN_FREE_SIZE) {
            pakIndexStr = realloc(pakIndexStr, length + PAK_BUFFER_BLOCK_SIZE);
            length += PAK_BUFFER_BLOCK_SIZE;
        }
    }
    PakFile pakIndexBuf;
    // puts(pakIndexStr);
    pakIndexBuf.buffer = pakIndexStr;
    pakIndexBuf.size = offset;
    sprintf(pathBuf, "%s/pak_index.ini", outputPath);
    writeFile(pathBuf, pakIndexBuf);
    freeFile(pakIndexBuf);
    free(files);
    return true;
}

uint32_t countChar(const char *string, uint32_t length, char toCount) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < length; i++) {
        if (string[i] == toCount)
            count++;
    }
    return count;
}

static char _s[12];

static void th_sep(unsigned val) {
    if (val < 1000) {
        sprintf(_s + strlen(_s), "%d", val);
    } else {
        th_sep(val / 1000);
        sprintf(_s + strlen(_s), ",%03d", val % 1000);
    }
}

const char* thousands_separated(unsigned val) {
    memset(_s, 0, sizeof(_s));
    th_sep(val);
    return _s;
}

#define SZ_SZ "%11s"

bool pakList(PakFile file, const char *destDirectory) {
    MyPakHeader myHeader;
    int rc;
    uint8_t* buffer = file.buffer;
    if (!pakParseHeader(buffer, &myHeader)) {
        return false;
    }
    PakFile* files = pakGetFiles(buffer);
    if (files == NULL) {
        return false;
    }

    struct stat dirStat = { 0 };
    if (!stat(destDirectory, &dirStat)) {
        if (!forceOverwrite) {
            printf("Error: \'%s\' already exists\n", destDirectory);
            return false;
        }
        rc = run("rmdir /s /q \"%s\"", destDirectory);
        if (rc) {
            printf("Error: unable to remove \'%s\'\n", destDirectory);
            return FALSE;
        }
    }

    if (destDirectory) {
        rc = run("mkdir \"%s\"", destDirectory);
        if (rc) {
            printf("Error: cannot create \'%s\' directory\n", destDirectory);
            return false;
        }
    } else {
        destDirectory = ".";
    }

    char fileNameBuf[FILENAME_MAX + 1], buf2[FILENAME_MAX + 1];
    char pathBuf[PATH_MAX + 2] = { 0 };

    const char *outerExt;

    uint32_t total_octets = 0;
    for (uint32_t i = 0; i < myHeader.resource_count; i++) {
        outerExt = pakGetFileType(files[i]);
        if (!strcmp(outerExt, ".br")) {
            f_wr(tmpFileName, files[i].buffer + 8, files[i].size - 8);
        } else {
            f_wr(tmpFileName, files[i].buffer, files[i].size);
        }
        snprintf(fileNameBuf, FILENAME_MAX, "%s\\%05u%s", destDirectory, files[i].id, outerExt);

        if (!strcmp(outerExt, ".gz") || !strcmp(outerExt, ".br")) {
            rc = run("mkdir \"%s\"", fileNameBuf);
            if (!strcmp(outerExt, ".gz")) {
                rc = run("move /y \"%s\" \"%s.gz\" >nul", tmpFileName, tmpFileName);
                rc = run("gzip -d \"%s.gz\"", tmpFileName);
            } else {
                rc = run("move /y \"%s\" \"%s.br\" >nul", tmpFileName, tmpFileName);
                rc = run("brotli -d -f -o \"%s\" \"%s.br\"", tmpFileName, tmpFileName);
            }

            if (rc) {
                printf("Error: cannot decompress \'%s\'\n", fileNameBuf);
                return false;
            }

            PakFile extrFile = { 0 };
            extrFile.buffer = f_rd(tmpFileName, &extrFile.size);
            const char* innerExt = pakGetFileType(extrFile);
            rc = run("move /y \"%s\" \"%s\\%05u%s\" >nul", tmpFileName, fileNameBuf, files[i].id, innerExt);
            printf("%12s  %05u%s/%05u%s\n", thousands_separated(extrFile.size), files[i].id, outerExt, files[i].id, innerExt);
            total_octets += extrFile.size;
            free(extrFile.buffer);
        }
        else {
            rc = run("move /y \"%s\" \"%s\" >nul", tmpFileName, fileNameBuf);
            printf("%12s  %05u%s\n", thousands_separated(files[i].size), files[i].id, outerExt);
            total_octets += files[i].size;
        }

    }

    PakAlias* aliasBuf = NULL;
    if (myHeader.alias_count > 0) {
        printf("\n");
        aliasBuf = (PakAlias*)(buffer + myHeader.size +
            (myHeader.resource_count + 1) * PAK_RESOURCE_SIZE);
    }
    for (unsigned int i = 0; i < myHeader.alias_count; i++) {
        const char* aliasExt = pakGetFileType(files[aliasBuf->entry_index]);
        unsigned short targResourceId = files[aliasBuf->entry_index].id;

        if (!strcmp(aliasExt, ".gz") || !strcmp(aliasExt, ".br")) {
            run("mklink /d \"%s\\%05u%s\" \"%05u%s\" >nul", destDirectory, aliasBuf->resource_id, aliasExt, targResourceId, aliasExt);
        } else {
            run("mklink \"%s\\%05u%s\" \"%05u%s\" >nul", destDirectory, aliasBuf->resource_id, aliasExt, targResourceId, aliasExt);
        }
        printf("%12s  %05u%s --> %05u%s\n", " ", aliasBuf->resource_id, aliasExt, targResourceId, aliasExt);
        aliasBuf++;
    }
    printf("\n");
    printf("%12s  Input PAK file size\n", thousands_separated(file.size));
    printf("%12s  Unpacked octets total\n\n", thousands_separated(total_octets));

    free(files);
    return true;
}

PakFile pakPack(PakFile pakIndex, char *path) { // TODO
    MyPakHeader myHeader = { 0 };
    char *pakIndexBuf = pakIndex.buffer;

    PakFile pakFile = NULL_File;
    PakFile *resFiles = NULL;
    PakAlias *pakAlias = NULL;

    uint32_t count = 0;
    uint32_t offset = sizeof(PAK_INDEX_GLOBAL_TAG) - 1;
    sscanf(pakIndexBuf + offset, " version=%u%n", &myHeader.version, &count);
    if (count == 0) {
        goto PAK_PACK_END;
    }
    offset += count;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
    sscanf(pakIndexBuf + offset, " encoding=%hhu%n", &myHeader.encoding,
           &count);
#pragma GCC diagnostic pop
    //	printf("version=%u\nencoding=%u\n", myHeader.version,
    // myHeader.encoding);
    if (myHeader.version == 5) {
        myHeader.size = PAK_HEADER_SIZE_V5;
    } else if (myHeader.version == 4) {
        myHeader.size = PAK_HEADER_SIZE_V4;
    } else {
        puts(PAK_ERROR_UNKNOWN_VER);
        goto PAK_PACK_END;
    }
    char *pakIndexEnd = pakIndexBuf + pakIndex.size - 1;
    char *pakEntryIndex =
        strstr(pakIndexBuf, PAK_INDEX_RES_TAG) + sizeof(PAK_INDEX_RES_TAG) - 1;
    char *pakAliasIndex = strstr(pakIndexBuf, PAK_INDEX_ALIAS_TAG);
    if (myHeader.version == 4 || pakAliasIndex == NULL) {
        myHeader.alias_count = 0;
        pakAliasIndex = pakIndexEnd;
    } else {
        pakAliasIndex += sizeof(PAK_INDEX_ALIAS_TAG) - 1;
        myHeader.alias_count =
                (uint16_t) countChar(pakAliasIndex, pakIndexEnd - pakAliasIndex, '=');
    }
    myHeader.resource_count =
        countChar(pakEntryIndex, pakAliasIndex - pakEntryIndex, '=');

    // printf("resource_count=%u\nalias_count=%u\n", myHeader.resource_count,
    // myHeader.alias_count);

    char fileNameBuf[FILENAME_MAX] = { 0 };
    char pathBuf[PATH_MAX] = { 0 };
    resFiles = calloc(myHeader.resource_count, sizeof(PakFile));
    if (resFiles == NULL) {
        goto PAK_PACK_END;
    }

    offset = 0;
    for (uint32_t i = 0; i < myHeader.resource_count; i++) {
        uint32_t id = 0;
        sscanf(pakEntryIndex + offset, " %u=%s%n ", &id, fileNameBuf, &count);
        if (count == 0 || sprintf(pathBuf, "%s%s", path, fileNameBuf) == 0) {
            puts(PAK_ERROR_BROKEN_INDEX);
            myHeader.resource_count = i;
            goto PAK_PACK_END;
        }
        offset += count;
        resFiles[i] = readFile(pathBuf);
        if (resFiles[i].size == 0 || resFiles[i].buffer == NULL) {
            puts(PAK_ERROR_BROKEN_INDEX);
            myHeader.resource_count = i;
            goto PAK_PACK_END;
        }
        resFiles[i].id = (uint16_t) id;
        //	printf("id=%u\tfile_name=%s\tpath=%s\tsize=%u\n",id,
        // fileNameBuf, pathBuf, resFiles[i].size);
    }
    if (myHeader.alias_count > 0) {
        offset = 0;
        pakAlias = calloc(myHeader.alias_count, sizeof(PakAlias));
        if (pakAlias == NULL) {
            goto PAK_PACK_END;
        }
        for (uint32_t i = 0; i < myHeader.alias_count; i++) {
            sscanf(pakAliasIndex + offset, " %hu=%hu%n ",
                   &pakAlias[i].resource_id, &pakAlias[i].entry_index, &count);
            if (count == 0) {
                puts(PAK_ERROR_BROKEN_INDEX);
                goto PAK_PACK_END;
            }
            offset += count;
            //	printf("resource_id=%hu\tentry_index=%hu\n",pakAlias[i].resource_id,
            // pakAlias[i].entry_index);
        }
    }
    pakFile = pakPackFiles(&myHeader, resFiles, pakAlias);
    printf("\nresource_count=%u\nalias_count=%u\n", myHeader.resource_count,
           myHeader.alias_count);
    printf("version=%u\nencoding=%u\n", myHeader.version, myHeader.encoding);
    printf("\npak size: %u\n", pakFile.size);
PAK_PACK_END:
    if (resFiles != NULL) {
        for (uint32_t i = 0; i < myHeader.resource_count; i++) {
            if (resFiles[i].buffer != NULL)
                free(resFiles[i].buffer);
        }
        free(resFiles);
    }
    if (pakAlias != NULL)
        free(pakAlias);
    return pakFile;
}
