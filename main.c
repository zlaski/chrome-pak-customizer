#if defined(_WIN32) && defined(_LGPL)
#include "main.h"
#endif
#include "pak_defs.h"
#include "pak_file.h"
#include "pak_file_io.h"
#include "pak_get_file_type.h"
#include "pak_header.h"
#include "pak_pack.h"

#define HELP_TEXT                                                   \
    "Pack/Unpack Chrome/Brave PAK files.\n\n"                       \
    "%s --list <pak_file>\n"                                        \
    "    List contents of PAK file\n"                               \
    "%s --unpack <pak_file> <destination_path>\n"                   \
    "    Unpack contents of PAK file into destination folder\n"     \
    "%s --pack <pak_index_file> <destination_pak_file>\n"           \
    "    Build a PAK file using the index provided\n\n"             \
    "Note: existing destination files would be overwritten\n"

bool forceOverwrite = false;

void printHelp() {
    // get self path
    char selfName[PATH_MAX];
#ifdef _WIN32
    GetModuleFileName(NULL, selfName, PATH_MAX);
    // get file name from path
    const char *ptr = strrchr(selfName, '\\');
#else
    int ret = readlink("/proc/self/exe", selfName, sizeof(selfName) - 1);
    if (ret == -1)
        strcpy(selfName, "pak");
    else
        selfName[ret] = 0;
    // get file name from path
    const char *ptr = strrchr(selfName, '/');
#endif

    if (ptr != NULL)
        strcpy(selfName, ptr + 1);

    printf(HELP_TEXT, selfName, selfName, selfName);
}

int pakUnpackPath(char *pakFilePath, char *outputPath) {
    PakFile pakFile = readFile(pakFilePath);
    if (pakFile.size == 0 || pakFile.buffer == NULL) {
        printf("Error: cannot read pak file %s", pakFilePath);
        return 1;
    }
    MyPakHeader myHeader;
    if (!pakParseHeader(pakFile.buffer, &myHeader)) {
        return 2;
    }

    if (!pakCheckFormat(pakFile.buffer, pakFile.size)) {
        return 3;
    }

    if (!pakUnpack(pakFile.buffer, outputPath)) {
        freeFile(pakFile);
        return 4;
    }
    freeFile(pakFile);
    return 0;
}

int pakListPath(char* pakFilePath, char *destDirectory) {
    PakFile pakFile = readFile(pakFilePath);
    if (pakFile.size == 0 || pakFile.buffer == NULL) {
        printf("Error: cannot read pak file %s", pakFilePath);
        return 1;
    }
    MyPakHeader myHeader;
    if (!pakParseHeader(pakFile.buffer, &myHeader)) {
        return 2;
    }

    if (!pakCheckFormat(pakFile.buffer, pakFile.size)) {
        return 3;
    }

    printf("Contents of %s\n\n", pakFilePath);
    if (!pakList(pakFile, destDirectory)) {
        freeFile(pakFile);
        return 4;
    }
    freeFile(pakFile);
    return 0;
}

int pakPackIndexFile(char *indexPath, char *outputFilePath) {
    int returnCode = 0;
    PakFile pakPackedFile = NULL_File;
    PakFile pakIndexFile = NULL_File;
    char *filesPath = NULL;
    bool freeFilesPath = false;
    char *outputFilePath2 = NULL;
    char *index = strrchr(indexPath, '\\');
    if (index == NULL) {
        index = strrchr(indexPath, '/');
    }
    if (index != NULL && index > indexPath) {
        filesPath = calloc(index - indexPath + 2, sizeof(char));
        if (filesPath == NULL) {
            returnCode = 5;
            goto PAK_PACK_INDEX_END;
        }
        strncpy(filesPath, indexPath, index - indexPath + 1);
        freeFilesPath = true;
    } else {
        filesPath = "";
    }

    pakIndexFile = readFile(indexPath);
    if (pakIndexFile.size == 0 || pakIndexFile.buffer == NULL) {
        printf("Error: cannot read file %s", indexPath);
        returnCode = 6;
        goto PAK_PACK_INDEX_END;
    }

    // workaround outputFilePath="" after pakPack()
    outputFilePath2 = calloc(strlen(outputFilePath) + 1, sizeof(char));
    if (outputFilePath2 == NULL) {
        returnCode = 7;
        goto PAK_PACK_INDEX_END;
    }
    strcpy(outputFilePath2, outputFilePath);

    pakPackedFile = pakPack(pakIndexFile, filesPath);
    if (pakPackedFile.buffer == NULL) {
        returnCode = 8;
        goto PAK_PACK_INDEX_END;
    }
    if (!writeFile(outputFilePath2, pakPackedFile)) {
        printf("Error: cannot write to %s", outputFilePath2);
        returnCode = 9;
        goto PAK_PACK_INDEX_END;
    }

PAK_PACK_INDEX_END:
    if (pakIndexFile.buffer != NULL)
        freeFile(pakIndexFile);
    if (pakPackedFile.buffer != NULL)
        freeFile(pakPackedFile);
    if (outputFilePath2 != NULL)
        free(outputFilePath2);
    if (freeFilesPath && filesPath != NULL)
        free(filesPath);
    return returnCode;
}

char tempDir[PATH_MAX + 1];
char tmpFileName[PATH_MAX + 16];

static void setUpTempPath(void) {
    char* t = getenv("TMPDIR");
    if (!t) {
        t = getenv("TMP");
    }
    if (!t) {
        t = getenv("TEMP");
    }
    if (t) {
        strncpy(tempDir, t, PATH_MAX);
    }
    else {
#ifdef _WIN32
        GetTempPath(PATH_MAX, tempDir);
#else
        strcpy(tempDir, "/tmp");
#endif
    }
    strcat(tempDir, (tempDir[1] == ':' ? "\\" : "/"));
    strcpy(tmpFileName, tempDir);
    strcat(tmpFileName, "payload.tmp");

}

#define PAK_FLAGS_HELP 0
#define PAK_FLAGS_UNPACK 1
#define PAK_FLAGS_PACK 2
#define PAK_FLAGS_LIST 3

int main(int argc, char *argv[]) {
    uint32_t flags = 0;
    bool process = false;
    char path1[PATH_MAX + 1] = { 0 };
    char path2[PATH_MAX + 1] = { 0 };

    int i = 1;
    if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--force")) {
        forceOverwrite = TRUE;
        i = 2;
    }
    for (; i < argc; i++) {
        char *arg = argv[i];
        bool isConfig = false;
        if (*arg == '-') {
            arg++;
            isConfig = true;
        }
        if (isConfig) {
            switch (*arg) {
            case 'h':
                flags = PAK_FLAGS_HELP;
                break;
            case 'a':
            case 'p':
                flags = PAK_FLAGS_PACK;
                break;
            case 'u':
            case 'e':
            case 'x':
                flags = PAK_FLAGS_UNPACK;
                break;
            case 'l':
            case 't':
                flags = PAK_FLAGS_LIST;
                break;
            default:
                if (!strcmp(arg, "-help")) {
                    flags = PAK_FLAGS_HELP;
                }
                else if (!strcmp(arg, "-pack")) {
                    flags = PAK_FLAGS_PACK;
                }
                else if (!strcmp(arg, "-unpack") || !strcmp(arg, "-extract")) {
                    flags = PAK_FLAGS_UNPACK;
                }
                else if (!strcmp(arg, "-list")) {
                    flags = PAK_FLAGS_LIST;
                }
            }
        }
        if ((flags == PAK_FLAGS_UNPACK || flags == PAK_FLAGS_PACK) &&
            argc - i > 2) {
            strcpy(path1, argv[i + 1]);
            strcpy(path2, argv[i + 2]);
            process = true;
            break;
        }
        else if (flags == PAK_FLAGS_LIST &&
            argc - i > 1) {
            strcpy(path1, argv[i + 1]);
            strcpy(path2, argv[i + 2]);   // may be NULL
            process = true;
            break;
        }
    }
    if (flags == PAK_FLAGS_HELP || !process) {
        printHelp();
        return 0;
    }
    setUpTempPath();

    char *w;

    if (*path1) {
        w = winified(path1);
        // printf("winified: \"%s\" --> \"%s\"\n", path1, w);
        strncpy(path1, w, MAX_PATH);
        free(w);
    }
    if (*path2) {
        w = winified(path2);
        // printf("winified: \"%s\" --> \"%s\"\n", path2, w);
        strncpy(path2, w, MAX_PATH);
        free(w);
    }

    if (flags == PAK_FLAGS_UNPACK) {
        return pakListPath(path2, path1);
    } else if (flags == PAK_FLAGS_LIST) {
        return pakListPath(path2, path1);
    } else if (flags == PAK_FLAGS_PACK) {
        return pakPackIndexFile(path2, path1);
    }
    return 32;
}
