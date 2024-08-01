#pragma once
#ifndef __PAK_GET_FILE_TYPE_H__
#define __PAK_GET_FILE_TYPE_H__
#include "pak_defs.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <regex.h>

typedef unsigned char byte;

typedef const byte * (*extMatcher)(const byte* buf, int sz);

typedef struct FileType {
    const char *type;
    extMatcher matchFunc;  // regex_t dfa;
} FileType;

/**
 * Generate a FileType, for internal uses only.
 * @param char* type - file extension.
 * @param char* identifer - file header identifer in string.
 * @see pakGetFileType()
 * @return FileType
 */
#define PAK_GEN_FILE_TYPE(typ) \
    {"." #typ, _##typ##_matcher }

/**
 * Get file extension form a file, returns "" on failure.
 * @param PakFile file - the file to parse.
 * @return char* - pointer to file extension.
 */
const char *pakGetFileType(PakFile file);

#endif // __PAK_GET_FILE_TYPE_H__
