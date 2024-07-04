#include "pak_get_file_type.h"

static const FileType FILE_TYPES[] = {
    PAK_GEN_FILE_TYPE(".png", "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"),
    PAK_GEN_FILE_TYPE(".html", "<!doctype html>"),
    PAK_GEN_FILE_TYPE(".html", "<!DOCTYPE html>"),
    PAK_GEN_FILE_TYPE(".html", "<html>"),
    PAK_GEN_FILE_TYPE(".html", "<!--"),
    PAK_GEN_FILE_TYPE(".html", "<link"),
    PAK_GEN_FILE_TYPE(".svg", "<svg "),
    PAK_GEN_FILE_TYPE(".js", "// "),
    PAK_GEN_FILE_TYPE(".js", "(function"),
    PAK_GEN_FILE_TYPE(".css", "/*"),
    PAK_GEN_FILE_TYPE(".json", "{"),
    PAK_GEN_FILE_TYPE(".gz", "\x1f\x8b"),
    PAK_GEN_FILE_TYPE(".webp", "RIFF\xFF\xFF\xFF\xFFWEBP"),
    PAK_GEN_FILE_TYPE(".ico", "\0\0\1\0"),
    PAK_GEN_FILE_TYPE(".cur", "\0\0\2\0"),
    PAK_GEN_FILE_TYPE(".gif", "GIF89a"),
    PAK_GEN_FILE_TYPE(".jpg", "\xFF\xD8\xFF\xFF\xFF\xFFJFIF"),
    PAK_GEN_FILE_TYPE(".wasm", "\0asm"),
    PAK_GEN_FILE_TYPE(".woff", "wOFF"),
    PAK_GEN_FILE_TYPE(".woff2", "wOF2"),
    PAK_GEN_FILE_TYPE(NULL, "")
};

static int header_match(const char* header, const char* magic, int len) {
    for (; len--; ++header, ++magic) {
        if ((*magic != -1) && (*header != *magic)) {
            return 0;
        }
    }
    return 1;
}

char* pakGetFileType(PakFile file) {
    for (const FileType* ft = FILE_TYPES; ft->type; ++ft) {
        if (file.size >= ft->size
            && header_match(file.buffer, ft->identifer, ft->size)) {
            return ft->type;
        }
    }
    return "";
}
