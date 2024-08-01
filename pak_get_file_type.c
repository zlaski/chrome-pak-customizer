#include "pak_get_file_type.h"

// zip:     50 4B 03 04 0A 00 00 
// zstd:    28 B5 2F FD
// zlib:    78 01 - No Compression / low
// zlib:    78 5E - Fast Compression
// zlib:    78 9C - Default Compression
// zlib:    78 DA - Best Compression

// zlib is sometimes "wrapped" by a gzip header: 1F 8B 08 00 00 00 00 00 00 0B

// FLEVEL:       0       1       2       3
// CINFO :
//    0      08 1D   08 5B   08 99   08 D7
//    1      18 19   18 57   18 95   18 D3
//    2      28 15   28 53   28 91   28 CF
//    3      38 11   38 4F   38 8D   38 CB
//    4      48 0D   48 4B   48 89   48 C7
//    5      58 09   58 47   58 85   58 C3
//    6      68 05   68 43   68 81   68 DE
//    7      78 01   78 5E   78 9C   78 DA

// # no FNAME and FCOMMENT bit implies no file name / comment.That means only binary
// > 3	byte & 0x18 = 0

//byte[] header = new byte[20];
//System.arraycopy(fileBytes, 0, header, 0, Math.min(fileBytes.length, header.length));
//
//int c1 = header[0] & 0xff;
//int c2 = header[1] & 0xff;
//int c3 = header[2] & 0xff;
//int c4 = header[3] & 0xff;
//int c5 = header[4] & 0xff;
//int c6 = header[5] & 0xff;
//int c7 = header[6] & 0xff;
//int c8 = header[7] & 0xff;
//int c9 = header[8] & 0xff;
//int c10 = header[9] & 0xff;
//int c11 = header[10] & 0xff;
//int c12 = header[11] & 0xff;
//int c13 = header[12] & 0xff;
//int c14 = header[13] & 0xff;
//int c15 = header[14] & 0xff;
//int c16 = header[15] & 0xff;
//int c17 = header[16] & 0xff;
//int c18 = header[17] & 0xff;
//int c19 = header[18] & 0xff;
//int c20 = header[19] & 0xff;
//
//if (c1 == 0x00 && c2 == 0x00 && c3 == 0x00)//c4 == 0x20 0x18 0x14
//{
//    if (c5 == 0x66 && c6 == 0x74 && c7 == 0x79 && c8 == 0x70)//ftyp
//    {
//        if (c9 == 0x69 && c10 == 0x73 && c11 == 0x6F && c12 == 0x6D)//isom
//            return "video/mp4";
//
//        if (c9 == 0x4D && c10 == 0x53 && c11 == 0x4E && c12 == 0x56)//MSNV
//            return "video/mp4";
//
//        if (c9 == 0x6D && c10 == 0x70 && c11 == 0x34 && c12 == 0x32)//mp42
//            return "video/mp4";
//
//        if (c9 == 0x4D && c10 == 0x34 && c11 == 0x56 && c12 == 0x20)//M4V
//            return "video/m4v"; //flv-m4v
//
//        if (c9 == 0x71 && c10 == 0x74 && c11 == 0x20 && c12 == 0x20)//qt
//            return "video/mov";
//
//        if (c9 == 0x33 && c10 == 0x67 && c11 == 0x70 && c17 != 0x69 && c18 != 0x73)
//            return "video/3gp";//3GG, 3GP, 3G2
//    }
//
//    if (c5 == 0x6D && c6 == 0x6F && c7 == 0x6F && c8 == 0x76)//MOOV
//    {
//        return "video/mov";
//    }
//}

#define LITLEN(s) (sizeof(s) - 1)
#define STRLIT(l) l, LITLEN(l)
#define _MIN(A, B) ((A) < (B)? (A): (B))

#define MEMMATCH(b, l)        (Accum = ((sz <= (b - buf)) || memcmp    (b, l, _MIN(sz - (b - buf), LITLEN(l))))? NULL: b + LITLEN(l))
#define MEMIMATCH(b, l)       (Accum = ((sz <= (b - buf)) || memcasecmp(b, l, _MIN(sz - (b - buf), LITLEN(l))))? NULL: b + LITLEN(l))
#define MEMSCAN(b, l)         (Accum = ((sz > (b - buf))? memmem    (b, sz - (b - buf), STRLIT(l)): NULL))
#define MEMISCAN(b, l)        (Accum = ((sz > (b - buf))? memcasemem(b, sz - (b - buf), STRLIT(l)): NULL))

static const byte *Accum;

static const byte *_gz_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x1F\x8B\x08")) {
        return Accum;
    }
    return 0;
}

static const byte *_bz2_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "BZh")) {
        return Accum;
    }
    return 0;
}

static const byte* _py_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "#!/usr/bin/env python")) {
        return Accum;
    }
    return 0;
}

static const byte* _mgc_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x1C\x04\x1E\xF1")) {
        return Accum;
    }
    return 0;
}

static const byte* _pch_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "CPCH\x01")) {
        return Accum;
    }
    return 0;
}

static const byte* _sha1_matcher(const byte* buf, int sz) {
    if (sz != 0x28) {
        return 0;
    }
    for (int c = 0; c < sz; ++c) {
        if (!isxdigit(buf[c])) {
            return 0;
        }
    }
    return buf + 0x28;
}

static const byte* _dng_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "II*\x00\x08")) {
        return Accum;
    }
    return 0;
}

static const byte* _br_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x1E\x9B")) {
        return Accum;
    }
    return 0;
}

static const byte *_bc_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "BC\xC0\xDE")) {
        return Accum;
    }
    return 0;
}

static const byte* _flv_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x0B\x77\x01\xB2")) {
        return Accum;
    }
    return 0;
}

static const byte* _h263_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x0B\x77\x01\xB2")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\x00\x00\x80\x02\x0C")) {
        return Accum;
    }
    return 0;
}

static const byte *_bdic_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "BDic\x02")) {
        return Accum;
    }
    return 0;
}

static const byte* _mkv_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x1A\x45\xDF\xA3\x01")) {
        return Accum;
    }
    return 0;
}

static const byte *_vp9_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "DKIF") && MEMMATCH(buf + 8, "VP9")) {
        return Accum;
    }
    return 0;
}

static const byte *_vp8_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "DKIF") && MEMMATCH(buf + 8, "VP8")) {
        return Accum;
    }
    return 0;
}

static const byte *_rtp_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "#!rtpplay")) {
        return Accum;
    }
    return 0;
}

static const byte *_bzip_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "BZ0")) {
        return Accum;
    }
    return 0;
}

static const byte *_tfl_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf + 4, "TFL")) {
        return Accum;
    }
    return 0;
}

static const byte *_pyd_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "MZ\x90") && MEMISCAN(Accum, "\0.\0p\0y\0d\0\0\0")) {
        return Accum;
    }
    return 0;
}

static const byte *_node_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "MZ\x90") && MEMISCAN(Accum, "?AV_Node_base")) {
        return Accum;
    }
    return 0;
}

static const byte *_exe_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "MZ\x90")) {
        return Accum;
    }
    return 0;
}

static const byte *_windb_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "MZ\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_dll_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "MZ\x78")) {
        return Accum;
    }
    return 0;
}

static const byte *_eot_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "NG\x01\x00")) {
        return Accum;
    }
    if (MEMMATCH(buf, "7P\x00\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _icc_matcher(const byte* buf, int sz) {
    if (!buf[0] && MEMMATCH(buf + 4, "lcms\x02")) {
        return Accum;
    }
    return 0;
}

static const byte *_a_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "!<arch>") && buf[24] == '0') {
        return buf + 25;
    }
    return 0;
}

static const byte *_lib_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "!<arch>") && buf[24] == '-') {
        return buf + 25;
    }
    if (MEMMATCH(buf, "!<thin>")) {
        return Accum;
    }
    return 0;
}

static const byte *_p12_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x30\x82\x09\x90\x02\x01\x03\x30")) {
        return Accum;
    }
    return 0;
}

static const byte *_spl_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "VIMspell")) {
        return Accum;
    }
    return 0;
}

static const byte *_sug_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "VIMsug")) {
        return Accum;
    }
    return 0;
}

static const byte *_lz_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "LZIP")) {
        return Accum;
    }
    return 0;
}

static const byte *_pdb_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "Microsoft C/C++ MSF")) {
        return Accum;
    }
    return 0;
}

static const byte* _ninja_matcher(const byte* buf, int sz) {
    if (MEMSCAN(buf, "\x0Abuild ")) {
        return Accum;
    }
    return 0;
}

static const byte *_msi_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")) {
        return Accum;
    }
    return 0;
}

static const byte *_lzh_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf + 2, "-lh")) {
        return Accum;
    }
    return 0;
}

static const byte *_pyc_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xA7\x0D\x0D\x0A")) {
        return Accum;
    }
    return 0;
}

static const byte *_lzo_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x89\x4c\x5a\x4f")) {
        return Accum;
    }
    return 0;
}

static const byte* _sxg_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "sxg1-b")) {
        return Accum;
    }
    return 0;
}

static const byte *_mp4_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00")) {
        if (MEMMATCH(buf + 4, "ftypiso")) {
            return Accum;
        }
        if (MEMMATCH(buf + 4, "ftypMSNV")) {
            return Accum;
        }
        if (MEMMATCH(buf + 4, "ftypmp42")) {
            return Accum;
        }
    }
    return 0;
}

static const byte* _avif_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00")) {
        if (MEMMATCH(buf + 4, "ftypavif")) {
            return Accum;
        }
    }
    return 0;
}

static const byte* _m4v_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00")) {
        if (MEMMATCH(buf + 4, "ftypM4V ")) {
            return Accum;
        }
    }
    return 0;
}

static const byte* _m4a_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00")) {
        if (MEMMATCH(buf + 4, "ftypM4A ")) {
            return Accum;
        }
    }
    return 0;
}

static const byte* _3gp_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00")) {
        if (MEMMATCH(buf + 4, "ftyp3gp") && Accum[0] != 'i' && Accum[1] != 's') {
            return Accum + 2;
        }
    }
    return 0;
}

static const byte* _mov_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00")) {
        if (MEMMATCH(buf + 4, "ftypqt  ")) {
            return Accum;
        }
        if (MEMMATCH(buf + 4, "moov")) {
            return Accum;
        }
        if (MEMMATCH(buf + 4, "free")) {
            return Accum;
        }
        if (MEMMATCH(buf + 4, "mdat")) {
            return Accum;
        }
        if (MEMMATCH(buf + 4, "wide")) {
            return Accum;
        }
    }
    return 0;
}

static const byte *_xz_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xFD\x37\x7A\x58\x5A\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _icu_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x20\x00\xDA\x27\x14\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_7z_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "7z\274\257\047\034")) {
        return Accum;
    }
    return 0;
}

static const byte* _h264_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00\x01\x06")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\x00\x00\x00\x01\x67")) {
        return Accum;
    }
    return 0;
}

static const byte *_Z_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x1F\x9D")) {
        return Accum;
    }
    return 0;
}

static const byte* _iso_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "CD001")) {
        return Accum;
    }
    return 0;
}

static const byte* _chm_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "ITSF")) {
        return Accum;
    }
    return 0;
}

static const byte* _hqx_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf + 1, "This file must be converted with BinHex")) {
        return Accum;
    }
    return 0;
}

static const byte* _arc_matcher(const byte* buf, int sz) {
    if (sz >= 2 && buf[0] == 0x1A && (buf[1] == 0x02 || buf[1] == 0x03 || buf[1] == 0x04 || buf[1] == 0x08 || buf[1] == 0x09)) {
        return buf + 2;
    }
    if (MEMMATCH(buf, "ArC\x01")) {
        return Accum;
    }
    return 0;
}

static const byte* _hlp_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf + 7, "\x00\x00\xFF\xFF\xFF\xFF")) {
        return Accum;
    }
    if (MEMMATCH(buf, "LN\x02\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _gid_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "?_\x03\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _whl_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "PK\x03\x04") && MEMSCAN(Accum, "/WHEELPK\1")) {
        return Accum;
    }
    return 0;
}

static const byte *_zip_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "PK\x03\x04")) {
        return Accum;
    }
    if (MEMMATCH(buf, "PK\x07\x08")) {
        return Accum;
    }
    if (MEMMATCH(buf, "PK\x05\x06")) {
        return Accum;
    }
    if (MEMMATCH(buf, "PK\x06\x06")) {
        return Accum;
    }
    return 0;
}

static const byte *_jar_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "PK\x03\x04") && MEMSCAN(buf + 8, "META-INF/MANIFEST.MF")) {
        return Accum;
    }
    return 0;
}

static const byte *_aar_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "PK\x03\x04") && MEMSCAN(buf + 8, "AndroidManifest.xml")) {
        return Accum;
    }
    return 0;
}

static const byte *_tar_matcher(const byte* buf, int sz) {
    // this one is a bit bizarre...
    if (MEMMATCH(buf + 0x100, "austar  ")) {
        return Accum;
    }
    return 0;
}

static const byte *_skp_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "skiapict\x0F\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_so_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x7F\x45\x4C\x46") && buf[0x10] == 3 && buf[0x11] == 0) {
        return buf + 12;
    }
    return 0;
}

static const byte *_elf_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x7F\x45\x4C\x46")) {
        return Accum;
    }
    return 0;
}

static const byte *_zstd_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x28\xB5\x2F\xFD")) {
        return Accum;
    }
    return 0;
}

static const byte *_tiff_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x49\x49\x2A\x00")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\x49\x20\x49")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\x4D\x4D\x00\x2A")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\x4D\x4D\x00\x2B")) {
        return Accum;
    }
    return 0;
}

static const byte *_rar_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x52\x61\x72\x21\x1A\x07")) {
        return Accum;
    }
    return 0;
}

static const byte* _arj_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x60\xEA")) {
        return Accum;
    }
    return 0;
}

static const byte *_obj_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x64\x86")) {
        return Accum;
    }
    return 0;
}

static const byte* _sit_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "SIT!\x00")) {
        return Accum;
    }
    if (MEMMATCH(buf, "StuffIt (c)")) {
        return Accum;
    }
    return 0;
}

static const byte* _zoo_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "ZOO ")) {
        return Accum;
}
    if (MEMMATCH(buf, "StuffIt (c)")) {
        return Accum;
    }
    return 0;
}

static const byte *_zz_matcher(const byte* buf, int sz) {
#if 0
    unsigned short chk = ((buf[0] << 8) | buf[1]);
    if (chk % 31) {
        return 0;
    }
#endif
    if (MEMMATCH(buf, "\x78\x01")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\x78\x5E")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\x78\x9C")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\x78\xDA")) {
        return Accum;
    }
    return 0;
}


static const byte *_png_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x89PNG")) {
        return Accum;
    }
    return 0;
}

static const byte* _descriptor_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x0A\xA7\x0B\x0A")) {
        return Accum;
    }
    return 0;
}

static const byte* _class_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xCA\xFE\xBA\xBE")) {
        return Accum;
    }
    return 0;
}

static const byte *_xml_matcher(const byte* buf, int sz) {
    if (MEMIMATCH(buf, "<xml")) {
        return Accum;
    }
    if (MEMIMATCH(buf, "<?xml")) {
        return Accum;
    }
    return 0;
}

static const byte *_html_matcher(const byte* buf, int sz) {
    if (MEMIMATCH(buf, "<html")) {
        return Accum;
    }
    if (MEMIMATCH(buf, "<!doctype html")) {
        return Accum;
    }
    if (MEMIMATCH(buf, "<head>")) {
        return Accum;
    }
    if (MEMIMATCH(buf, "<!--")) {
        return Accum;
    }
    if (MEMISCAN(buf, "<a href") && MEMISCAN(Accum + 1, "</a>")) {
        return Accum;
    }
    return 0;
}

static const byte *_svg_matcher(const byte* buf, int sz) {
    const byte* b = buf;
    if(_xml_matcher(buf, sz)) {
        b = Accum;
    }

    if (MEMISCAN(b, "<svg")) {
        return Accum;
    }
    return 0;
}

static const byte *_xtb_matcher(const byte* buf, int sz) {

    if (buf[0] == '{' && MEMSCAN(buf + 1, ",plural,") - buf < 32) {
        return Accum;
    }

    const byte* b = buf;
    if (_xml_matcher(buf, sz)) {
        b = Accum;
    }

    if (MEMISCAN(b, "<!DOCTYPE translationbundle>")) {
        return Accum;
    }
    return 0;
}

static const byte *_grdp_matcher(const byte* buf, int sz) {
    const byte* b = buf;
    if (_xml_matcher(buf, sz)) {
        b = Accum;
    }

    if (MEMISCAN(b, "<grit-part")) {
        return Accum;
    }
    return 0;
}

static const byte *_grd_matcher(const byte* buf, int sz) {
    const byte* b = buf;
    if (_xml_matcher(buf, sz)) {
        b = Accum;
    }


    if (MEMISCAN(b, "<grit ")) {
        return Accum;
    }
    return 0;
}

static const byte *_js_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "(function")) {
        return Accum;
    }
    if (MEMMATCH(buf, "(async function")) {
        return Accum;
    }
    if (MEMMATCH(buf, "const ")) {
        return Accum;
    }
    if (MEMMATCH(buf, "var ")) {
        return Accum;
    }
    if (MEMMATCH(buf, "function ")) {
        return Accum;
    }
    if (MEMMATCH(buf, "let ")) {
        return Accum;
    }
    if (MEMMATCH(buf, "if ")) {
        return Accum;
    }
    if (MEMMATCH(buf, "export ")) {
        return Accum;
    }
    if (MEMMATCH(buf, "import")) {
        return Accum;
    }
    if (MEMMATCH(buf, "window.")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\"use ")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\'use ")) {
        return Accum;
    }
    if (MEMMATCH(buf, "(()")) {
        return Accum;
    }

    const byte *b = buf;

    if (*b == '(') {
        ++b;
    }
    while (isalnum(*b) || *b == '_') {
        ++b;
    }
    if (b > buf && (*b == '(' || *b == '.')) {
        ++b;
        return b;
    }
    return 0;
}

static const byte *_css_matcher(const byte* buf, int sz) {
    if (MEMIMATCH(buf, "@import")) {
        return Accum;
    }
    if (MEMIMATCH(buf, "@namespace")) {
        return Accum;
    }

    const byte* b = buf;
    bool saw_letter = false;
    while (sz && (isalnum(*b) || strchr(" \t,@:*-=\'_.#()[]\r\n", *b))) { 
        if (isalnum(*b) || *b == '*' || *b == '#') {
            saw_letter = true;
        }
        ++b, --sz;
    }
    if (saw_letter && *b == '{') {
        ++b;
        return b;
    }
    return 0;
}

static const byte *_json_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "[{\"")) {
        return Accum;
    }

    if ((buf[0] == '{' || buf[0] == '[') && (isspace(buf[1]) || buf[1] == '\'' || buf[1] == '\"')) {
        return buf + 2;
    }
    const byte *b = buf;
    if (*b == '!') {
      ++b;
    }
    if (isalpha(*b)) {
        while (isalnum(*++b));
    }
    if (isspace(*b)) {
        while (isspace(*++b));
    }
    if (*b++ != '=') {
        return 0;
    }
    if (isspace(*b)) {
        while (isspace(*++b));
    }
    if (*b == '[' || *b == '{' || *b == '\'' || *b == '\"') {
        return b;
    }
    return 0;
}

static const byte *_flac_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "fLaC")) {
        return Accum;
    }
    return 0;
}

static const byte *_webp_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "RIFF") && MEMMATCH(buf + 8, "WEBP")) {
        return Accum;
    }
    return 0;
}

static const byte *_wav_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "RIFF") && MEMMATCH(buf + 8, "WAVEfmt")) {
        return Accum;
    }
    return 0;
}

static const byte *_txt_matcher(const byte* buf, int sz) {
    const byte* b = buf;
    while (1) {
        while (sz > 0 && *b && (isalnum(*b) || strchr(" .,-%#+&/\'\"\r\n\t\\:;$!?=_<>()[]", *b))) {
            ++b; --sz;
        }
        if (!sz || !*b) {
            return b;
        }
        // check for UTF-8 chars
        wchar_t wide;
        mbstate_t mbst = { 0 };
        int m = mbrtoc16(&wide, b, sz < MB_LEN_MAX ? sz: MB_LEN_MAX, &mbst);
        if (m < 2) {
            return 0;
        }
        b += m; sz -= m;
        if (sz <= 0 || !*b) {
            return b - m;
        }
    }
    return 0;
}

static const byte *_tga_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x02\x00\x00\x00\x00\x00") && MEMMATCH(buf + 16, "\x18\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_pfb_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x80\x01") && MEMMATCH(buf + 6, "%!PS-Adobe")) {
        return Accum;
    }
    return 0;
}

static const byte *_ico_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x01\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _icon_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "CANVAS_DIMENSIONS, ")) {
        return Accum;
    }
    return 0;
}

static const byte *_cur_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x02\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_gif_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "GIF87a") || MEMMATCH(buf, "GIF89a")) {
        return Accum;
    }
    return 0;
}

static const byte *_dylib_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xCF\xFA\xED\xFE") && MEMMATCH(buf + 12, "\x06\x00\x00\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_o_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xCF\xFA\xED\xFE") && MEMMATCH(buf + 12, "\x01\x00\x00\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_macho_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xCF\xFA\xED\xFE")) {
        return Accum;
    }
    return 0;
}

static const byte *_ai_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "%PDF-") && MEMSCAN(Accum, "Illustrator")) {
        return Accum;
    }
    return 0;
}

static const byte* _crt_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x30\x82\x03") && MEMMATCH(buf + 4, "\x30\x82")) {
        return Accum;
    }
    return 0;
}

static const byte* _crl_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x30\x82\x01") && MEMMATCH(buf + 4, "\x30\x81")) {
        return Accum;
    }
    return 0;
}

static const byte* _cpp_matcher(const byte* buf, int sz) {
    if (MEMSCAN(buf, "#include") 
        && (MEMSCAN(buf, "namespace") || MEMSCAN(buf, "std::") || MEMSCAN(buf, "public:"))) {
        return Accum;
    }
    return 0;
}

static const byte* _c_matcher(const byte* buf, int sz) {
    if (MEMSCAN(buf, "#include")) {
        return Accum;
    }
    return 0;
}

static const byte *_pdf_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "%PDF-")) {
        return Accum;
    }
    return 0;
}

static const byte* _xpm_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "/* XPM */ ")) {
        return Accum;
    }
    return 0;
}

static const byte *_pnm_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x50\x36\x0A\x23")) {
        return Accum;
    }
    return 0;
}

static const byte *_gpg_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x99\x02\x0D\x04")) {
        return Accum;
    }
    return 0;
}

static const byte *_nef_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "MM\x00\x2A")) {
        return Accum;
    }
    return 0;
}

static const byte *_orf_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "IIRO\x08")) {
        return Accum;
    }
    return 0;
}

static const byte *_ps_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "%!PS-Adobe-")) {
        return Accum;
    }
    return 0;
}

static const byte* _eps_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xC5\xD0\xD3\xC6")) {
        return Accum;
    }
    return 0;
}

static const byte* _wmf_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xD7\xCD\xC6\x9A")) {
        return Accum;
    }
    return 0;
}

static const byte *_rtf_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "{\\rtf1")) {
        return Accum;
    }
    return 0;
}

static const byte *_crx_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "Cr24")) {
        return Accum;
    }
    return 0;
}

static const byte* _bsdiff_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "GBSDIF")) {
        return Accum;
    }
    return 0;
}

static const byte* _hevc_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00\x01\x40\x01\x0C\x01")) {
        return Accum;
    }
    return 0;
}

static const byte *_jpeg_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xFF\xD8")) {
        return Accum;
    }
    return 0;
}

static const byte* _cacerts_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xFE\xED\xFE\xED\x00\x00\x00\x02")) {
        return Accum;
    }
    return 0;
}

static const byte *_jp2_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00\x0C\x6A\x50")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\xFF\x4F\xFF\x51")) {
        return Accum;
    }
    return 0;
}

static const byte *_pb_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x08\x07\x12")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\x08\x01\x12")) {
        return Accum;
    }
    return 0;
}

static const byte *_epub_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "PK\x03\x04") && MEMSCAN(Accum, "application/epub")) {
        return Accum;
    }
    return 0;
}

#if 0
static const byte *_brotli_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xCE\xB2\xCF\x81");
    return 0;
}
#endif

static const byte *_webm_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x1A\x45\xDF\xA3")) {
        return Accum;
    }
    return 0;
}

static const byte* _bmp_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "BMF\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _cab_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "MSCF")) {
        return Accum;
    }
    return 0;
}

static const byte *_midi_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00\x0C\x6A\x50")) {
        return Accum;
    }
    if (MEMMATCH(buf, "MThd")) {
        return Accum;
    }
    return 0;
}

static const byte *_wasm_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\0asm")) {
        return Accum;
    }
    return 0;
}

static const byte *_sqlite_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "SQLite format")) {
        return Accum;
    }
    return 0;
}

static const byte* _rm_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, ".RMF")) {
        return Accum;
    }
    return 0;
}

static const byte* _swf_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "FWS\x06")) {
        return Accum;
    }
    if (MEMMATCH(buf, "FLV")) {
        return Accum;
    }
    return 0;
}

static const byte* _vvc_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x00\x00\x00\x01\x00\x79\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_woff_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "wOFF")) {
        return Accum;
    }
    return 0;
}

static const byte* _mskp_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "Skia Multi-Picture Doc\x0A\x0A\x02\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_icns_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "icns\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_ogg_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "OggS") && MEMMATCH(buf + 0x1D, "vorbis")) {
        return Accum;
    }
    return 0;
}

static const byte *_opus_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "OggS") && MEMMATCH(buf + 0x1C, "Opus")) {
        return Accum;
    }
    return 0;
}

static const byte *_ogv_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "OggS") && MEMMATCH(buf + 0x1C, "OVP8")) {
        return Accum;
    }
    return 0;
}

static const byte* _3ds_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "MM") && MEMMATCH(buf + 6, "\x02\x00\x0A\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _ivf_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "DKIF\x00") && MEMMATCH(buf + 8, "AV")) {
        return Accum;
    }
    if (MEMMATCH(buf, "IVF")) {
        return Accum;
    }
    return 0;
}

static const byte* _m2ts_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "G@") && MEMMATCH(buf + 3, "\x10\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_otf_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "OTTO")) {
        return Accum;
    }
    return 0;
}

static const byte* _psd_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "8BPS\x00")) {
        return Accum;
    }
    return 0;
}

static const byte *_res_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf + 12, "ResB")) {
        return Accum;
    }
    return 0;
}

static const byte *_ttf_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf + 12, "GDEF")) {
        return Accum;
    }
    return 0;
}

static const byte *_woff2_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "wOF2")) {
        return Accum;
    }
    return 0;
}

static const byte* _mpg_matcher(const byte* buf, int sz) {
    if (sz >= 4 && MEMMATCH(buf, "\x00\x00\x01") && buf[3] >= 0xB0 && buf[3] <= 0xBF) {
        return Accum;
    }
    return 0;
}

static const byte* _wma_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x30\x26\xB2\x75")) {
        return Accum;
    }
    return 0;
}

static const byte* _pack_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "PACK\0\0")) {
        return Accum;
    }
    return 0;
}

static const byte* _rev_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "RIDX\0\0")) {
        return Accum;
    }
    if (MEMMATCH(buf, "RIVE\x07")) {
        return Accum;
    }
    return 0;
}

static const byte* _vsidx_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "CDG\x11")) {
        return Accum;
    }
    return 0;
}

static const byte* _idx_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xFF\x74\x4F\x63\x00\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _ttc_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "ttcf\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _bs_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x42\x43\xC0\xDE")) {
        return Accum;
    }
    return 0;
}

static const byte* _pak_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\x05\x00\x00\x00\x01\x00\x00\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _mo_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "\xDE\x12\x04\x95\x00\x00")) {
        return Accum;
    }
    return 0;
}

static const byte* _data_1_matcher(const byte* buf, int sz) {
    if (sz > 10 && MEMMATCH(buf, "\xC3\xCA\x04\xC1") && buf[8] == 1) {
        return buf + 9;
    }
    return 0;
}

static const byte* _data_2_matcher(const byte* buf, int sz) {
    if (sz > 10 && MEMMATCH(buf, "\xC3\xCA\x04\xC1") && buf[8] == 2) {
        return buf + 9;
    }
    return 0;
}

static const byte* _data_3_matcher(const byte* buf, int sz) {
    if (sz > 10 && MEMMATCH(buf, "\xC3\xCA\x04\xC1") && buf[8] == 3) {
        return buf + 9;
    }
    return 0;
}

static const byte *_mp3_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "ID3") && MEMSCAN(Accum, "\xFF\xFB")) {
        return Accum;
    }
    if (MEMMATCH(buf, "\xFF\xFB")) {
        return Accum;
    }
    return 0;
}

static const byte *_lottie_matcher(const byte* buf, int sz) {
    if (MEMMATCH(buf, "LOTTIE")) {
        return Accum;
    }
    return 0;
}

static FileType MEDIA_FILES[] = {
    PAK_GEN_FILE_TYPE(gz),
    PAK_GEN_FILE_TYPE(br),
    PAK_GEN_FILE_TYPE(lz),
    PAK_GEN_FILE_TYPE(rm),
    PAK_GEN_FILE_TYPE(lzh),
    PAK_GEN_FILE_TYPE(lzo),
    PAK_GEN_FILE_TYPE(hlp),
    PAK_GEN_FILE_TYPE(gid),
    PAK_GEN_FILE_TYPE(iso),
    PAK_GEN_FILE_TYPE(7z),
    PAK_GEN_FILE_TYPE(bz2),
    PAK_GEN_FILE_TYPE(swf),
    PAK_GEN_FILE_TYPE(zz),
    PAK_GEN_FILE_TYPE(pch),
    PAK_GEN_FILE_TYPE(epub),
    PAK_GEN_FILE_TYPE(a),
    PAK_GEN_FILE_TYPE(obj),
    PAK_GEN_FILE_TYPE(sit),
    PAK_GEN_FILE_TYPE(zoo),
    PAK_GEN_FILE_TYPE(pnm),
    PAK_GEN_FILE_TYPE(pfb),
    PAK_GEN_FILE_TYPE(lib),
    PAK_GEN_FILE_TYPE(pack),
    PAK_GEN_FILE_TYPE(idx),
    PAK_GEN_FILE_TYPE(mkv),
    PAK_GEN_FILE_TYPE(pyc),
    PAK_GEN_FILE_TYPE(vsidx),
    PAK_GEN_FILE_TYPE(descriptor),
    PAK_GEN_FILE_TYPE(so),
    PAK_GEN_FILE_TYPE(elf),
    PAK_GEN_FILE_TYPE(aar),
    PAK_GEN_FILE_TYPE(jar),
    PAK_GEN_FILE_TYPE(tar),
    PAK_GEN_FILE_TYPE(cacerts),
    PAK_GEN_FILE_TYPE(node),
    PAK_GEN_FILE_TYPE(pyd),
    PAK_GEN_FILE_TYPE(rev),
    PAK_GEN_FILE_TYPE(p12),
    PAK_GEN_FILE_TYPE(mo),
    PAK_GEN_FILE_TYPE(exe),
    PAK_GEN_FILE_TYPE(windb),
    PAK_GEN_FILE_TYPE(mskp),
    PAK_GEN_FILE_TYPE(bdic),
    PAK_GEN_FILE_TYPE(psd),
    PAK_GEN_FILE_TYPE(bmp),
    PAK_GEN_FILE_TYPE(3ds),
    PAK_GEN_FILE_TYPE(ivf),
    PAK_GEN_FILE_TYPE(h263),
    PAK_GEN_FILE_TYPE(h264),
    PAK_GEN_FILE_TYPE(vvc),
    PAK_GEN_FILE_TYPE(wma),
    PAK_GEN_FILE_TYPE(icc),
    PAK_GEN_FILE_TYPE(mpg),
    PAK_GEN_FILE_TYPE(bc),
    PAK_GEN_FILE_TYPE(vp8),
    PAK_GEN_FILE_TYPE(vp9),
    PAK_GEN_FILE_TYPE(dll),
    PAK_GEN_FILE_TYPE(eot),
    PAK_GEN_FILE_TYPE(rar),
    PAK_GEN_FILE_TYPE(ttf),
    PAK_GEN_FILE_TYPE(tiff),
    PAK_GEN_FILE_TYPE(otf),
    PAK_GEN_FILE_TYPE(icns),
    PAK_GEN_FILE_TYPE(res),
    PAK_GEN_FILE_TYPE(bzip),
    PAK_GEN_FILE_TYPE(pdb),
    PAK_GEN_FILE_TYPE(msi),
    PAK_GEN_FILE_TYPE(tfl),
    PAK_GEN_FILE_TYPE(xz),
    PAK_GEN_FILE_TYPE(dylib),
    PAK_GEN_FILE_TYPE(data_1),
    PAK_GEN_FILE_TYPE(data_2),
    PAK_GEN_FILE_TYPE(data_3),
    PAK_GEN_FILE_TYPE(sha1),
    PAK_GEN_FILE_TYPE(o),
    PAK_GEN_FILE_TYPE(macho),
    PAK_GEN_FILE_TYPE(opus),
    PAK_GEN_FILE_TYPE(ogv),
    PAK_GEN_FILE_TYPE(bs),
    PAK_GEN_FILE_TYPE(py),
    PAK_GEN_FILE_TYPE(bsdiff),
    PAK_GEN_FILE_TYPE(gpg),
    PAK_GEN_FILE_TYPE(mgc),
    PAK_GEN_FILE_TYPE(nef),
    PAK_GEN_FILE_TYPE(orf),
    PAK_GEN_FILE_TYPE(ogg),
    PAK_GEN_FILE_TYPE(spl),
    PAK_GEN_FILE_TYPE(sug),
    PAK_GEN_FILE_TYPE(rtp),
    PAK_GEN_FILE_TYPE(zstd),
    PAK_GEN_FILE_TYPE(skp),
    PAK_GEN_FILE_TYPE(whl),
    PAK_GEN_FILE_TYPE(zip),
    PAK_GEN_FILE_TYPE(gif),
    PAK_GEN_FILE_TYPE(icu),
    PAK_GEN_FILE_TYPE(m2ts),
    PAK_GEN_FILE_TYPE(crt),
    PAK_GEN_FILE_TYPE(crl),
    PAK_GEN_FILE_TYPE(pak),
    PAK_GEN_FILE_TYPE(webm),
    PAK_GEN_FILE_TYPE(flac),
    PAK_GEN_FILE_TYPE(sxg),
    PAK_GEN_FILE_TYPE(mp3),
    PAK_GEN_FILE_TYPE(cab),
    PAK_GEN_FILE_TYPE(mp4),
    PAK_GEN_FILE_TYPE(avif),
    PAK_GEN_FILE_TYPE(m4v),
    PAK_GEN_FILE_TYPE(m4a),
    PAK_GEN_FILE_TYPE(dng),
    PAK_GEN_FILE_TYPE(mov),
    PAK_GEN_FILE_TYPE(hevc),
    PAK_GEN_FILE_TYPE(3gp),
    PAK_GEN_FILE_TYPE(wav),
    PAK_GEN_FILE_TYPE(jpeg),
    PAK_GEN_FILE_TYPE(gz),
    PAK_GEN_FILE_TYPE(Z),
    PAK_GEN_FILE_TYPE(jp2),
    PAK_GEN_FILE_TYPE(hqx),
    PAK_GEN_FILE_TYPE(arc),
    PAK_GEN_FILE_TYPE(class),
    PAK_GEN_FILE_TYPE(midi),
    PAK_GEN_FILE_TYPE(crx),
    PAK_GEN_FILE_TYPE(pb),
    PAK_GEN_FILE_TYPE(flv),
    PAK_GEN_FILE_TYPE(lottie),
    PAK_GEN_FILE_TYPE(sqlite),
    PAK_GEN_FILE_TYPE(wasm),
    PAK_GEN_FILE_TYPE(woff),
    PAK_GEN_FILE_TYPE(woff2),
    PAK_GEN_FILE_TYPE(png),
    PAK_GEN_FILE_TYPE(webp),
    PAK_GEN_FILE_TYPE(ttc),
    PAK_GEN_FILE_TYPE(tga),
    PAK_GEN_FILE_TYPE(chm),
    PAK_GEN_FILE_TYPE(ico),
    PAK_GEN_FILE_TYPE(ai),
    PAK_GEN_FILE_TYPE(pdf),
    PAK_GEN_FILE_TYPE(wmf),
    PAK_GEN_FILE_TYPE(xpm),
    PAK_GEN_FILE_TYPE(eps),
    PAK_GEN_FILE_TYPE(ps),
    PAK_GEN_FILE_TYPE(arj),
    PAK_GEN_FILE_TYPE(cur)
};

static FileType TEXT_FILES[] = {
    PAK_GEN_FILE_TYPE(rtf),
    PAK_GEN_FILE_TYPE(icon),
    PAK_GEN_FILE_TYPE(json),
    PAK_GEN_FILE_TYPE(js),
    PAK_GEN_FILE_TYPE(css),
    PAK_GEN_FILE_TYPE(cpp),
    PAK_GEN_FILE_TYPE(c),
    PAK_GEN_FILE_TYPE(svg),
    PAK_GEN_FILE_TYPE(ninja),
    PAK_GEN_FILE_TYPE(xtb),
    PAK_GEN_FILE_TYPE(grdp),
    PAK_GEN_FILE_TYPE(grd),
    PAK_GEN_FILE_TYPE(xml),
    PAK_GEN_FILE_TYPE(html),
    PAK_GEN_FILE_TYPE(txt)
};

static int header_match(const char* header, const char* magic, int len) {
    for (; len--; ++header, ++magic) {
        if ((*magic != -1) && (*header != *magic)) {
            return 0;
        }
    }
    return 1;
}

const char* pakGetFileType(PakFile file) {
    char* buf = file.buffer;
    int sz = file.size;

    for (FileType* ft = MEDIA_FILES; ft < MEDIA_FILES + (sizeof(MEDIA_FILES) / sizeof(MEDIA_FILES[0])); ++ft) {

        if (ft->matchFunc(buf, sz)) {
            return ft->type;
        }
    }

    // dealing with text files for here on out.  Remove BOM, comments

    if (MEMMATCH(buf, "\xEF\xBB\xBF")) {
        buf += 3; sz -= 3;    // UTF-8 BOM
    } else if (MEMMATCH(buf, "\x00\x00\xFE\xFF")) {
        buf += 4; sz -= 4;    // UTF-32 BE
    } else if (MEMMATCH(buf, "\xFF\xFE\x00\x00")) {
        buf += 4; sz -= 4;    // UTF-32 LE
    } else if (MEMMATCH(buf, "\xFE\xFF")) {
        buf += 2; sz -= 2;    // UTF-16 BE
    } else if (MEMMATCH(buf, "\xFF\xFE")) {
        buf += 2; sz -= 2;    // UTF-16 LE
    }

    while (1) {
        while (strchr(" \t\r\f\v\n", *buf)) { ++buf; --sz; }

        if (buf[0] == ';' || buf[0] == '#') {
            ++buf; --sz;
            while (buf[0] && buf[0] != '\n' && buf[0] != '\r') { ++buf; --sz; }

        }
        else if (buf[0] == '/' && buf[1] == '/') {
            buf += 2; sz -= 2;
            while (buf[0] && buf[0] != '\n' && buf[0] != '\r') { ++buf; --sz; }
        }
        else if (buf[0] == '/' && buf[1] == '*') {
            buf += 2; sz -= 2;
            while (buf[0] && buf[1] && (buf[0] != '*' || buf[1] != '/')) { ++buf; --sz; }
            buf += 2; sz -= 2;
        }
        else {
            break;
        }
    }

    if (sz <= 0) {
        return ".js";
    }

    for (FileType* ft = TEXT_FILES; ft < TEXT_FILES + (sizeof(TEXT_FILES) / sizeof(TEXT_FILES[0])); ++ft) {

        if (ft->matchFunc(buf, sz)) {
            return ft->type;
        }
    }

    return ".unknown";
}
