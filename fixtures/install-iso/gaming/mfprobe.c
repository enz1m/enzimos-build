/* SPDX-License-Identifier: MIT
 * Minimal Windows PE media decoder fixture. ABI facts follow Microsoft Source
 * Reader/IMFAttributes/IMFSample documentation; no Windows SDK or CRT bundled.
 */
typedef unsigned long DWORD;
typedef long HRESULT;
typedef unsigned short WCHAR;
typedef struct { DWORD a; unsigned short b, c; unsigned char d[8]; } GUID;
typedef struct Object { void **vtable; } Object;
#include "mf-reference.h"
__declspec(dllimport) void ExitProcess(unsigned int);
__declspec(dllimport) void *GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(void *, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) void *LoadLibraryA(const char *);
__declspec(dllimport) void *GetProcAddress(void *, const char *);
static void text(const char *value) {
    DWORD length = 0, written;
    while (value[length]) length++;
    WriteFile(GetStdHandle((DWORD)-11), value, length, &written, (void *)0);
}
static void number(DWORD value) {
    char code[11] = "0x00000000";
    for (unsigned i = 0; i < 8; i++) code[9-i] = "0123456789abcdef"[(value >> (i*4)) & 15];
    text(code);
}
static void require(HRESULT result, const char *operation) {
    if (result < 0) {
        char code[11] = "0x00000000";
        for (unsigned i = 0; i < 8; i++) code[9-i] = "0123456789abcdef"[((DWORD)result >> (i*4)) & 15];
        text("ENZIMOS_MF_FAIL "); text(operation); text(" "); text(code); text("\n"); ExitProcess(2);
    }
}
static const GUID frame_size = {0x1652c33d,0xd6b2,0x4012,{0xb8,0x34,0x72,0x03,0x08,0x49,0xa3,0x7d}};
static const GUID bits_key = {0xf2deb57f,0x40fa,0x4764,{0xaa,0x33,0xed,0x4f,0x2d,0x1f,0xf6,0x69}};
static const GUID channels_key = {0x37e48bf5,0x645e,0x4c5b,{0x89,0xde,0xad,0xa9,0xe2,0x9b,0x69,0x6a}};
static const GUID rate_key = {0x5faeeae7,0x0290,0x4c31,{0x9e,0x8a,0xc5,0x34,0xf6,0x8d,0x9d,0xba}};
static const GUID major_key = {0x48eba18e,0xf8c9,0x4687,{0xbf,0x11,0x0a,0x74,0xc9,0xf9,0x6a,0x8f}};
static const GUID subtype_key = {0xf7e34c9a,0x42e8,0x4714,{0xb7,0x4b,0xcb,0x29,0xd7,0x2c,0x35,0xe5}};
static const GUID video = {0x73646976,0,0x0010,{0x80,0,0,0xaa,0,0x38,0x9b,0x71}};
static const GUID audio = {0x73647561,0,0x0010,{0x80,0,0,0xaa,0,0x38,0x9b,0x71}};
static const GUID nv12 = {0x3231564e,0,0x0010,{0x80,0,0,0xaa,0,0x38,0x9b,0x71}};
static const GUID pcm = {1,0,0x0010,{0x80,0,0,0xaa,0,0x38,0x9b,0x71}};
static void release(Object *value) {
    if (value) ((DWORD (*)(Object *))value->vtable[2])(value);
}
static void decode(void *reader_dll, void *platform, int is_video) {
    Object *reader = (void *)0, *type = (void *)0;
    const WCHAR path[] = L"Z:\\var\\tmp\\enzimos-gaming-lab\\fixtures\\av.mp4";
    HRESULT (*create_reader)(const WCHAR *, Object *, Object **) = GetProcAddress(reader_dll, "MFCreateSourceReaderFromURL");
    HRESULT (*create_type)(Object **) = GetProcAddress(platform, "MFCreateMediaType");
    if (!create_reader || !create_type) ExitProcess(3);
    require(create_reader(path, (void *)0, &reader), "source-reader");
    require(create_type(&type), "media-type");
    HRESULT (*set_guid)(Object *, const GUID *, const GUID *) = (void *)type->vtable[24];
    require(set_guid(type, &major_key, is_video ? &video : &audio), "major-type");
    require(set_guid(type, &subtype_key, is_video ? &nv12 : &pcm), "raw-subtype");
    if (!is_video) {
        HRESULT (*set_uint)(Object *, const GUID *, DWORD) = (void *)type->vtable[21];
        require(set_uint(type, &bits_key, 16), "PCM16");
        require(set_uint(type, &channels_key, 1), "mono");
        require(set_uint(type, &rate_key, 48000), "sample-rate");
    }
    DWORD stream = is_video ? (DWORD)-4 : (DWORD)-3;
    HRESULT (*set_type)(Object *, DWORD, DWORD *, Object *) = (void *)reader->vtable[7];
    require(set_type(reader, stream, (void *)0, type), is_video ? "decode-H264-NV12" : "decode-AAC-PCM");
    release(type);
    if (is_video) {
        Object *actual_type = (void *)0;
        unsigned long long dimensions = 0;
        HRESULT (*get_type)(Object *, DWORD, Object **) = (void *)reader->vtable[6];
        require(get_type(reader, stream, &actual_type), "negotiated-type");
        HRESULT (*get_size)(Object *, const GUID *, unsigned long long *) = (void *)actual_type->vtable[8];
        require(get_size(actual_type, &frame_size, &dimensions), "frame-size");
        release(actual_type);
        // Some MFTs allocate an aligned 192-line surface for a 180-line clip.
        if ((dimensions >> 32) != 320 || ((DWORD)dimensions != 180 && (DWORD)dimensions != 192)) ExitProcess(8);
    }
    unsigned samples = 0, positive_audio = 0, negative_audio = 0;
    long long previous = -1;
    for (unsigned count = 0; count < 500; count++) {
        Object *sample = (void *)0;
        DWORD actual = 0, flags = 0, length = 0;
        long long timestamp = 0;
        HRESULT (*read_sample)(Object *, DWORD, DWORD, DWORD *, DWORD *, long long *, Object **) = (void *)reader->vtable[9];
        require(read_sample(reader, stream, 0, &actual, &flags, &timestamp, &sample), "read-sample");
        if (sample) {
            HRESULT (*total_length)(Object *, DWORD *) = (void *)sample->vtable[45];
            require(total_length(sample, &length), "raw-buffer-length");
            if (!length || (is_video && (length < 320*180*3/2 || length > 320*192*3/2)) || timestamp < previous) {
                text("ENZIMOS_MF_RAW_BUFFER_FAIL length="); number(length);
                text(" timestamp="); number((DWORD)timestamp); text("\n"); ExitProcess(4);
            }
            Object *buffer = (void *)0;
            unsigned char *raw = (void *)0;
            DWORD capacity = 0, current = 0;
            HRESULT (*contiguous)(Object *, Object **) = (void *)sample->vtable[41];
            require(contiguous(sample, &buffer), "contiguous-buffer");
            HRESULT (*lock)(Object *, unsigned char **, DWORD *, DWORD *) = (void *)buffer->vtable[3];
            require(lock(buffer, &raw, &capacity, &current), "raw-data");
            if (!raw || current != length || capacity < current) ExitProcess(9);
            if (is_video && samples == 0) {
                for (unsigned i = 0; i < sizeof(expected_luma) / sizeof(expected_luma[0]); i++) {
                    int difference = (int)raw[expected_luma[i][0]] - (int)expected_luma[i][1];
                    if (difference < -2 || difference > 2) {
                        text("ENZIMOS_MF_REFERENCE_FAIL pixel="); number(expected_luma[i][0]);
                        text(" actual="); number(raw[expected_luma[i][0]]); text("\n"); ExitProcess(10);
                    }
                }
            } else if (!is_video) {
                for (unsigned i = 0; i + 1 < current; i += 2) {
                    short value = (short)(raw[i] | (raw[i+1] << 8));
                    if (value > 512) positive_audio++;
                    if (value < -512) negative_audio++;
                }
            }
            HRESULT (*unlock)(Object *) = (void *)buffer->vtable[4];
            require(unlock(buffer), "unlock-buffer"); release(buffer);
            previous = timestamp; samples++; release(sample);
        }
        if (flags & 2) break;
    }
    release(reader);
    if (samples < 8 || (!is_video && (!positive_audio || !negative_audio))) ExitProcess(5);
    text(is_video ? "ENZIMOS_PROTON_MF_H264_RAW_VIDEO_PASS\n" : "ENZIMOS_PROTON_MF_AAC_RAW_AUDIO_PASS\n");
}
void mainCRTStartup(void) {
    void *ole = LoadLibraryA("ole32.dll"), *platform = LoadLibraryA("mfplat.dll"), *reader = LoadLibraryA("mfreadwrite.dll");
    if (!ole || !platform || !reader) ExitProcess(6);
    HRESULT (*initialize)(void *, DWORD) = GetProcAddress(ole, "CoInitializeEx");
    HRESULT (*startup)(DWORD, DWORD) = GetProcAddress(platform, "MFStartup");
    if (!initialize || !startup) ExitProcess(7);
    require(initialize((void *)0, 0), "COM"); require(startup(0x00020070, 0), "MF-startup");
    decode(reader, platform, 1); decode(reader, platform, 0); ExitProcess(0);
}
