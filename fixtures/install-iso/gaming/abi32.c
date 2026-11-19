/* SPDX-License-Identifier: MIT */
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    const char *libraries[] = {"libvulkan.so.1", "libGL.so.1", "libpulse.so.0", "libasound.so.2", "libgamemode.so.0"};
    for (unsigned i = 0; i < sizeof(libraries) / sizeof(libraries[0]); i++) {
        void *handle = dlopen(libraries[i], RTLD_NOW | RTLD_LOCAL);
        if (!handle) { fprintf(stderr, "%s: %s\n", libraries[i], dlerror()); return 2; }
        if (i == 4) {
            int (*request)(void) = (int (*)(void))dlsym(handle, "real_gamemode_request_start");
            int (*finish)(void) = (int (*)(void))dlsym(handle, "real_gamemode_request_end");
            int (*query)(void) = (int (*)(void))dlsym(handle, "real_gamemode_query_status");
            const char *(*error)(void) = (const char *(*)(void))dlsym(handle, "real_gamemode_error_string");
            if (!request || !finish || !query || !error) { fprintf(stderr, "GameMode ABI: %s\n", dlerror()); return 3; }
            if (request() != 0 || query() != 2 || finish() != 0) {
                fprintf(stderr, "GameMode request: %s\n", error()); return 3;
            }
        }
        dlclose(handle);
    }
    puts("ENZIMOS_GAMING_32BIT_ABI_AND_GAMEMODE_PASS");
    return 0;
}
