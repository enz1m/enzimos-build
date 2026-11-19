/* SPDX-License-Identifier: MIT
 * Tiny native SDL render/input/audio consumer, not a commercial game benchmark.
 */
#include <SDL2/SDL.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdatomic.h>
static double phase;
static _Atomic unsigned audio_calls;
static void audio(void *unused, Uint8 *stream, int size) {
    (void)unused;
    float *samples = (float *)stream;
    for (int i = 0; i < size / (int)sizeof(float); i++) {
        samples[i] = (float)(sin(phase) * .05);
        phase += 2 * 3.141592653589793 * 440 / 48000;
    }
    atomic_fetch_add_explicit(&audio_calls, 1, memory_order_relaxed);
}
int main(void) {
    SDL_version linked; SDL_GetVersion(&linked);
    fprintf(stderr, "SDL runtime %u.%u.%u revision=%s\n", linked.major, linked.minor, linked.patch, SDL_GetRevision());
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_JOYSTICK | SDL_INIT_AUDIO) != 0) {
        fprintf(stderr, "SDL init: %s\n", SDL_GetError()); return 2;
    }
    SDL_Window *window = SDL_CreateWindow("enzimOS gaming fixture", SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED, 640, 360, 0);
    if (!window) {
        fprintf(stderr, "SDL window (%s): %s\n", SDL_GetCurrentVideoDriver(), SDL_GetError());
        SDL_Quit();
        return 3;
    }
    SDL_Renderer *renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_SOFTWARE);
    if (!renderer) {
        fprintf(stderr, "SDL software renderer (%s): %s\n", SDL_GetCurrentVideoDriver(), SDL_GetError());
        SDL_Surface *surface = SDL_GetWindowSurface(window);
        fprintf(stderr, "SDL window surface: %s\n", surface ? "available" : SDL_GetError());
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 3;
    }
    SDL_Joystick *pad = NULL;
    for (int i = 0; i < SDL_NumJoysticks(); i++) {
        const char *name = SDL_JoystickNameForIndex(i);
        Uint16 vendor = SDL_JoystickGetDeviceVendor(i), product = SDL_JoystickGetDeviceProduct(i);
        printf("ENZIMOS_PAD name=%s vendor=%04x product=%04x\n", name ? name : "", vendor, product);
        if (vendor == 0x045e && product == 0x028e) pad = SDL_JoystickOpen(i);
    }
    if (!pad) { fprintf(stderr, "fixture pad missing\n"); return 4; }
    SDL_AudioSpec want = {0}, have = {0};
    want.freq = 48000; want.format = AUDIO_F32SYS; want.channels = 1;
    want.samples = 1024; want.callback = audio;
    SDL_AudioDeviceID sound = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
    if (!sound) { fprintf(stderr, "audio: %s\n", SDL_GetError()); return 5; }
    SDL_PauseAudioDevice(sound, 0);
    unsigned ticks = 0, axis_changes = 0, buttons = 0, max_delay = 0, keys = 0;
    puts("ENZIMOS_GAMEPROBE_VISIBLE"); fflush(stdout);
    Uint32 start = SDL_GetTicks(), previous = start;
    int previous_axis = 0;
    while (SDL_GetTicks() - start < 30000) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_JOYBUTTONDOWN) buttons++;
            if (event.type == SDL_KEYDOWN && event.key.keysym.sym == SDLK_SPACE) keys++;
        }
        int value = SDL_JoystickGetAxis(pad, 0);
        if (value != previous_axis) { axis_changes++; previous_axis = value; }
        SDL_SetRenderDrawColor(renderer, 25, (Uint8)(80 + ticks % 80), 140, 255);
        SDL_RenderClear(renderer); SDL_RenderPresent(renderer);
        Uint32 now = SDL_GetTicks(), delay = now - previous;
        if (delay > max_delay) max_delay = delay;
        previous = now; ticks++; SDL_Delay(16);
    }
    unsigned callbacks = atomic_load_explicit(&audio_calls, memory_order_relaxed);
    printf("ENZIMOS_GAMEPROBE ticks=%u max_delay_ms=%u axes=%u buttons=%u audio_callbacks=%u keys=%u audio_driver=%s video_driver=%s\n",
        ticks, max_delay, axis_changes, buttons, callbacks, keys, SDL_GetCurrentAudioDriver(), SDL_GetCurrentVideoDriver());
    SDL_CloseAudioDevice(sound); SDL_JoystickClose(pad); SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window); SDL_Quit();
    return ticks >= 300 && max_delay < 2000 && axis_changes > 4 && buttons > 4 && callbacks > 4 && keys > 0 ? 0 : 6;
}
