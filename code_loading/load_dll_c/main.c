#include <windows.h>
#include <stdio.h>

typedef void (*OpenCalcFunc)();

int main() {
    HMODULE hLib;
    OpenCalcFunc openCalc;

    // Load the DLL
    hLib = LoadLibrary("../../payloads/calc_exe/calc.dll");
    if (hLib == NULL) {
        printf("Unable to load calc.dll\n");
        return 1;
    }

    printf("calc.dll loaded successfully.\n");

    // Get a pointer to the OpenCalc function
    openCalc = (OpenCalcFunc)GetProcAddress(hLib, "OpenCalc");
    if (openCalc == NULL) {
        printf("Unable to find OpenCalc function\n");
        FreeLibrary(hLib);
        return 1;
    }

    // Call the OpenCalc function
    openCalc();

    // Free the DLL
    FreeLibrary(hLib);
    printf("calc.dll unloaded.\n");

    return 0;
}
