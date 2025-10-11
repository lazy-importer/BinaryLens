#include <windows.h>
#include <iostream>

#include "plugin/action_handler.h"

#include <hexrays.hpp>

__declspec(dllexport) plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC,
    init,
    term,
    run,
    "",
    "",
    "BinaryLens",
    0
};