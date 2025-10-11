#include <windows.h>
#include <iostream>

#include <ida.hpp>
#include <kernwin.hpp> 

#define ACTION_NAME "BinaryLens"

plugmod_t* idaapi init();
bool idaapi run(size_t);
void idaapi term();