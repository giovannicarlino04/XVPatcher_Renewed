#include "patches.h"

//WITH THE OLD APPROACH WE ONLY HAD ONE DATA FOLDER, THIS CAUSED A WEIRD BUG
//THAT DID NOT ACTIVATE THE DLC3, LET'S SEE IF MAKING SEPARATE FOLDERS FIXES IT
bool CPKPatches(HANDLE hProcess, uintptr_t moduleBaseAddress) {
   	const BYTE newBytes1[] = { 0x2F, 0x64, 0x61, 0x74, 0x61, 0x2F, 0x00, 0x00, 0x00, 0x00 };
   	const BYTE newBytes2[] = { 0x2F, 0x64, 0x61, 0x74, 0x61, 0x02, 0x2F, 0x00, 0x00, 0x00 };
   	const BYTE newBytes3[] = { 0x2F, 0x64, 0x61, 0x74, 0x61, 0x70, 0x01, 0x2F, 0x00, 0x00 };
   	const BYTE newBytes4[] = { 0x2F, 0x64, 0x61, 0x74, 0x61, 0x70, 0x02, 0x2F, 0x00, 0x00 };
   	const BYTE newBytes5[] = { 0x2F, 0x64, 0x61, 0x74, 0x61, 0x70, 0x03, 0x2F, 0x00, 0x00 };

	const SIZE_T patchsize1 = sizeof(newBytes1);
	const SIZE_T patchsize2 = sizeof(newBytes2);
	const SIZE_T patchsize3 = sizeof(newBytes3);
	const SIZE_T patchsize4 = sizeof(newBytes4);
	const SIZE_T patchsize5 = sizeof(newBytes5);

	LPVOID address1 = nullptr;
    LPVOID address2 = nullptr;	
    LPVOID address3 = nullptr;
    LPVOID address4 = nullptr;
	LPVOID address5 = nullptr;
    SIZE_T numberOfBytesWritten;
    DWORD oldProtect;
    DWORD newProtect = PAGE_EXECUTE_READWRITE;

    if (moduleBaseAddress != 0) {
        address1 = (LPVOID)(moduleBaseAddress + 0x1197BC4);
        address2 = (LPVOID)(moduleBaseAddress + 0x1197BB8);
        address3 = (LPVOID)(moduleBaseAddress + 0x1196D58);
        address4 = (LPVOID)(moduleBaseAddress + 0x1196D64);
        address5 = (LPVOID)(moduleBaseAddress + 0x1196D70);
    }

    // Patch memory at address1
    if (!VirtualProtect(address1, patchsize1, newProtect, &oldProtect)) {
        return false;
    }
    if (WriteProcessMemory(hProcess, address1, newBytes1, patchsize1, &numberOfBytesWritten)) {
    }
    if (!VirtualProtect(address1, patchsize1, oldProtect, &oldProtect)) {
        return false;
    }

    // Patch memory at address2
    if (!VirtualProtect(address2, patchsize2, newProtect, &oldProtect)) {
        return false;
    }
    if (WriteProcessMemory(hProcess, address2, newBytes2, patchsize2, &numberOfBytesWritten)) {
    }
    if (!VirtualProtect(address2, patchsize2, oldProtect, &oldProtect)) {
        return false;
    }

    // Patch memory at address3
    if (!VirtualProtect(address3, patchsize3, newProtect, &oldProtect)) {
        return false;
    }
    if (WriteProcessMemory(hProcess, address3, newBytes3, patchsize3, &numberOfBytesWritten)) {
    }
    if (!VirtualProtect(address3, patchsize3, oldProtect, &oldProtect)) {
        return false;
    }

    // Patch memory at address4
    if (!VirtualProtect(address4, patchsize4, newProtect, &oldProtect)) {
        return false;
    }
    if (WriteProcessMemory(hProcess, address4, newBytes4, patchsize4, &numberOfBytesWritten)) {
    }
    if (!VirtualProtect(address4, patchsize4, oldProtect, &oldProtect)) {
        return false;
    }

    // Patch memory at address5
    if (!VirtualProtect(address5, patchsize5, newProtect, &oldProtect)) {
        return false;
    }
    if (WriteProcessMemory(hProcess, address5, newBytes5, patchsize5, &numberOfBytesWritten)) {
    }
    if (!VirtualProtect(address5, patchsize5, oldProtect, &oldProtect)) {
        return false;
    }

	return true;
}

bool CMSPatches(HANDLE hProcess, uintptr_t moduleBaseAddress) {
   	const char* newBytes1 = "\x7F\x7C\x09\xB8\x00";  // CMS Patch 1  //64 7C 09 B8 01 Before
    const char* newBytes2 = "\x70\x7D\x6E\xC7\x45";  // CMS Patch 2  //64 7D 6E C7 45 Before

	LPVOID address1 = nullptr;
    LPVOID address2 = nullptr;
    SIZE_T numberOfBytesWritten;

    if (moduleBaseAddress != 0) {
        address1 = (LPVOID)(moduleBaseAddress + 0x15EE39);
        address2 = (LPVOID)(moduleBaseAddress + 0x19363A);
    }
	else{
	}

    /////////////// PATCHES GO HERE ///////////////

    if (WriteProcessMemory(hProcess, address1, newBytes1, strlen(newBytes1), &numberOfBytesWritten)) {
    }
    if (WriteProcessMemory(hProcess, address2, newBytes2, strlen(newBytes2), &numberOfBytesWritten)) {
    }
	return 0;
}

bool VersionStringPatch(HANDLE hProcess, uintptr_t moduleBaseAddress) {
	const BYTE patchsize = wcslen(L"\x76\x65\x72\x2e\x31\x2e\x30\x38\x2e\x30\x30") * sizeof(wchar_t);
    const wchar_t* newBytes1 = L"\x58\x56\x50\x61\x74\x63\x68\x65\x72";

    LPVOID address1 = nullptr;
    SIZE_T numberOfBytesWritten;
    DWORD oldProtect;
    DWORD newProtect = PAGE_EXECUTE_READWRITE;

    if (moduleBaseAddress != 0) {
        address1 = (LPVOID)(moduleBaseAddress + 0x11ACFB4);
    }

    ////////////////// PATCHES GO HERE ///////////////

    // Version String Patch 1
    if (address1 == nullptr) {
        return false;
    }

    if (!VirtualProtect(address1, patchsize, newProtect, &oldProtect)) {
        return false;
    }

    if (!WriteProcessMemory(hProcess, address1, newBytes1, patchsize, &numberOfBytesWritten)) {
        return false;
    }

    if (!VirtualProtect(address1, patchsize, oldProtect, &newProtect)) {
        return false;
    }

    return true;
}


bool BacBcmPatch(HANDLE hProcess, uintptr_t moduleBaseAddress) {
    const char* newBytes1 = "\x90\x90\x75\x21\xC7";

    LPVOID address1 = nullptr;
    SIZE_T numberOfBytesWritten;
    DWORD oldProtect;
    DWORD newProtect = PAGE_EXECUTE_READWRITE;

    if (moduleBaseAddress != 0) {
        address1 = (LPVOID)(moduleBaseAddress + 0x1A7F7D);
    }

    ////////////////// PATCHES GO HERE ///////////////

    if (address1 == nullptr) {
        return false;
    }

    if (!VirtualProtect(address1, strlen(newBytes1), newProtect, &oldProtect)) {
        return false;
    }

    if (!WriteProcessMemory(hProcess, address1, newBytes1, strlen(newBytes1), &numberOfBytesWritten)) {
        return false;
    }

    if (!VirtualProtect(address1, strlen(newBytes1), oldProtect, &newProtect)) {
        return false;
    }
    return true;
}
bool InfiniteTimerPatch(HANDLE hProcess, uintptr_t moduleBaseAddress) {
    const char* newBytes1 = "\xFF\xFF";

    LPVOID address1 = nullptr;
    SIZE_T numberOfBytesWritten;
    DWORD oldProtect;
    DWORD newProtect = PAGE_EXECUTE_READWRITE;

    if (moduleBaseAddress != 0) {
        address1 = (LPVOID)(moduleBaseAddress + 0x1193B52);
    }

    ////////////////// PATCHES GO HERE ///////////////

    if (address1 == nullptr) {
        return false;
    }

    if (!VirtualProtect(address1, strlen(newBytes1), newProtect, &oldProtect)) {
        return false;
    }

    if (!WriteProcessMemory(hProcess, address1, newBytes1, strlen(newBytes1), &numberOfBytesWritten)) {
        return false;
    }

    if (!VirtualProtect(address1, strlen(newBytes1), oldProtect, &newProtect)) {
        return false;
    }
    return true;
}