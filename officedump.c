#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

DWORD getPID(char* processName)
{
    // Find the process ID of the Word.exe process
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("[!] Failed to create toolhelp snapshot\n");
        return -1;
    }

    BOOL bResult = Process32First(hSnapshot, &pe);
    while (bResult)
    {
        // printf("Searching process, %s\n", pe.szExeFile);
        if (_stricmp(pe.szExeFile, processName) == 0)
        {
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }

        bResult = Process32Next(hSnapshot, &pe);
    }

    CloseHandle(hSnapshot);
    printf("[!] Failed to find process %s\n", processName);
    return -1;
}

int word(DWORD pid) {
    // Open the handle to the Word.exe process
    HANDLE hExcel = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hExcel)
    {
        printf("[!] Failed to open handle to WINWORD.EXE process\n");
        return 1;
    } else {
        printf("[+] ====== Word Process ======\n");
    }

    // Find the address of the money signature in the Excel.exe process
    LPVOID pAddress = NULL;
    BYTE signature_1[] = { 0x09, 0x05, 0x00, 0x00 };
    BYTE signature_1_oldformat[] = { 0xC6, 0x00, 0x00, 0x00 }; //for doc format, the length is the same
    INT skipBytes = 8;
    BYTE signature_2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    MEMORY_BASIC_INFORMATION mbi = {0};

    while (VirtualQueryEx(hExcel, pAddress, &mbi, sizeof(mbi)))
    {
        // Check if this memory block is readable and has the money signature
        if ((mbi.Protect & PAGE_READWRITE) &&
            !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) && mbi.Type == MEM_PRIVATE)
        {
            // printf("Checking Region: 0x%llx\n", (unsigned long long)pAddress);
            LPVOID pBuffer = malloc(mbi.RegionSize);
            if (!pBuffer)
            {
                printf("Failed to allocate memory for buffer\n");
                CloseHandle(hExcel);
                return 1;
            }
            SIZE_T dwBytesRead = 0;
            //BOOL bFound = FALSE;
            if (ReadProcessMemory(hExcel, mbi.BaseAddress, pBuffer, mbi.RegionSize, &dwBytesRead))
            {
                // Search for the signature in the buffer
                LPBYTE pByteAddress = (LPBYTE)pBuffer;
                DWORD dwOffset = 0;
                while (dwOffset < mbi.RegionSize - sizeof(signature_1) - skipBytes -  sizeof(signature_2) - 0x8)
                {
                    if ((memcmp(pByteAddress + dwOffset, signature_1, sizeof(signature_1)) == 0 && memcmp(pByteAddress + dwOffset + sizeof(signature_1) + skipBytes, signature_2, sizeof(signature_2)) == 0) ||
                    (memcmp(pByteAddress + dwOffset, signature_1_oldformat, sizeof(signature_1_oldformat)) == 0 && memcmp(pByteAddress + dwOffset + sizeof(signature_1_oldformat) + skipBytes, signature_2, sizeof(signature_2)) == 0))
                    {
                        // Reverse the byte order of the 8 bytes after the signature
                        BYTE reversed[8] = {0};
                        memcpy(reversed, (BYTE*)pByteAddress + dwOffset + sizeof(signature_1) + skipBytes + sizeof(signature_2), sizeof(reversed));
                        _byteswap_uint64(*(unsigned long long*)reversed);
                        // Convert the reversed bytes to a pointer and add the offset
                        LPVOID pPointer = *(LPVOID*)reversed;

                        // Read the length of the data to be parsed
                        BYTE bLength = 0;
                        ReadProcessMemory(hExcel, (BYTE*)pPointer - 1, &bLength, sizeof(bLength), NULL);
                        //wLength = _byteswap_ushort(wLength);
                        bLength = 0x9e - bLength;
                        if (bLength >= 0x9e) {
                            dwOffset++;
                            continue;
                        }
                        // printf("Signature: 0x%llx\n", (unsigned long long)pAddress + dwOffset);
                        // printf("Pointer: 0x%llx\n", (unsigned long long)pPointer);
                        // printf("Length: %d\n", bLength);
                        // Read the data to be parsed
                        wchar_t* pData = (wchar_t*)malloc((bLength + 1) * sizeof(wchar_t));
                        memset(pData, 0, (bLength+1) * sizeof(wchar_t));
                        ReadProcessMemory(hExcel, pPointer, pData, bLength * sizeof(wchar_t), NULL);
                        //pData[wLength] = L'\0';

                        // Print the data as wchar_t
                        wprintf(L"[+] Found potential document password (len=%d): %ls\n", bLength, pData);
                        //bFound = TRUE;
                        free(pData);
                        //break;
                    }
                    dwOffset++;
                }
            }
            if (pBuffer)
                free(pBuffer);
            //if (bFound)
            //    break;
        }

        // Move to the next memory block
        pAddress = (BYTE*)pAddress + mbi.RegionSize;
    }

    // Close the handle to the Excel.exe process
    CloseHandle(hExcel);
    return 0;
}

int excel(DWORD pid)
{
    // Open the handle to the Excel.exe process
    HANDLE hExcel = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hExcel)
    {
        printf("[!] Failed to open handle to Excel.exe process\n");
        return 1;
    } else {
        printf("[+] ====== Excel Process ======\n");
    }

    // Find the address of the money signature in the Excel.exe process
    LPVOID pAddress = NULL;
    BYTE signature[] = { 0x8F, 0xD6, 0x75, 0x23, 0x05, 0xFF };
    MEMORY_BASIC_INFORMATION mbi = {0};

    while (VirtualQueryEx(hExcel, pAddress, &mbi, sizeof(mbi)))
    {
        // Check if this memory block is readable and has the money signature
        if ((mbi.Protect & PAGE_READWRITE) &&
            !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) && mbi.Type == MEM_PRIVATE)
        {
            // printf("Checking Region: 0x%llx\n", (unsigned long long)pAddress);
            LPVOID pBuffer = malloc(mbi.RegionSize);
            if (!pBuffer)
            {
                printf("[!] Failed to allocate memory for buffer\n");
                CloseHandle(hExcel);
                return 1;
            }
            SIZE_T dwBytesRead = 0;
            //BOOL bFound = FALSE;
            if (ReadProcessMemory(hExcel, mbi.BaseAddress, pBuffer, mbi.RegionSize, &dwBytesRead))
            {
                // Search for the signature in the buffer
                LPBYTE pByteAddress = (LPBYTE)pBuffer;
                DWORD dwOffset = 0;
                while (dwOffset < mbi.RegionSize - sizeof(signature) - 0x30)
                {
                    if (memcmp(pByteAddress + dwOffset, signature, sizeof(signature)) == 0)
                    {
                        // Reverse the byte order of the 8 bytes after the signature
                        // printf("Signature: 0x%llx\n", (unsigned long long)pAddress + dwOffset);
                        BYTE reversed[8] = {0};
                        memcpy(reversed, (BYTE*)pByteAddress + dwOffset + 0x30, sizeof(reversed));
                        _byteswap_uint64(*(unsigned long long*)reversed);
                        // Convert the reversed bytes to a pointer and add the offset
                        LPVOID pPointer = *(LPVOID*)reversed;
                        // printf("Pointer: 0x%llx\n", (unsigned long long)pPointer);

                        // Read the length of the data to be parsed
                        WORD wLength = 0;
                        ReadProcessMemory(hExcel, pPointer, &wLength, sizeof(wLength), NULL);
                        wchar_t* pData = (wchar_t*)malloc((wLength + 1) * sizeof(wchar_t));
                        memset(pData, 0, (wLength+1) * sizeof(wchar_t));
                        ReadProcessMemory(hExcel, (BYTE*)pPointer + sizeof(wLength), pData, wLength * sizeof(wchar_t), NULL);
                        //pData[wLength] = L'\0';

                        // Print the data as wchar_t
                        wprintf(L"[+] Found potential document password (len=%d): %ls\n", wLength, pData);
                        //bFound = TRUE;
                        free(pData);
                        //break;
                    }
                    dwOffset++;
                }
            }
            if (pBuffer)
                free(pBuffer);
            //if (bFound)
            //    break;
        }

        // Move to the next memory block
        pAddress = (BYTE*)pAddress + mbi.RegionSize;
    }

    // Close the handle to the Excel.exe process
    CloseHandle(hExcel);

    return 0;
}

int main(int argc, char *argv[]) {
    int check_excel = 0, check_word = 0;
    int excel_pid = 0, word_pid = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("-h : show this help message\n");
            printf("-e : check Excel\n");
            printf("-w : check Word\n");
            printf("-ep : specific PID for Excel\n");
            printf("-wp : specific PID for Word\n");
            exit(0);
        }
        else if (strcmp(argv[i], "-e") == 0) {
            check_excel = 1;
        }
        else if (strcmp(argv[i], "-w") == 0) {
            check_word = 1;
        }
        else if (strcmp(argv[i], "-ep") == 0) {
            if (i + 1 < argc) {
                excel_pid = atoi(argv[i+1]);
                i++;
            }
            else {
                printf("Error: Missing argument for -ep option.\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-wp") == 0) {
            if (i + 1 < argc) {
                word_pid = atoi(argv[i+1]);
                i++;
            }
            else {
                printf("Error: Missing argument for -wp option.\n");
                return 1;
            }
        }
        else {
            printf("Error: Invalid option %s.\n", argv[i]);
            return 1;
        }
    }

    if (!(check_excel || check_word)) {
        check_excel = 1;
        check_word = 1;
    }
    
    if (check_excel) {
        if (!excel_pid)
            excel_pid = getPID("EXCEL.EXE");
        if (excel_pid != -1)
            excel(excel_pid);
    }
    if (check_word) {
        if (!word_pid)
            word_pid = getPID("WINWORD.EXE");
        if (word_pid != -1)
            word(word_pid);
    }    
    return 0;
}