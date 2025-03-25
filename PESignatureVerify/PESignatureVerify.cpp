#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include<windows.h>
#include<wintrust.h>
#include<stdio.h>
#include<io.h>
#include<fcntl.h>
#include<stdlib.h>
#include<locale.h>
#include <Softpub.h>


#pragma warning(disable: 4996)
#define SIZEOF_WIN_CERTIFICATE_HDR 8
#pragma comment (lib, "wintrust")


DWORD Parse(FILE* fin);
int ParseDOSHeader(FILE* fin);
DWORD ParseNTHeader(FILE* fin);
DWORD ParseDataDirectory(FILE* fin, PIMAGE_DATA_DIRECTORY DataDir);
DWORD ParseAuthenticodeSignature(FILE* fin);
int ExtractToFile(FILE* fin, FILE* fout, DWORD Size);
int VerifySignature(LPCWSTR filename);

int wmain(int argc, wchar_t* argv[])
{
    FILE* fin, * fout;
    DWORD Size;
    int retval;

    _wsetlocale(LC_ALL, L"");

    if (argc != 3)
    {
        fwprintf(stderr,
            L"usage: extract-authenticode [input output]\n\n"
            L"  input:  Authenticode signed PE format filename.\n"
            L"          (e.g. .exe, .dll, etc.)\n"
            L"  output: PKCS#7 signed data filename.\n");
        return 1;
    }

    fin = _wfopen(argv[1], L"rb");
    if (!fin)
    {
        fwprintf(stderr, L"input file %s open failed: %s\n", argv[1],
            _wcserror(errno));
        return 1;
    }

    Size = Parse(fin);
    if (!Size)
    {
        fclose(fin);
        return 1;
    }

	fout = _wfopen(argv[2], L"wb");

    retval = ExtractToFile(fin, fout, Size);

    fclose(fout);
    fclose(fin);

    return VerifySignature(argv[1]);
}

DWORD Parse(FILE* fin)
{
    DWORD Size, Length;

    if (ParseDOSHeader(fin))
    {
        return 0;
    }

    Size = ParseNTHeader(fin);

    if (Size)
    {
        Length = ParseAuthenticodeSignature(fin);
        if (Size > Length)
        {
            return Length;
        }
        else
        {
            return 0;
        }
    }
    return 0;
}

int ParseDOSHeader(FILE* fin)
{
    IMAGE_DOS_HEADER DOSHeader;
    size_t ReadCount;
    fpos_t Position;
    int retval;

    ReadCount = fread(&DOSHeader, sizeof(DOSHeader), 1, fin);
    if (ReadCount < 0)
    {
        _wperror(L"fread IMAGE_DOS_HEADER failed");
        return 1;
    }
    else if (ReadCount == 0)
    {
        wprintf(L"fread IMAGE_DOS_HEADER failed: EOF\n");
        return 1;
    }

    if (DOSHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        wprintf(L"IMAGE_DOS_HEADER e_magic = unknown (0x%04x)\n",
            DOSHeader.e_magic);
        return 1;
    }

    wprintf(L"IMAGE_DOS_HEADER e_lfanew = 0x%08x\n", DOSHeader.e_lfanew);

    Position = DOSHeader.e_lfanew;
    retval = fsetpos(fin, &Position);
    if (retval != 0)
    {
        _wperror(L"fsetpos IMAGE_DOS_HEADER e_lfanew failed");
        return 1;
    }
    return 0;
}

DWORD ParseNTHeader(FILE* fin)
{
    union
    {
        IMAGE_NT_HEADERS32 NTHeaders32;
        IMAGE_NT_HEADERS64 NTHeaders64;
    } NTHeaders;
    size_t ReadCount;

    ReadCount = fread(&NTHeaders, sizeof(NTHeaders), 1, fin);
    if (ReadCount < 0)
    {
        _wperror(L"fread IMAGE_NT_HEADERS failed");
        return 0;
    }
    else if (ReadCount == 0)
    {
        wprintf(L"fread IMAGE_NT_HEADER failed: EOF\n");
        return 0;
    }

    if (NTHeaders.NTHeaders32.Signature != IMAGE_NT_SIGNATURE)
    {
        wprintf(L"IMAGE_NT_HEADERS Signature = unknown (0x%08x)\n",
            NTHeaders.NTHeaders32.Signature);
        return 0;
    }

    if (NTHeaders.NTHeaders32.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        wprintf(L"IMAGE_FILE_HEADER Machine = IMAGE_FILE_MACHINE_I386\n");
    }
    else if (NTHeaders.NTHeaders64.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        wprintf(L"IMAGE_FILE_HEADER Machine = IMAGE_FILE_MACHINE_AMD64\n");
    }
    else
    {
        wprintf(L"IMAGE_FILE_HEADER Machine = unknown (0x%04x)\n",
            NTHeaders.NTHeaders32.FileHeader.Machine);
    }

    if (NTHeaders.NTHeaders32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        wprintf(L"IMAGE_OPTIONAL_HEADER32 Magic found.\n");
        return ParseDataDirectory(fin, NTHeaders.NTHeaders32.OptionalHeader.DataDirectory);
    }
    else if (NTHeaders.NTHeaders64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        wprintf(L"IMAGE_OPTIONAL_HEADER64 Magic found.\n");
        return ParseDataDirectory(fin, NTHeaders.NTHeaders64.OptionalHeader.DataDirectory);
    }

    wprintf(L"IMAGE_OPTIONAL_HEADER Magic = unknown (0x%04x)\n",
        NTHeaders.NTHeaders32.OptionalHeader.Magic);
    return 0;
}

DWORD ParseDataDirectory(FILE* fin, PIMAGE_DATA_DIRECTORY DataDir)
{
    fpos_t Position;
    DWORD Size;
    int retval;

    Position = DataDir[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    Size = DataDir[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

    wprintf(L"IMAGE_DIRECTORY_ENTRY_SECURITY VirtualAddress = 0x%08x\n",
        Position);
    wprintf(L"IMAGE_DIRECTORY_ENTRY_SECURITY Size = 0x%08x\n",
        Size);

    if (Position && Size)
    {
        retval = fsetpos(fin, &Position);
        if (retval != 0)
        {
            _wperror(L"fsetpos IMAGE_DIRECTORY_ENTRY_SECURITY "
                L"VirtualAddress failed");
            return 0;
        }
        return Size;
    }
    wprintf(L"WIN_CERTIFICATE not found.\n");
    return 0;
}

DWORD ParseAuthenticodeSignature(FILE* fin)
{
    size_t ReadCount;
    WIN_CERTIFICATE WinCert;

    ReadCount = fread(&WinCert, SIZEOF_WIN_CERTIFICATE_HDR, 1, fin);
    if (ReadCount < 0)
    {
        _wperror(L"fread WIN_CERTIFICATE failed");
        return 0;
    }
    else if (ReadCount == 0)
    {
        wprintf(L"fread WIN_CERTIFICATE failed: EOF\n");
        return 0;
    }

    wprintf(L"WIN_CERTIFICATE dwLength = 0x%08x\n", WinCert.dwLength);

    switch (WinCert.wRevision)
    {
    case WIN_CERT_REVISION_1_0:
        wprintf(L"WIN_CERTIFICATE wRevision = WIN_CERT_REVISION_1_0\n");
        break;
    case WIN_CERT_REVISION_2_0:
        wprintf(L"WIN_CERTIFICATE wRevision = WIN_CERT_REVISION_2_0\n");
        break;
    default:
        wprintf(L"WIN_CERTIFICATE wRevision = unknown (0x%04x)\n",
            WinCert.wRevision);
        break;
    }

    if (WinCert.wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA)
    {
        wprintf(L"WIN_CERTIFICATE wCertificateType = "
            L"WIN_CERT_TYPE_PKCS_SIGNED_DATA\n");
    }
    else
    {
        wprintf(L"WIN_CERTIFICATE wCertificateType = unknown (0x%04x)\n",
            WinCert.wCertificateType);
    }

    return WinCert.dwLength - SIZEOF_WIN_CERTIFICATE_HDR;
}

int ExtractToFile(FILE* fin, FILE* fout, DWORD Size)
{
    unsigned char* Buf;
    size_t Count;

    Buf = (unsigned char*)malloc(Size);
    if (!Buf)
    {
        _wperror(L"malloc failed");
        return 1;
    }

    Count = fread(Buf, Size, 1, fin);
    if (Count < 0)
    {
        _wperror(L"fread WIN_CERTIFICATE bCertificate failed");
        free(Buf);
        return 1;
    }
    else if (Count == 0)
    {
        wprintf(L"fread WIN_CERTIFICATE bCertificate failed: EOF\n");
        free(Buf);
        return 1;
    }

    Count = fwrite(Buf, Size, 1, fout);
    if (Count < 0)
    {
        _wperror(L"fwrite pkcs#7 failed");
        free(Buf);
        return 1;
    }
    else if (Count == 0)
    {
        wprintf(L"fwrite pkcs#7 failed: EOF\n");
        free(Buf);
        return 1;
    }

    free(Buf);
    return 0;
}

int VerifySignature(LPCWSTR filename)
{
    WINTRUST_FILE_INFO FileInfo = { 0 };
    WINTRUST_DATA WinTrustData = { 0 };
    GUID ActionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG lStatus;
    DWORD dwLastError;

    FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileInfo.pcwszFilePath = filename;

    WinTrustData.cbStruct = sizeof(WINTRUST_DATA);
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.pFile = &FileInfo;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.dwProvFlags = WTD_SAFER_FLAG;

    lStatus = WinVerifyTrust(NULL, &ActionGUID, &WinTrustData);

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &ActionGUID, &WinTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:

        wprintf(L"The file \"%s\" is signed and the signature "
            L"was verified.\n",
            filename);
        break;

    case TRUST_E_NOSIGNATURE:

        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            wprintf(L"The file \"%s\" is not signed.\n",
                filename);
        }
        else
        {
            wprintf(L"An unknown error occurred trying to "
                L"verify the signature of the \"%s\" file.\n",
                filename);
        }

        break;

    case TRUST_E_EXPLICIT_DISTRUST:
        wprintf(L"The signature is present, but specifically "
            L"disallowed.\n");
        break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:
        wprintf(L"The signature is present, but not "
            L"trusted.\n");
        break;

    case CRYPT_E_SECURITY_SETTINGS:

        wprintf(L"CRYPT_E_SECURITY_SETTINGS - The hash "
            L"representing the subject or the publisher wasn't "
            L"explicitly trusted by the admin and admin policy "
            L"has disabled user trust. No signature, publisher "
            L"or timestamp errors.\n");
        break;

    default:
        wprintf(L"Error is: 0x%x.\n",
            lStatus);
        break;
    }
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &ActionGUID,
        &WinTrustData);

    return true;
}

