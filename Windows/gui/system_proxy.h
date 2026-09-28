#ifndef PB_SYSTEM_PROXY_H
#define PB_SYSTEM_PROXY_H

#include <windows.h>
#include <wchar.h>
#include <wctype.h>
#include <stdlib.h>

#pragma comment(lib, "wininet.lib")

/* Keep WinINet declarations local: MinGW's wininet.h and winhttp.h expose
   incompatible declarations for several shared type names. */
typedef struct {
    DWORD dwOption;
    union {
        DWORD dwValue;
        LPWSTR pszValue;
        FILETIME ftValue;
    } Value;
} PBInternetPerConnOptionW;

typedef struct {
    DWORD dwSize;
    LPWSTR pszConnection;
    DWORD dwOptionCount;
    DWORD dwOptionError;
    PBInternetPerConnOptionW* pOptions;
} PBInternetPerConnOptionListW;

#define PB_INTERNET_PER_CONN_FLAGS          1
#define PB_INTERNET_PER_CONN_PROXY_SERVER   2
#define PB_INTERNET_PER_CONN_AUTOCONFIG_URL 4
#define PB_PROXY_TYPE_PROXY                0x00000002
#define PB_PROXY_TYPE_AUTO_PROXY_URL       0x00000004
#define PB_PROXY_TYPE_AUTO_DETECT          0x00000008
#define PB_INTERNET_OPTION_PER_CONNECTION_OPTION 75
#define PB_INTERNET_OPTION_REFRESH          37

typedef void* PBInternetHandle;

__declspec(dllimport) BOOL WINAPI InternetSetOptionW(
    PBInternetHandle hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
__declspec(dllimport) BOOL WINAPI InternetQueryOptionW(
    PBInternetHandle hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);

#pragma comment(linker, "/defaultlib:wininet.lib")

typedef enum {
    PB_SYSTEM_PROXY_OK = 0,
    PB_SYSTEM_PROXY_DISABLED,
    PB_SYSTEM_PROXY_PAC_ONLY,
    PB_SYSTEM_PROXY_UNSUPPORTED,
    PB_SYSTEM_PROXY_INVALID,
    PB_SYSTEM_PROXY_QUERY_FAILED
} PBSystemProxyStatus;

typedef struct {
    PBSystemProxyStatus status;
    wchar_t host[256];
    unsigned short port;
    DWORD error;
} PBSystemProxy;

static wchar_t* PB_SystemProxyTrim(wchar_t* text)
{
    while (*text && iswspace(*text)) text++;
    wchar_t* end = text + wcslen(text);
    while (end > text && iswspace(end[-1])) *--end = 0;
    return text;
}

static BOOL PB_ParseSystemProxyEndpoint(const wchar_t* value, wchar_t* host, int hostCount,
                                        unsigned short* port)
{
    wchar_t endpoint[512];
    lstrcpynW(endpoint, value ? value : L"", ARRAYSIZE(endpoint));
    wchar_t* text = PB_SystemProxyTrim(endpoint);

    if (_wcsnicmp(text, L"http://", 7) == 0) text += 7;
    else if (_wcsnicmp(text, L"https://", 8) == 0) text += 8;
    else if (wcsstr(text, L"://") != NULL) return FALSE;

    text = PB_SystemProxyTrim(text);
    size_t textLength = wcslen(text);
    while (textLength > 0 && text[textLength - 1] == L'/')
        text[--textLength] = 0;
    if (!*text || *text == L'[' || wcspbrk(text, L"\\?#@") != NULL) return FALSE;

    wchar_t* colon = wcsrchr(text, L':');
    if (!colon || colon == text || wcschr(text, L':') != colon) return FALSE;
    *colon++ = 0;

    wchar_t* hostText = PB_SystemProxyTrim(text);
    wchar_t* portText = PB_SystemProxyTrim(colon);
    if (!*hostText || !*portText || (int)wcslen(hostText) >= hostCount) return FALSE;

    wchar_t* end = NULL;
    unsigned long parsedPort = wcstoul(portText, &end, 10);
    while (end && *end && iswspace(*end)) end++;
    if (!end || *end || parsedPort == 0 || parsedPort > 65535) return FALSE;

    lstrcpynW(host, hostText, hostCount);
    *port = (unsigned short)parsedPort;
    return TRUE;
}

static PBSystemProxyStatus PB_ParseSystemProxyServer(const wchar_t* server,
                                                      wchar_t* host, int hostCount,
                                                      unsigned short* port)
{
    wchar_t work[1024];
    wchar_t direct[512] = L"";
    wchar_t http[512] = L"";
    wchar_t https[512] = L"";
    BOOL sawUnsupported = FALSE;

    lstrcpynW(work, server ? server : L"", ARRAYSIZE(work));
    wchar_t* context = NULL;
    for (wchar_t* token = wcstok_s(work, L"; \t\r\n", &context); token;
         token = wcstok_s(NULL, L"; \t\r\n", &context))
    {
        token = PB_SystemProxyTrim(token);
        if (!*token) continue;

        wchar_t* equal = wcschr(token, L'=');
        if (!equal)
        {
            if (!direct[0]) lstrcpynW(direct, token, ARRAYSIZE(direct));
            continue;
        }

        *equal++ = 0;
        wchar_t* key = PB_SystemProxyTrim(token);
        wchar_t* value = PB_SystemProxyTrim(equal);
        if (_wcsicmp(key, L"http") == 0)
            lstrcpynW(http, value, ARRAYSIZE(http));
        else if (_wcsicmp(key, L"https") == 0)
            lstrcpynW(https, value, ARRAYSIZE(https));
        else if (_wcsicmp(key, L"socks") == 0 || _wcsicmp(key, L"socks5") == 0)
            sawUnsupported = TRUE;
    }

    const wchar_t* selected = http[0] ? http : (https[0] ? https : direct);
    if (!selected[0]) return sawUnsupported ? PB_SYSTEM_PROXY_UNSUPPORTED : PB_SYSTEM_PROXY_INVALID;
    return PB_ParseSystemProxyEndpoint(selected, host, hostCount, port)
        ? PB_SYSTEM_PROXY_OK : PB_SYSTEM_PROXY_INVALID;
}

static void PB_FreeSystemProxyOption(PBInternetPerConnOptionW* option)
{
    if (option->Value.pszValue)
    {
        GlobalFree((HGLOBAL)option->Value.pszValue);
        option->Value.pszValue = NULL;
    }
}

// 读取当前用户的 WinINet/LAN 静态代理；本模块不会修改系统设置，也不执行 PAC。
static PBSystemProxy PB_QuerySystemProxy(void)
{
    PBSystemProxy result;
    ZeroMemory(&result, sizeof(result));
    result.status = PB_SYSTEM_PROXY_QUERY_FAILED;

    PBInternetPerConnOptionW options[3];
    ZeroMemory(options, sizeof(options));
    options[0].dwOption = PB_INTERNET_PER_CONN_FLAGS;
    options[1].dwOption = PB_INTERNET_PER_CONN_PROXY_SERVER;
    options[2].dwOption = PB_INTERNET_PER_CONN_AUTOCONFIG_URL;

    PBInternetPerConnOptionListW list;
    ZeroMemory(&list, sizeof(list));
    list.dwSize = sizeof(list);
    list.pszConnection = NULL;
    list.dwOptionCount = ARRAYSIZE(options);
    list.pOptions = options;

    DWORD size = sizeof(list);
    // WinINet may cache connection options in a long-lived process. Refresh its
    // cache before reading; this does not change the user's proxy settings.
    InternetSetOptionW(NULL, PB_INTERNET_OPTION_REFRESH, NULL, 0);
    BOOL ok = InternetQueryOptionW(NULL, PB_INTERNET_OPTION_PER_CONNECTION_OPTION,
                                   &list, &size);
    if (!ok)
    {
        result.error = GetLastError();
        PB_FreeSystemProxyOption(&options[1]);
        PB_FreeSystemProxyOption(&options[2]);
        return result;
    }

    DWORD flags = options[0].Value.dwValue;
    const wchar_t* server = options[1].Value.pszValue;
    BOOL hasPac = (flags & (PB_PROXY_TYPE_AUTO_PROXY_URL | PB_PROXY_TYPE_AUTO_DETECT)) != 0;

    if ((flags & PB_PROXY_TYPE_PROXY) != 0 && server && server[0])
        result.status = PB_ParseSystemProxyServer(server, result.host, ARRAYSIZE(result.host), &result.port);
    else
        result.status = hasPac ? PB_SYSTEM_PROXY_PAC_ONLY : PB_SYSTEM_PROXY_DISABLED;

    PB_FreeSystemProxyOption(&options[1]);
    PB_FreeSystemProxyOption(&options[2]);
    return result;
}

#endif // PB_SYSTEM_PROXY_H

// The full WinINet declarations are intentionally not included here: MinGW's
// wininet.h conflicts with the winhttp.h used by the update checker.
