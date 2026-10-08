#ifndef PB_SYSTEM_PROXY_H
#define PB_SYSTEM_PROXY_H

#include <windows.h>
#include <wchar.h>
#include <wctype.h>
#include <stdlib.h>

/* Read the current user's Internet Settings registry values directly.
   WinINet's INTERNET_OPTION_REFRESH + InternetQueryOption pair is racy in a
   long-lived process and can alternate between the previous and current
   endpoint. The registry values are what Windows Settings shows, and this
   module never modifies them or executes PAC. */

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

static BOOL PB_ReadRegistryString(HKEY key, const wchar_t* name, wchar_t* out, DWORD cch)
{
    if (cch == 0) return FALSE;
    out[0] = 0;
    DWORD type = 0;
    DWORD bytes = cch * sizeof(wchar_t);
    LONG rc = RegQueryValueExW(key, name, NULL, &type, (LPBYTE)out, &bytes);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        out[0] = 0;
        return FALSE;
    }
    out[cch - 1] = 0;
    return out[0] != 0;
}

// 读取当前用户的静态系统代理（ProxyEnable / ProxyServer）。不修改系统设置，也不执行 PAC。
static PBSystemProxy PB_QuerySystemProxy(void)
{
    PBSystemProxy result;
    ZeroMemory(&result, sizeof(result));
    result.status = PB_SYSTEM_PROXY_QUERY_FAILED;

    HKEY key = NULL;
    LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, KEY_QUERY_VALUE, &key);
    if (rc != ERROR_SUCCESS)
    {
        result.error = (DWORD)rc;
        return result;
    }

    DWORD proxyEnable = 0;
    DWORD enableSize = sizeof(proxyEnable);
    DWORD enableType = 0;
    if (RegQueryValueExW(key, L"ProxyEnable", NULL, &enableType,
                         (LPBYTE)&proxyEnable, &enableSize) != ERROR_SUCCESS ||
        enableType != REG_DWORD)
        proxyEnable = 0;

    wchar_t server[1024];
    BOOL haveServer = PB_ReadRegistryString(key, L"ProxyServer", server, ARRAYSIZE(server));

    wchar_t autoConfig[1024];
    BOOL havePac = PB_ReadRegistryString(key, L"AutoConfigURL", autoConfig, ARRAYSIZE(autoConfig));

    RegCloseKey(key);

    if (proxyEnable && haveServer)
        result.status = PB_ParseSystemProxyServer(server, result.host, ARRAYSIZE(result.host), &result.port);
    else
        result.status = havePac ? PB_SYSTEM_PROXY_PAC_ONLY : PB_SYSTEM_PROXY_DISABLED;

    return result;
}

#endif // PB_SYSTEM_PROXY_H
