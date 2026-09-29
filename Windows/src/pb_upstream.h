#ifndef PB_UPSTREAM_H
#define PB_UPSTREAM_H

#include "pb_internal.h"

#define MAX_PROXY_CHAIN_DEPTH 4

#if defined(__GNUC__)
static __thread char g_last_upstream_error[256] = {0};
#else
static __declspec(thread) char g_last_upstream_error[256] = {0};
#endif

static void pb_set_upstream_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(g_last_upstream_error, sizeof(g_last_upstream_error), _TRUNCATE, fmt, ap);
    va_end(ap);
}

static PB_FORCEINLINE const char* pb_get_last_upstream_error(void)
{
    return g_last_upstream_error;
}

// Helper: exact match find for upstream config lookup (no fallback)
static PB_FORCEINLINE const PROXY_CONFIG* pb_find_proxy_config_exact(UINT32 config_id)
{
    if (config_id == 0) return NULL;
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        if (g_proxy_configs[i].config_id == config_id)
            return &g_proxy_configs[i];
    }
    return NULL;
}

// Perform HTTP CONNECT tunnel handshake through an upstream HTTP proxy.
// Reads byte-by-byte to find "\r\n\r\n" to avoid buffering any downstream/target data.
static int pb_upstream_http_connect(SOCKET s, const char *target_host, UINT16 target_port, const PROXY_CONFIG *upstream)
{
    char request[1024];
    int req_len;
    BOOL use_auth = (upstream != NULL && upstream->username[0] != '\0');

    if (use_auth)
    {
        char credentials[512];
        char encoded[1024];
        _snprintf_s(credentials, sizeof(credentials), _TRUNCATE, "%s:%s", upstream->username, upstream->password);
        base64_encode(credentials, encoded, sizeof(encoded));

        req_len = _snprintf_s(request, sizeof(request), _TRUNCATE,
            "CONNECT %s:%u HTTP/1.1\r\n"
            "Host: %s:%u\r\n"
            "Proxy-Authorization: Basic %s\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            target_host, target_port, target_host, target_port, encoded);
    }
    else
    {
        req_len = _snprintf_s(request, sizeof(request), _TRUNCATE,
            "CONNECT %s:%u HTTP/1.1\r\n"
            "Host: %s:%u\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            target_host, target_port, target_host, target_port);
    }

    if (req_len <= 0 || send_all(s, request, req_len) != req_len)
    {
        pb_set_upstream_error("Failed to send CONNECT request to upstream %s:%u", upstream->host, upstream->port);
        log_message("[UPSTREAM] Failed to send CONNECT to upstream %s:%u", upstream->host, upstream->port);
        return -1;
    }

    char status_line[128] = {0};
    int status_pos = 0;
    int state = 0; // 0: init, 1: \r, 2: \r\n, 3: \r\n\r, 4: \r\n\r\n
    int total_read = 0;
    const int MAX_HEADER_SIZE = 8192;

    while (total_read < MAX_HEADER_SIZE)
    {
        char ch;
        int n = recv(s, &ch, 1, 0);
        if (n <= 0)
        {
            pb_set_upstream_error("Upstream %s:%u closed connection while waiting for CONNECT response", upstream->host, upstream->port);
            log_message("[UPSTREAM] Failed to receive CONNECT response from upstream %s:%u", upstream->host, upstream->port);
            return -1;
        }
        total_read++;

        if (state < 2 && status_pos < (int)(sizeof(status_line) - 1))
        {
            if (ch != '\r' && ch != '\n')
                status_line[status_pos++] = ch;
        }

        if (state == 0 && ch == '\r') state = 1;
        else if (state == 1 && ch == '\n') state = 2;
        else if (state == 2 && ch == '\r') state = 3;
        else if (state == 3 && ch == '\n') {
            state = 4;
            break;
        }
        else if (ch == '\r') state = 1;
        else state = 0;
    }

    if (state != 4)
    {
        pb_set_upstream_error("Upstream %s:%u returned invalid HTTP header", upstream->host, upstream->port);
        log_message("[UPSTREAM] Header too large or invalid from %s:%u", upstream->host, upstream->port);
        return -1;
    }

    status_line[status_pos] = '\0';
    const char *sp = strchr(status_line, ' ');
    if (!sp || atoi(sp + 1) != 200)
    {
        pb_set_upstream_error("Upstream %s:%u rejected CONNECT (%s)", upstream->host, upstream->port, status_line);
        log_message("[UPSTREAM] CONNECT rejected by %s:%u: %s", upstream->host, upstream->port, status_line);
        return -1;
    }

    return 0;
}

// Recursively connects through the upstream chain up to MAX_PROXY_CHAIN_DEPTH
static SOCKET pb_connect_proxy_chain_internal(const PROXY_CONFIG *proxy, int depth)
{
    if (!proxy || depth > MAX_PROXY_CHAIN_DEPTH)
    {
        pb_set_upstream_error("Proxy chain depth limit reached or null proxy");
        log_message("[UPSTREAM] Chain depth exceeded limit (%d) or null proxy", depth);
        return INVALID_SOCKET;
    }

    const PROXY_CONFIG *upstream = pb_find_proxy_config_exact(proxy->upstream_config_id);
    if (!upstream)
    {
        // Direct connection to the target proxy
        UINT32 proxy_ip = proxy->resolved_ip ? proxy->resolved_ip : resolve_hostname(proxy->host);
        if (proxy_ip == 0)
        {
            pb_set_upstream_error("Could not resolve proxy host '%s'", proxy->host);
            return INVALID_SOCKET;
        }

        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET)
        {
            pb_set_upstream_error("Failed to create socket");
            return INVALID_SOCKET;
        }

        configure_tcp_socket(s, 4194304, 30000);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = proxy_ip;
        addr.sin_port = htons(proxy->port);

        if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
        {
            pb_set_upstream_error("Could not connect to proxy %s:%u (error %d)", proxy->host, proxy->port, WSAGetLastError());
            closesocket(s);
            return INVALID_SOCKET;
        }
        return s;
    }

    // Connect to the upstream proxy first
    SOCKET s = pb_connect_proxy_chain_internal(upstream, depth + 1);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    int rc = -1;
    if (upstream->type == PROXY_TYPE_HTTP)
        rc = pb_upstream_http_connect(s, proxy->host, proxy->port, upstream);
    else
    {
        rc = socks5_connect_domain(s, proxy->host, proxy->port, upstream);
        if (rc != 0)
            pb_set_upstream_error("Upstream SOCKS5 %s:%u handshake failed (code %d)", upstream->host, upstream->port, rc);
    }

    if (rc != 0)
    {
        log_message("[UPSTREAM] Handshake to target %s:%u via upstream %s:%u failed",
                    proxy->host, proxy->port, upstream->host, upstream->port);
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

// Public helper to establish a connected socket to the target proxy
static PB_FORCEINLINE SOCKET pb_connect_proxy_chain(const PROXY_CONFIG *proxy)
{
    g_last_upstream_error[0] = '\0';
    return pb_connect_proxy_chain_internal(proxy, 0);
}

#endif // PB_UPSTREAM_H
