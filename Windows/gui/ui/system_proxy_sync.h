#ifndef PB_SYSTEM_PROXY_SYNC_H
#define PB_SYSTEM_PROXY_SYNC_H

static BOOL ReadSystemProxy(PBSystemProxy* value)
{
    *value = PB_QuerySystemProxy();
    return value->status == PB_SYSTEM_PROXY_OK;
}

static const wchar_t* SystemProxyStatusText(PBSystemProxyStatus status)
{
    switch (status)
    {
    case PB_SYSTEM_PROXY_DISABLED:    return L"Windows system proxy is disabled.";
    case PB_SYSTEM_PROXY_PAC_ONLY:    return L"Windows system proxy uses PAC/auto-detect; a single endpoint is required.";
    case PB_SYSTEM_PROXY_UNSUPPORTED: return L"Windows system proxy has no supported HTTP/HTTPS endpoint.";
    case PB_SYSTEM_PROXY_INVALID:     return L"Windows system proxy address is invalid.";
    default:                          return L"Could not read the Windows system proxy.";
    }
}

static void LogSystemProxyStatus(const PBSystemProxy* value)
{
    if (value->status == PB_SYSTEM_PROXY_OK)
    {
        wchar_t line[384];
        _snwprintf_s(line, ARRAYSIZE(line), _TRUNCATE,
                     L"[system proxy] Using HTTP proxy %s:%u.\r\n", value->host, value->port);
        LogStoreAdd(&g_actStore, line);
    }
    else
    {
        wchar_t line[512];
        if (value->error)
            _snwprintf_s(line, ARRAYSIZE(line), _TRUNCATE,
                         L"[system proxy] %s (error %lu)\r\n",
                         SystemProxyStatusText(value->status), value->error);
        else
            _snwprintf_s(line, ARRAYSIZE(line), _TRUNCATE,
                         L"[system proxy] %s\r\n", SystemProxyStatusText(value->status));
        LogStoreAdd(&g_actStore, line);
    }
}

static BOOL ConfigChainContains(UINT32 currentStoredId, UINT32 targetStoredId, int depth)
{
    if (currentStoredId == 0 || depth > 4) return FALSE;
    if (currentStoredId == targetStoredId) return TRUE;
    PBConfig* c = FindStoredConfig(currentStoredId);
    if (!c || c->upstreamStoredId == 0) return FALSE;
    return ConfigChainContains(c->upstreamStoredId, targetStoredId, depth + 1);
}

static BOOL RuleReferencesConfig(const PBRule* r, UINT32 storedId)
{
    UINT32 target = r->cfgStoredId;
    if (target == 0 && g_profile.cfgCount > 0)
        target = g_profile.cfg[0].storedId;
    return ConfigChainContains(target, storedId, 0);
}

static void DisableSystemProxyRules(UINT32 storedId)
{
    for (int i = 0; i < g_profile.ruleCount; i++)
    {
        PBRule* r = &g_profile.rule[i];
        if (r->nativeId && r->enabled && _wcsicmp(r->action, L"PROXY") == 0 &&
            RuleReferencesConfig(r, storedId))
            g_api.DisableRule(r->nativeId);
    }
}

static void EnableSystemProxyRules(UINT32 storedId)
{
    for (int i = 0; i < g_profile.ruleCount; i++)
    {
        PBRule* r = &g_profile.rule[i];
        if (r->nativeId && r->enabled && _wcsicmp(r->action, L"PROXY") == 0 &&
            RuleReferencesConfig(r, storedId))
            g_api.EnableRule(r->nativeId);
    }
}

static BOOL RebindSystemProxyRules(UINT32 storedId, UINT32 nativeId)
{
    BOOL rebound = TRUE;
    for (int i = 0; i < g_profile.ruleCount; i++)
    {
        PBRule* r = &g_profile.rule[i];
        if (!r->nativeId || _wcsicmp(r->action, L"PROXY") != 0 ||
            !RuleReferencesConfig(r, storedId))
            continue;

        char proc[2048], hosts[512], ports[256], domains[512];
        W2Ux(r->proc, proc, sizeof(proc));
        W2Ux(r->hosts, hosts, sizeof(hosts));
        W2Ux(r->ports, ports, sizeof(ports));
        W2Ux(r->domains, domains, sizeof(domains));
        if (!g_api.EditRule(r->nativeId, proc, hosts, ports, domains,
                            (PBRuleProtocol)ProtoIdx(r->proto),
                            (PBRuleAction)ActionIdx(r->action), nativeId))
            rebound = FALSE;
    }
    return rebound;
}

static void SyncSystemProxy(void)
{
    BOOL hasSystemConfig = FALSE;
    for (int i = 0; i < g_profile.cfgCount; i++)
        if (g_profile.cfg[i].systemProxy) { hasSystemConfig = TRUE; break; }
    if (!hasSystemConfig)
    {
        g_systemProxyKnown = FALSE;
        g_systemProxyApplied = FALSE;
        return;
    }

    PBSystemProxy current;
    BOOL valid = ReadSystemProxy(&current);
    BOOL changed = !g_systemProxyKnown || current.status != g_systemProxy.status ||
                   current.error != g_systemProxy.error ||
                   (valid && (_wcsicmp(current.host, g_systemProxy.host) != 0 ||
                              current.port != g_systemProxy.port));
    if (!changed && (!valid || g_systemProxyApplied)) return;

    if (changed) LogSystemProxyStatus(&current);
    g_systemProxy = current;
    g_systemProxyKnown = TRUE;
    g_systemProxyApplied = valid;

    for (int i = 0; i < g_profile.cfgCount; i++)
    {
        PBConfig* c = &g_profile.cfg[i];
        if (!c->systemProxy) continue;

        if (!valid)
        {
            DisableSystemProxyRules(c->storedId);
            continue;
        }

        lstrcpynW(c->type, L"HTTP", ARRAYSIZE(c->type));
        lstrcpynW(c->host, current.host, ARRAYSIZE(c->host));
        _snwprintf_s(c->port, ARRAYSIZE(c->port), _TRUNCATE, L"%u", current.port);

        char host[256]; W2Ux(current.host, host, sizeof(host));
        BOOL applied = FALSE;
        BOOL hadNativeConfig = c->nativeId != 0;
        if (c->nativeId)
            applied = g_api.EditProxyConfig(c->nativeId, PB_PROXY_HTTP, host, current.port,
                                            "", "", c->sendDomain ? TRUE : FALSE);
        else
        {
            c->nativeId = g_api.AddProxyConfig(PB_PROXY_HTTP, host, current.port,
                                                "", "", c->sendDomain ? TRUE : FALSE);
            if (c->storedId == 0) c->storedId = c->nativeId;
            applied = c->nativeId != 0;
        }

        if (applied && !hadNativeConfig)
        {
            if (!RebindSystemProxyRules(c->storedId, c->nativeId))
                applied = FALSE;
            else if (g_api.SetProxyUpstream)
            {
                for (int j = 0; j < g_profile.cfgCount; j++)
                {
                    PBConfig* sub = &g_profile.cfg[j];
                    if (sub->nativeId && sub->upstreamStoredId == c->storedId)
                        g_api.SetProxyUpstream(sub->nativeId, c->nativeId);
                }
            }
        }
        if (!applied) g_systemProxyApplied = FALSE;
    }

    // Treat the shared endpoint as unavailable until every system-proxy config has
    // been updated. This prevents one failed config from being re-enabled while
    // the global availability guard is still false.
    if (!g_systemProxyApplied)
    {
        for (int i = 0; i < g_profile.cfgCount; i++)
            if (g_profile.cfg[i].systemProxy)
                DisableSystemProxyRules(g_profile.cfg[i].storedId);
    }
    else
    {
        for (int i = 0; i < g_profile.cfgCount; i++)
            if (g_profile.cfg[i].systemProxy)
                EnableSystemProxyRules(g_profile.cfg[i].storedId);
    }
}

#endif // PB_SYSTEM_PROXY_SYNC_H
