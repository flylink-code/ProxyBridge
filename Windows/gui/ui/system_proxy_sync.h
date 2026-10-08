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
                     L"[system proxy] Using %s:%u.\r\n", value->host, value->port);
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

// A new endpoint is applied only after two identical polls. One mismatched or
// failed read must not rewrite the live port or disable rules that are already
// using the last confirmed system proxy.
static PBSystemProxy g_systemProxyPending;
static BOOL          g_systemProxyPendingSeen = FALSE;
static int           g_systemProxyPendingHits = 0;

static BOOL SystemProxySame(const PBSystemProxy* a, const PBSystemProxy* b)
{
    if (a->status != b->status) return FALSE;
    if (a->status != PB_SYSTEM_PROXY_OK) return TRUE;
    return a->port == b->port && _wcsicmp(a->host, b->host) == 0;
}

static void ClearSystemProxyPending(void)
{
    g_systemProxyPendingSeen = FALSE;
    g_systemProxyPendingHits = 0;
    ZeroMemory(&g_systemProxyPending, sizeof(g_systemProxyPending));
}

static BOOL SystemProxyConfirmed(const PBSystemProxy* current)
{
    if (!g_systemProxyPendingSeen || !SystemProxySame(&g_systemProxyPending, current))
    {
        g_systemProxyPending = *current;
        g_systemProxyPendingSeen = TRUE;
        g_systemProxyPendingHits = 1;
        return FALSE;
    }
    if (g_systemProxyPendingHits < 2)
        g_systemProxyPendingHits++;
    return g_systemProxyPendingHits >= 2;
}

static void SetSystemProxyRuleState(BOOL enable)
{
    for (int i = 0; i < g_profile.cfgCount; i++)
        if (g_profile.cfg[i].systemProxy)
        {
            if (enable) EnableSystemProxyRules(g_profile.cfg[i].storedId);
            else        DisableSystemProxyRules(g_profile.cfg[i].storedId);
        }
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
        ClearSystemProxyPending();
        return;
    }

    PBSystemProxy current;
    ReadSystemProxy(&current);
    if (!SystemProxyConfirmed(&current))
        return;

    // A failed registry read is not "proxy off". Keep the last confirmed endpoint.
    if (current.status == PB_SYSTEM_PROXY_QUERY_FAILED)
        return;

    BOOL valid = (current.status == PB_SYSTEM_PROXY_OK);
    BOOL endpointChanged = !g_systemProxyKnown || !SystemProxySame(&current, &g_systemProxy);
    BOOL availabilityChanged = !g_systemProxyKnown || (valid != (g_systemProxyApplied != FALSE));
    if (!endpointChanged && !availabilityChanged)
        return;

    if (endpointChanged) LogSystemProxyStatus(&current);
    BOOL wasApplied = g_systemProxyApplied;
    g_systemProxy = current;
    g_systemProxyKnown = TRUE;

    if (!valid)
    {
        g_systemProxyApplied = FALSE;
        if (availabilityChanged)
            SetSystemProxyRuleState(FALSE);
        return;
    }

    BOOL allApplied = TRUE;
    for (int i = 0; i < g_profile.cfgCount; i++)
    {
        PBConfig* c = &g_profile.cfg[i];
        if (!c->systemProxy) continue;

        if (!c->type[0])
            lstrcpynW(c->type, L"HTTP", ARRAYSIZE(c->type));
        lstrcpynW(c->host, current.host, ARRAYSIZE(c->host));
        _snwprintf_s(c->port, ARRAYSIZE(c->port), _TRUNCATE, L"%u", current.port);

        char host[256]; W2Ux(current.host, host, sizeof(host));
        PBProxyType pt = PB_TypeFromText(c->type);
        BOOL applied = FALSE;
        BOOL hadNativeConfig = c->nativeId != 0;
        if (c->nativeId)
            applied = g_api.EditProxyConfig(c->nativeId, pt, host, current.port,
                                            "", "", c->sendDomain ? TRUE : FALSE);
        else
        {
            c->nativeId = g_api.AddProxyConfig(pt, host, current.port,
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
                if (c->upstreamStoredId)
                {
                    UINT32 upNativeId = ResolveNativeCfg(c->upstreamStoredId);
                    g_api.SetProxyUpstream(c->nativeId, upNativeId);
                }
                for (int j = 0; j < g_profile.cfgCount; j++)
                {
                    PBConfig* sub = &g_profile.cfg[j];
                    if (sub->nativeId && sub->upstreamStoredId == c->storedId)
                        g_api.SetProxyUpstream(sub->nativeId, c->nativeId);
                }
            }
        }
        if (!applied) allApplied = FALSE;
    }

    g_systemProxyApplied = allApplied;

    // Toggle rules only when availability changes. A host/port update keeps the
    // same native config id, so matched apps stay on that config instead of
    // being disabled and reconnecting against the next port the poll happens to see.
    if (wasApplied && !g_systemProxyApplied)
        SetSystemProxyRuleState(FALSE);
    else if (!wasApplied && g_systemProxyApplied)
        SetSystemProxyRuleState(TRUE);
}

#endif // PB_SYSTEM_PROXY_SYNC_H
