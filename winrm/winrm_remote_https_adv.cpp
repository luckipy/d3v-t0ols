#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WSMAN_API_VERSION_1_1
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <wincrypt.h>
#include <schnlsp.h>
#include <security.h>
#include <schannel.h>
#include <wsman.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <conio.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Wsmsvc.lib")
#pragma comment(lib, "Iphlpapi.lib")

/* ─── Constants ─────────────────────────────────────────────── */
#define DEFAULT_HTTP_PORT  5985
#define DEFAULT_HTTPS_PORT 5986
#define TCP_TIMEOUT_MS     5000
#define LOG_FILE           L"winrm_manager.log"
#define MAX_HOSTNAME       256
#define MAX_USERNAME       256
#define MAX_PASSWORD       256
#define MAX_COMMAND        4096
#define RECV_BUFSIZE       65536
#define SENTINEL_FMT       "**WRM*%lu*_"

/*
 * Registry key where WinRM client stores TrustedHosts.
 * This is the authoritative location — identical to what
 * "winrm get winrm/config/client" reads internally.
 */
#define WSMAN_CLIENT_REG_KEY \
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Client"
#define WSMAN_TRUSTED_HOSTS_VALUE L"TrustedHosts"

#ifndef WSMAN_OPTION_ALLOW_NEGOTIATE_IMPLICIT_CREDENTIALS
#define WSMAN_OPTION_ALLOW_NEGOTIATE_IMPLICIT_CREDENTIALS 23
#endif
#ifndef WSMAN_OPTION_UNENCRYPTED_MESSAGES
#define WSMAN_OPTION_UNENCRYPTED_MESSAGES 3
#endif

 /* ─── Console colors ─────────────────────────────────────────── */
#define COLOR_RESET   (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define COLOR_RED     (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define COLOR_GREEN   (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_YELLOW  (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_CYAN    (FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_WHITE   (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_MAGENTA (FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY)

static HANDLE  g_hCon = INVALID_HANDLE_VALUE;
static FILE* g_log = NULL;
static BOOL    g_wsaOk = FALSE;
static WSMAN_API_HANDLE g_api = NULL;
static DWORD   g_sentId = 1;

/* ═══════════════════════════════════════════════════════════════
   SECTION 1 — Logging
   ═══════════════════════════════════════════════════════════════ */

static void SetColor(WORD attr)
{
    if (g_hCon != INVALID_HANDLE_VALUE)
        SetConsoleTextAttribute(g_hCon, attr);
}

static void LogV(WORD col, const wchar_t* pfx, const wchar_t* fmt, va_list ap)
{
    wchar_t buf[4096];
    vswprintf_s(buf, _countof(buf), fmt, ap);
    SYSTEMTIME t; GetLocalTime(&t);
    SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
    wprintf(L"[%02d:%02d:%02d] ", t.wHour, t.wMinute, t.wSecond);
    SetColor(col); wprintf(L"%s%s\n", pfx, buf); SetColor(COLOR_RESET);
    if (g_log)
    {
        fwprintf(g_log, L"[%02d:%02d:%02d] %s%s\n",
            t.wHour, t.wMinute, t.wSecond, pfx, buf);
        fflush(g_log);
    }
}

#define MKLOG(fn, col, pfx) \
    static void fn(const wchar_t* f, ...) \
    { va_list a; va_start(a,f); LogV(col,pfx,f,a); va_end(a); }

MKLOG(LogInfo, COLOR_WHITE, L"      ")
MKLOG(LogOK, COLOR_GREEN, L"[OK]  ")
MKLOG(LogWarn, COLOR_YELLOW, L"[WARN]")
MKLOG(LogError, COLOR_RED, L"[ERR] ")
MKLOG(LogStep, COLOR_CYAN, L"[>>]  ")

static void PrintSep(void)
{
    SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    wprintf(L" -------------------------------------------------\n");
    SetColor(COLOR_RESET);
}

static void Banner(void)
{
    SetColor(COLOR_CYAN);
    wprintf(L"\n +===================================================+\n");
    wprintf(L" |  WinRM Manager v4.0  (Native WSMan / WsmSvc)      |\n");
    wprintf(L" |  No PowerShell  No winrs.exe  Pure WinAPI         |\n");
    wprintf(L" |  No process spawning  Registry + ICMP direct      |\n");
    wprintf(L" +===================================================+\n\n");
    SetColor(COLOR_RESET);
}

static void ReadLine(wchar_t* buf, int n, const wchar_t* prompt)
{
    SetColor(COLOR_YELLOW); wprintf(L" %s: ", prompt);
    SetColor(COLOR_WHITE); fflush(stdout);
    if (!fgetws(buf, n, stdin)) buf[0] = L'\0';
    size_t l = wcslen(buf);
    while (l > 0 && (buf[l - 1] == L'\n' || buf[l - 1] == L'\r')) buf[--l] = L'\0';
    SetColor(COLOR_RESET);
}

static void ReadPass(wchar_t* buf, int n)
{
    SetColor(COLOR_YELLOW); wprintf(L" Password: "); SetColor(COLOR_WHITE); fflush(stdout);
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE); DWORD mode = 0;
    GetConsoleMode(hIn, &mode);
    SetConsoleMode(hIn, (mode & ~ENABLE_ECHO_INPUT) | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
    DWORD rd = 0; ReadConsoleW(hIn, buf, (DWORD)(n - 1), &rd, NULL); buf[rd] = L'\0';
    SetConsoleMode(hIn, mode); SetColor(COLOR_RESET); wprintf(L"\n");
    size_t l = wcslen(buf);
    while (l > 0 && (buf[l - 1] == L'\n' || buf[l - 1] == L'\r')) buf[--l] = L'\0';
}

static void W2A(const wchar_t* w, char* a, int n)
{
    WideCharToMultiByte(CP_UTF8, 0, w, -1, a, n, NULL, NULL);
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 2 — WSMan error messages
   ═══════════════════════════════════════════════════════════════ */

static void LogWsmanErr(const wchar_t* ctx, DWORD code)
{
    static const struct { DWORD c; const wchar_t* m; } T[] =
    {
        {0x803380AB, L"Cert not trusted / TrustedHosts not set. Run option [11]."},
        {0x8033808B, L"Access denied - account lacks WinRM permission"},
        {0x80338012, L"Target not in TrustedHosts - use option [4]"},
        {0x80338126, L"WinRM service not running on target"},
        {0x80338127, L"Target unreachable or firewall blocking port"},
        {0x8033800D, L"Too many concurrent shells on target"},
        {0x80070005, L"Access denied - wrong credentials or username format"},
        {0x8007052E, L"Logon failure - wrong password"},
        {0x8007051F, L"Logon type not granted - Basic auth disabled"},
        {0x8007054F, L"Internal error - server-side WSMan state error"},
        {0, NULL}
    };
    LogError(L"%s failed: 0x%08X", ctx, code);
    for (int i = 0; T[i].m; i++)
        if (T[i].c == code) { LogError(L" -> %s", T[i].m); break; }
    if (g_api)
    {
        wchar_t msg[512] = { 0 }; DWORD used = 0;
        if (SUCCEEDED(WSManGetErrorMessage(g_api, 0, NULL, code,
            _countof(msg), msg, &used)) && used > 0)
            LogError(L" Detail: %s", msg);
    }
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 3 — Async context
   ═══════════════════════════════════════════════════════════════ */

typedef struct
{
    HANDLE               ev;
    HRESULT              hr;
    WSMAN_SHELL_HANDLE   hShell;
    WSMAN_COMMAND_HANDLE hCmd;
    char* pBuf;
    DWORD                cbBuf;
    BOOL                 bDone;
    DWORD                exitCode;
} CTX;

static BOOL CtxInit(CTX* c)
{
    ZeroMemory(c, sizeof * c);
    c->ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    return c->ev != NULL;
}

static void CtxFree(CTX* c)
{
    if (c->ev) { CloseHandle(c->ev);  c->ev = NULL; }
    if (c->pBuf) { free(c->pBuf);       c->pBuf = NULL; c->cbBuf = 0; }
}

static HRESULT CtxWait(CTX* c, DWORD ms)
{
    return (WaitForSingleObject(c->ev, ms) == WAIT_TIMEOUT)
        ? HRESULT_FROM_WIN32(ERROR_TIMEOUT) : c->hr;
}

static BOOL BufAppend(char** pp, DWORD* pcb, const BYTE* src, DWORD len)
{
    if (!src || !len) return TRUE;
    char* t = (char*)realloc(*pp, *pcb + len + 1);
    if (!t) return FALSE;
    *pp = t; memcpy(*pp + *pcb, src, len); *pcb += len; (*pp)[*pcb] = '\0';
    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 4 — Callbacks
   ═══════════════════════════════════════════════════════════════ */

static void CALLBACK cbShell(
    PVOID ctx, DWORD flags, WSMAN_ERROR* err,
    WSMAN_SHELL_HANDLE shell, WSMAN_COMMAND_HANDLE cmd,
    WSMAN_OPERATION_HANDLE /*op*/, WSMAN_RESPONSE_DATA* /*data*/)
{
    CTX* c = (CTX*)ctx; if (!c) return;
    c->hr = (err && err->code) ? HRESULT_FROM_WIN32(err->code) : S_OK;
    if (shell) c->hShell = shell;
    if (cmd)   c->hCmd = cmd;
    if (flags & WSMAN_FLAG_CALLBACK_END_OF_OPERATION) SetEvent(c->ev);
}

static void CALLBACK cbRecvStream(
    PVOID ctx, DWORD flags, WSMAN_ERROR* err,
    WSMAN_SHELL_HANDLE /*shell*/, WSMAN_COMMAND_HANDLE /*cmd*/,
    WSMAN_OPERATION_HANDLE /*op*/, WSMAN_RESPONSE_DATA* data)
{
    CTX* c = (CTX*)ctx; if (!c) return;

    if (err && err->code)
    {
        c->hr = HRESULT_FROM_WIN32(err->code);
        SetEvent(c->ev);
        return;
    }

    if (data)
    {
        WSMAN_RECEIVE_DATA_RESULT* r = &data->receiveData;
        if (r->commandState &&
            wcscmp(r->commandState, WSMAN_COMMAND_STATE_DONE) == 0)
        {
            c->bDone = TRUE;
            c->exitCode = r->exitCode;
        }
        DWORD  len = r->streamData.binaryData.dataLength;
        BYTE* src = r->streamData.binaryData.data;
        if (len > 0 && src) BufAppend(&c->pBuf, &c->cbBuf, src, len);
    }

    if (flags & WSMAN_FLAG_CALLBACK_END_OF_OPERATION) SetEvent(c->ev);
}

static void CALLBACK cbSend(
    PVOID ctx, DWORD flags, WSMAN_ERROR* err,
    WSMAN_SHELL_HANDLE /*s*/, WSMAN_COMMAND_HANDLE /*c2*/,
    WSMAN_OPERATION_HANDLE /*op*/, WSMAN_RESPONSE_DATA* /*d*/)
{
    CTX* c = (CTX*)ctx; if (!c) return;
    c->hr = (err && err->code) ? HRESULT_FROM_WIN32(err->code) : S_OK;
    if (flags & WSMAN_FLAG_CALLBACK_END_OF_OPERATION) SetEvent(c->ev);
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 5 — Session creation
   ═══════════════════════════════════════════════════════════════ */

static WSMAN_SESSION_HANDLE CreateWsmanSession(
    const wchar_t* url,
    const wchar_t* username,
    const wchar_t* password,
    BOOL           useSSL)
{
    /* Strip HOST\ prefix - NTLM/Negotiate needs bare SAM name for local accounts */
    wchar_t bareUser[MAX_USERNAME] = { 0 };
    const wchar_t* bs = wcschr(username, L'\\');
    wcscpy_s(bareUser, _countof(bareUser), bs ? bs + 1 : username);

    LogInfo(L" URL  : %s", url);
    LogInfo(L" User : %s", bareUser);

    WSMAN_USERNAME_PASSWORD_CREDS creds = { 0 };
    creds.username = bareUser;
    creds.password = password;

    WSMAN_AUTHENTICATION_CREDENTIALS auth = { 0 };
    auth.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    auth.userAccount = creds;

    WSMAN_SESSION_HANDLE session = NULL;
    HRESULT hr = WSManCreateSession(g_api, url, 0, &auth, NULL, &session);
    if (FAILED(hr) || !session) { LogWsmanErr(L"WSManCreateSession", (DWORD)hr); return NULL; }

    WSMAN_DATA d; ZeroMemory(&d, sizeof d); d.type = WSMAN_DATA_TYPE_DWORD;

    d.number = 60000;
    WSManSetSessionOption(session, WSMAN_OPTION_DEFAULT_OPERATION_TIMEOUTMS, &d);
    d.number = 1;
    WSManSetSessionOption(session, (WSManSessionOption)WSMAN_OPTION_ALLOW_NEGOTIATE_IMPLICIT_CREDENTIALS, &d);
    d.number = 1;
    WSManSetSessionOption(session, (WSManSessionOption)WSMAN_OPTION_UNENCRYPTED_MESSAGES, &d);

    if (useSSL)
    {
        d.number = 1; WSManSetSessionOption(session, WSMAN_OPTION_SKIP_CA_CHECK, &d);
        d.number = 1; WSManSetSessionOption(session, WSMAN_OPTION_SKIP_CN_CHECK, &d);
        d.number = 1; WSManSetSessionOption(session, WSMAN_OPTION_SKIP_REVOCATION_CHECK, &d);
    }

    LogOK(L"Session ready (SKIP_CA/CN=%s).", useSSL ? L"YES" : L"NO");
    return session;
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 6 — Shell lifecycle helpers
   ═══════════════════════════════════════════════════════════════ */

static WSMAN_SHELL_HANDLE DoCreateShell(WSMAN_SESSION_HANDLE sess)
{
    PCWSTR out[2] = { L"stdout", L"stderr" }; WSMAN_STREAM_ID_SET oset = { 2, out };
    PCWSTR in[1] = { L"stdin" };             WSMAN_STREAM_ID_SET iset = { 1, in };

    WSMAN_SHELL_STARTUP_INFO si; ZeroMemory(&si, sizeof si);
    si.inputStreamSet = &iset;
    si.outputStreamSet = &oset;

    CTX ctx; CtxInit(&ctx);
    WSMAN_SHELL_ASYNC  async = { &ctx, cbShell };
    WSMAN_SHELL_HANDLE h = NULL;

    WSManCreateShell(sess, 0,
        L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
        &si, NULL, NULL, &async, &h);

    HRESULT            hr = CtxWait(&ctx, 20000);
    WSMAN_SHELL_HANDLE result = ctx.hShell;
    CtxFree(&ctx);

    if (FAILED(hr) || !result)
    {
        LogWsmanErr(L"WSManCreateShell", FAILED(hr) ? (DWORD)hr : 5); return NULL;
    }
    return result;
}

static WSMAN_COMMAND_HANDLE DoRunCmd(
    WSMAN_SHELL_HANDLE sh, const wchar_t* exe, WSMAN_COMMAND_ARG_SET* args)
{
    CTX ctx; CtxInit(&ctx);
    WSMAN_SHELL_ASYNC    async = { &ctx, cbShell };
    WSMAN_COMMAND_HANDLE h = NULL;

    WSManRunShellCommand(sh, 0, exe, args, NULL, &async, &h);

    HRESULT              hr = CtxWait(&ctx, 20000);
    WSMAN_COMMAND_HANDLE result = ctx.hCmd;
    CtxFree(&ctx);

    if (FAILED(hr) || !result)
    {
        LogWsmanErr(L"WSManRunShellCommand", FAILED(hr) ? (DWORD)hr : 5); return NULL;
    }
    return result;
}

static void DoCloseCmd(WSMAN_COMMAND_HANDLE cmd)
{
    if (!cmd) return;
    CTX ctx; CtxInit(&ctx);
    WSMAN_SHELL_ASYNC async = { &ctx, cbShell };
    WSManCloseCommand(cmd, 0, &async); CtxWait(&ctx, 8000); CtxFree(&ctx);
}

static void DoCloseShell(WSMAN_SHELL_HANDLE sh)
{
    if (!sh) return;
    CTX ctx; CtxInit(&ctx);
    WSMAN_SHELL_ASYNC async = { &ctx, cbShell };
    WSManCloseShell(sh, 0, &async); CtxWait(&ctx, 8000); CtxFree(&ctx);
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 7 — DoRecvAll: single streaming receive until Done
   ═══════════════════════════════════════════════════════════════ */

static HRESULT DoRecvAll(
    WSMAN_SHELL_HANDLE   sh,
    WSMAN_COMMAND_HANDLE cmd,
    char** ppOut,
    DWORD* pcbOut,
    DWORD* pExitCode,
    DWORD   timeoutMs)
{
    CTX ctx; CtxInit(&ctx);

    PCWSTR ss[2] = { L"stdout", L"stderr" };
    WSMAN_STREAM_ID_SET   sset = { 2, ss };
    WSMAN_SHELL_ASYNC     async = { &ctx, cbRecvStream };
    WSMAN_OPERATION_HANDLE op = NULL;

    WSManReceiveShellOutput(sh, cmd, 0, &sset, &async, &op);

    DWORD w = WaitForSingleObject(ctx.ev, timeoutMs);

    if (w == WAIT_TIMEOUT && op)
        WSManCloseOperation(op, 0);

    *ppOut = ctx.pBuf;   ctx.pBuf = NULL;
    *pcbOut = ctx.cbBuf;  ctx.cbBuf = 0;
    if (pExitCode) *pExitCode = ctx.exitCode;

    HRESULT hr = (w == WAIT_TIMEOUT) ? HRESULT_FROM_WIN32(ERROR_TIMEOUT) : ctx.hr;
    CtxFree(&ctx);
    return hr;
}

/* ─── Send helper (for interactive stdin) ───────────────────── */
static HRESULT DoSend(
    WSMAN_SHELL_HANDLE   sh,
    WSMAN_COMMAND_HANDLE cmd,
    const char* buf,
    DWORD                len)
{
    CTX ctx; CtxInit(&ctx);

    WSMAN_DATA d; ZeroMemory(&d, sizeof d);
    d.type = WSMAN_DATA_TYPE_BINARY;
    d.binaryData.data = (BYTE*)buf;
    d.binaryData.dataLength = len;

    WSMAN_SHELL_ASYNC      async = { &ctx, cbSend };
    WSMAN_OPERATION_HANDLE op = NULL;

    WSManSendShellInput(sh, cmd, 0, L"stdin", &d, FALSE, &async, &op);

    DWORD   w = WaitForSingleObject(ctx.ev, 15000);
    if (w == WAIT_TIMEOUT && op) WSManCloseOperation(op, 0);

    HRESULT hr = (w == WAIT_TIMEOUT) ? HRESULT_FROM_WIN32(ERROR_TIMEOUT) : ctx.hr;
    CtxFree(&ctx);
    return hr;
}

/* Print UTF-8 bytes to console */
static void PrintUTF8(const char* b, DWORD cb)
{
    if (!b || !cb) return;
    int n = MultiByteToWideChar(CP_UTF8, 0, b, (int)cb, NULL, 0);
    if (n <= 0) { fwrite(b, 1, cb, stdout); return; }
    wchar_t* w = (wchar_t*)malloc((n + 1) * sizeof * w);
    if (!w) { fwrite(b, 1, cb, stdout); return; }
    MultiByteToWideChar(CP_UTF8, 0, b, (int)cb, w, n); w[n] = L'\0';
    DWORD wr = 0;
    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), w, (DWORD)n, &wr, NULL);
    free(w);
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 8 — RunWSManCommand
   ═══════════════════════════════════════════════════════════════ */

static DWORD RunWSManCommand(
    const wchar_t* host, int port, BOOL ssl,
    const wchar_t* user, const wchar_t* pass,
    const wchar_t* userCmd,
    wchar_t* outW, DWORD outWLen, DWORD* pExit)
{
    if (outW && outWLen > 0) outW[0] = L'\0';
    if (pExit) *pExit = (DWORD)-1;

    wchar_t url[512];
    swprintf_s(url, _countof(url), L"%s://%s:%d",
        ssl ? L"https" : L"http", host, port);

    WSMAN_SESSION_HANDLE sess = CreateWsmanSession(url, user, pass, ssl);
    if (!sess) return (DWORD)-1;

    WSMAN_SHELL_HANDLE shell = DoCreateShell(sess);
    if (!shell) { WSManCloseSession(sess, 0); return (DWORD)-1; }
    LogOK(L"Shell created.");

    PCWSTR argv[3] = { L"/c", userCmd, NULL };
    WSMAN_COMMAND_ARG_SET args = { 2, argv };

    WSMAN_COMMAND_HANDLE cmd = DoRunCmd(shell, L"cmd.exe", &args);
    if (!cmd)
    {
        DoCloseShell(shell);
        WSManCloseSession(sess, 0);
        return (DWORD)-1;
    }
    LogOK(L"Command started. Receiving output...");

    char* out = NULL;
    DWORD  outCb = 0;
    DWORD  exitCode = 0;
    HRESULT hr = DoRecvAll(shell, cmd, &out, &outCb, &exitCode, 300000);

    if (SUCCEEDED(hr) && out && outCb > 0)
    {
        PrintUTF8(out, outCb);
        wprintf(L"\n");
        if (outW && outWLen > 0)
            MultiByteToWideChar(CP_UTF8, 0, out, (int)outCb, outW, (int)outWLen);
    }
    else if (FAILED(hr))
        LogWsmanErr(L"DoRecvAll", (DWORD)hr);

    if (out) free(out);
    if (pExit) *pExit = exitCode;

    DoCloseCmd(cmd);
    DoCloseShell(shell);
    WSManCloseSession(sess, 0);

    return SUCCEEDED(hr) ? 0 : (DWORD)-1;
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 9 — Interactive CMD REPL
   ═══════════════════════════════════════════════════════════════ */

typedef struct
{
    WSMAN_SESSION_HANDLE  sess;
    WSMAN_SHELL_HANDLE    shell;
    WSMAN_COMMAND_HANDLE  cmd;
    wchar_t               cwd[512];
    char                  sentinel[64];
} ISHELL;

static DWORD g_isentId = 100000;

static void INextSentinel(ISHELL* sh)
{
    g_isentId++;
    StringCchPrintfA(sh->sentinel, _countof(sh->sentinel), SENTINEL_FMT, g_isentId);
}

typedef struct
{
    HANDLE  ev;
    HRESULT hr;
    char* pBuf;
    DWORD   cbBuf;
    BOOL    bDone;
    DWORD   exitCode;
    BOOL    bEOO;
} RECV_CTX;

static void CALLBACK cbInteractiveRecv(
    PVOID ctx, DWORD flags, WSMAN_ERROR* err,
    WSMAN_SHELL_HANDLE /*sh*/, WSMAN_COMMAND_HANDLE /*cmd*/,
    WSMAN_OPERATION_HANDLE /*op*/, WSMAN_RESPONSE_DATA* data)
{
    RECV_CTX* c = (RECV_CTX*)ctx; if (!c) return;

    if (err && err->code)
    {
        c->hr = HRESULT_FROM_WIN32(err->code);
        c->bEOO = TRUE;
        SetEvent(c->ev);
        return;
    }

    if (data)
    {
        WSMAN_RECEIVE_DATA_RESULT* r = &data->receiveData;
        if (r->commandState &&
            wcscmp(r->commandState, WSMAN_COMMAND_STATE_DONE) == 0)
        {
            c->bDone = TRUE;
            c->exitCode = r->exitCode;
        }
        DWORD len = r->streamData.binaryData.dataLength;
        BYTE* src = r->streamData.binaryData.data;
        if (len > 0 && src) BufAppend(&c->pBuf, &c->cbBuf, src, len);
    }

    if (flags & WSMAN_FLAG_CALLBACK_END_OF_OPERATION)
    {
        c->bEOO = TRUE;
        SetEvent(c->ev);
    }
}

static HRESULT IRecvUntilSentinel(
    WSMAN_SHELL_HANDLE   sh,
    WSMAN_COMMAND_HANDLE cmd,
    const char* sentinel,
    char** ppOut,
    DWORD* pcbOut)
{
    char* total = NULL;
    DWORD   cbTotal = 0;
    HRESULT hr = S_OK;
    int     loops = 60;

    PCWSTR ss[2] = { L"stdout", L"stderr" };
    WSMAN_STREAM_ID_SET sset = { 2, ss };

    while (loops-- > 0)
    {
        RECV_CTX rc; ZeroMemory(&rc, sizeof rc);
        rc.ev = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!rc.ev) { hr = E_OUTOFMEMORY; break; }

        WSMAN_SHELL_ASYNC      async = { &rc, cbInteractiveRecv };
        WSMAN_OPERATION_HANDLE op = NULL;

        WSManReceiveShellOutput(sh, cmd, 0, &sset, &async, &op);

        DWORD w = WaitForSingleObject(rc.ev, 10000);

        if (w == WAIT_TIMEOUT && op && !rc.bEOO)
            WSManCloseOperation(op, 0);

        CloseHandle(rc.ev);

        if (rc.pBuf && rc.cbBuf > 0)
            BufAppend(&total, &cbTotal, (BYTE*)rc.pBuf, rc.cbBuf);
        if (rc.pBuf) free(rc.pBuf);

        if (w != WAIT_TIMEOUT)
        {
            hr = rc.hr;
            if (FAILED(hr)) { LogError(L"IRecvUntilSentinel error: 0x%08X", (DWORD)hr); break; }
        }

        if (total)
        {
            char* pos = strstr(total, sentinel);
            if (pos)
            {
                *pos = '\0';
                cbTotal = (DWORD)(pos - total);
                while (cbTotal > 0 &&
                    (total[cbTotal - 1] == '\r' || total[cbTotal - 1] == '\n'))
                    total[--cbTotal] = '\0';
                hr = S_OK;
                break;
            }
        }

        if (rc.bDone) break;
    }

    *ppOut = total;
    *pcbOut = cbTotal;
    return hr;
}

static HRESULT IShellOpen(ISHELL* sh,
    const wchar_t* url, const wchar_t* user,
    const wchar_t* pass, BOOL ssl)
{
    ZeroMemory(sh, sizeof * sh);

    sh->sess = CreateWsmanSession(url, user, pass, ssl);
    if (!sh->sess) return E_FAIL;

    sh->shell = DoCreateShell(sh->sess);
    if (!sh->shell) { WSManCloseSession(sh->sess, 0); return E_FAIL; }
    LogOK(L"Shell created.");

    sh->cmd = DoRunCmd(sh->shell, L"cmd.exe", NULL);
    if (!sh->cmd) { DoCloseShell(sh->shell); WSManCloseSession(sh->sess, 0); return E_FAIL; }
    LogOK(L"cmd.exe started.");

    Sleep(800);

    const char setup[] = "chcp 65001 >nul 2>&1\r\n@echo off\r\nprompt $P$G\r\n";
    DoSend(sh->shell, sh->cmd, setup, (DWORD)strlen(setup));

    INextSentinel(sh);
    char flush[128];
    StringCchPrintfA(flush, _countof(flush), "echo %s\r\n", sh->sentinel);
    DoSend(sh->shell, sh->cmd, flush, (DWORD)strlen(flush));

    char* dummy = NULL; DWORD dCb = 0;
    IRecvUntilSentinel(sh->shell, sh->cmd, sh->sentinel, &dummy, &dCb);
    if (dummy) free(dummy);

    INextSentinel(sh);
    char cdcmd[128];
    StringCchPrintfA(cdcmd, _countof(cdcmd), "cd\r\necho %s\r\n", sh->sentinel);
    DoSend(sh->shell, sh->cmd, cdcmd, (DWORD)strlen(cdcmd));

    char* cwdOut = NULL; DWORD cwdCb = 0;
    IRecvUntilSentinel(sh->shell, sh->cmd, sh->sentinel, &cwdOut, &cwdCb);
    if (cwdOut && cwdCb > 0)
    {
        while (cwdCb > 0 &&
            (cwdOut[cwdCb - 1] == '\r' || cwdOut[cwdCb - 1] == '\n' || cwdOut[cwdCb - 1] == ' '))
            cwdOut[--cwdCb] = '\0';
        MultiByteToWideChar(CP_UTF8, 0, cwdOut, (int)cwdCb,
            sh->cwd, (int)_countof(sh->cwd) - 1);
        free(cwdOut);
    }
    if (!sh->cwd[0]) wcscpy_s(sh->cwd, _countof(sh->cwd), L"C:\\");

    return S_OK;
}

static void IShellClose(ISHELL* sh)
{
    if (!sh->cmd) return;
    DoSend(sh->shell, sh->cmd, "exit\r\n", 6);
    DoCloseCmd(sh->cmd);    sh->cmd = NULL;
    DoCloseShell(sh->shell); sh->shell = NULL;
    if (sh->sess) { WSManCloseSession(sh->sess, 0); sh->sess = NULL; }
}

static HRESULT IShellExec(ISHELL* sh, const wchar_t* userCmd,
    char** ppOut, DWORD* pcbOut)
{
    INextSentinel(sh);

    char cmdA[MAX_COMMAND * 2] = { 0 };
    WideCharToMultiByte(CP_UTF8, 0, userCmd, -1, cmdA, (int)sizeof(cmdA) - 1, NULL, NULL);

    char input[MAX_COMMAND * 2 + 128];
    int  len = _snprintf_s(input, sizeof input, _TRUNCATE,
        "%s\r\necho %s\r\n", cmdA, sh->sentinel);
    if (len < 0) return E_INVALIDARG;

    HRESULT hr = DoSend(sh->shell, sh->cmd, input, (DWORD)len);
    if (FAILED(hr)) { LogError(L"DoSend failed: 0x%08X", (DWORD)hr); return hr; }

    hr = IRecvUntilSentinel(sh->shell, sh->cmd, sh->sentinel, ppOut, pcbOut);

    if (SUCCEEDED(hr))
    {
        INextSentinel(sh);
        char cd[128];
        StringCchPrintfA(cd, _countof(cd), "cd\r\necho %s\r\n", sh->sentinel);
        DoSend(sh->shell, sh->cmd, cd, (DWORD)strlen(cd));
        char* cOut = NULL; DWORD cCb = 0;
        IRecvUntilSentinel(sh->shell, sh->cmd, sh->sentinel, &cOut, &cCb);
        if (cOut && cCb > 0)
        {
            while (cCb > 0 &&
                (cOut[cCb - 1] == '\r' || cOut[cCb - 1] == '\n' || cOut[cCb - 1] == ' '))
                cOut[--cCb] = '\0';
            ZeroMemory(sh->cwd, sizeof sh->cwd);
            MultiByteToWideChar(CP_UTF8, 0, cOut, (int)cCb,
                sh->cwd, (int)_countof(sh->cwd) - 1);
            free(cOut);
        }
    }
    return SUCCEEDED(hr) ? S_OK : hr;
}

static void RunInteractive(
    const wchar_t* host, int port, BOOL ssl,
    const wchar_t* user, const wchar_t* pass)
{
    PrintSep();
    LogStep(L"Opening interactive session on %s:%d ...", host, port);

    wchar_t url[512];
    swprintf_s(url, _countof(url), L"%s://%s:%d",
        ssl ? L"https" : L"http", host, port);

    ISHELL sh;
    if (FAILED(IShellOpen(&sh, url, user, pass, ssl)))
    {
        LogError(L"Failed to open interactive shell.");
        return;
    }

    LogOK(L"Connected. Type commands, 'exit' to quit.\n");
    SetColor(COLOR_CYAN);
    wprintf(L" ---- Remote CMD on %s ----\n\n", host);
    SetColor(COLOR_RESET);

    wchar_t line[MAX_COMMAND];
    while (TRUE)
    {
        SetColor(COLOR_YELLOW);
        wprintf(L"%s> ", sh.cwd);
        SetColor(COLOR_RESET);
        fflush(stdout);
        if (!fgetws(line, _countof(line), stdin)) break;
        line[wcscspn(line, L"\r\n")] = L'\0';
        if (!line[0]) continue;
        if (_wcsicmp(line, L"exit") == 0 || _wcsicmp(line, L"quit") == 0) break;

        char* out = NULL;
        DWORD   outCb = 0;
        HRESULT hr = IShellExec(&sh, line, &out, &outCb);

        if (out && outCb > 0) { PrintUTF8(out, outCb); wprintf(L"\n"); }
        if (out) free(out);

        if (FAILED(hr)) { LogError(L"Shell error 0x%08X.", (DWORD)hr); break; }
    }

    IShellClose(&sh);
    LogOK(L"Session closed.");
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 10 — Pure WinAPI local helpers
   ═══════════════════════════════════════════════════════════════

   All functions that previously used RunLocal() / CreateProcess()
   now use Win32 API directly:

     TrustedHosts  → Registry  (HKLM\...\WSMAN\Client, TrustedHosts)
     Ping          → IcmpSendEcho  (Iphlpapi.h / Iphlpapi.lib)
     TCP test      → socket + connect + select  (unchanged, already pure)
     SSL cert      → Schannel / SChannel  (unchanged, already pure)

   No child processes are spawned anywhere in this file.
   ═══════════════════════════════════════════════════════════════ */

   /* ─── Registry: read current TrustedHosts string ────────────── */
   /*
    * RegReadTrustedHosts
    *
    * Opens HKLM\...\WSMAN\Client and reads REG_SZ "TrustedHosts".
    * Returns TRUE and fills buf (up to bufCh chars) on success.
    * Returns FALSE + empty buf if key/value is absent or empty.
    *
    * Access: KEY_READ is sufficient; no elevation needed for reading.
    */
static BOOL RegReadTrustedHosts(wchar_t* buf, DWORD bufCh)
{
    buf[0] = L'\0';

    HKEY hk = NULL;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        WSMAN_CLIENT_REG_KEY, 0, KEY_READ, &hk);
    if (rc != ERROR_SUCCESS)
    {
        /* Key may not exist if WinRM was never configured */
        LogWarn(L"RegOpenKey(%s) -> %ld", WSMAN_CLIENT_REG_KEY, rc);
        return FALSE;
    }

    DWORD type = 0;
    DWORD cb = bufCh * sizeof(wchar_t);
    rc = RegQueryValueExW(hk, WSMAN_TRUSTED_HOSTS_VALUE, NULL, &type,
        (LPBYTE)buf, &cb);
    RegCloseKey(hk);

    if (rc == ERROR_FILE_NOT_FOUND)
    {
        /* Value simply not set yet — that is normal */
        return TRUE;
    }
    if (rc != ERROR_SUCCESS)
    {
        LogWarn(L"RegQueryValueEx(TrustedHosts) -> %ld", rc);
        return FALSE;
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ)
    {
        LogWarn(L"TrustedHosts has unexpected registry type %lu", type);
        buf[0] = L'\0';
        return FALSE;
    }
    return TRUE;
}

/* ─── Registry: write TrustedHosts string ───────────────────── */
/*
 * RegWriteTrustedHosts
 *
 * Writes newVal into HKLM\...\WSMAN\Client\TrustedHosts as REG_SZ.
 * Creates the key if absent.
 *
 * Access: Requires Administrator (KEY_WRITE on HKLM).
 * The WinRM service watches this registry location and picks up
 * the change without requiring a service restart.
 */
static BOOL RegWriteTrustedHosts(const wchar_t* newVal)
{
    HKEY  hk = NULL;
    DWORD disp = 0;
    LONG  rc = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        WSMAN_CLIENT_REG_KEY,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        NULL, &hk, &disp);

    if (rc != ERROR_SUCCESS)
    {
        LogError(L"RegCreateKeyEx(%s) -> %ld (need Admin)", WSMAN_CLIENT_REG_KEY, rc);
        return FALSE;
    }

    DWORD cbVal = (DWORD)((wcslen(newVal) + 1) * sizeof(wchar_t));
    rc = RegSetValueExW(hk, WSMAN_TRUSTED_HOSTS_VALUE, 0,
        REG_SZ, (const BYTE*)newVal, cbVal);
    RegCloseKey(hk);

    if (rc != ERROR_SUCCESS)
    {
        LogError(L"RegSetValueEx(TrustedHosts) -> %ld", rc);
        return FALSE;
    }
    return TRUE;
}

/* ─── TrustedHosts: display current value ───────────────────── */
static void ShowTrustedHosts(void)
{
    PrintSep();
    LogStep(L"Reading TrustedHosts from registry...");

    wchar_t cur[4096] = { 0 };
    if (!RegReadTrustedHosts(cur, _countof(cur))) return;

    if (!cur[0])
        LogWarn(L"TrustedHosts is empty (not configured).");
    else
    {
        SetColor(COLOR_MAGENTA);
        wprintf(L"\n TrustedHosts = %s\n\n", cur);
        SetColor(COLOR_RESET);
    }
}

/* ─── TrustedHosts: add a host ──────────────────────────────── */
/*
 * AddTrustedHost
 *
 * Reads the existing comma-separated list, appends the new host
 * (if not already present), and writes it back — all via registry
 * calls.  No winrm.exe or cmd.exe involved.
 */
static BOOL AddTrustedHost(const wchar_t* h)
{
    PrintSep();
    LogStep(L"Adding '%s' to TrustedHosts ...", h);

    wchar_t cur[4096] = { 0 };
    RegReadTrustedHosts(cur, _countof(cur));

    /* Wildcard already covers everything */
    if (wcscmp(cur, L"*") == 0)
    {
        LogWarn(L"TrustedHosts is '*' (all hosts already trusted).");
        return TRUE;
    }

    /* Check if host already present (case-insensitive) */
    wchar_t tmp[4096];
    wcscpy_s(tmp, _countof(tmp), cur);
    wchar_t* ctx2 = NULL;
    wchar_t* tok = wcstok_s(tmp, L",", &ctx2);
    while (tok)
    {
        /* trim surrounding spaces */
        while (*tok == L' ') tok++;
        wchar_t* e = tok + wcslen(tok) - 1;
        while (e > tok && *e == L' ') { *e = L'\0'; e--; }

        if (_wcsicmp(tok, h) == 0)
        {
            LogWarn(L"'%s' is already in TrustedHosts.", h);
            return TRUE;
        }
        tok = wcstok_s(NULL, L",", &ctx2);
    }

    /* Build new value */
    wchar_t newVal[4096] = { 0 };
    if (cur[0] == L'\0')
        wcscpy_s(newVal, _countof(newVal), h);
    else
        swprintf_s(newVal, _countof(newVal), L"%s,%s", cur, h);

    if (!RegWriteTrustedHosts(newVal)) return FALSE;

    LogOK(L"Added '%s'. TrustedHosts = %s", h, newVal);
    return TRUE;
}

/* ─── TrustedHosts: remove a host ──────────────────────────── */
/*
 * RemoveTrustedHost
 *
 * Reads the list, removes the matching entry (case-insensitive),
 * rebuilds the CSV and writes back via registry.
 */
static BOOL RemoveTrustedHost(const wchar_t* h)
{
    PrintSep();
    LogStep(L"Removing '%s' from TrustedHosts ...", h);

    wchar_t cur[4096] = { 0 };
    RegReadTrustedHosts(cur, _countof(cur));

    if (!cur[0])
    {
        LogWarn(L"TrustedHosts is already empty — nothing to remove.");
        return TRUE;
    }

    /* Walk the CSV list, skip the target host */
    wchar_t newVal[4096] = { 0 };
    wchar_t tmp[4096];
    wcscpy_s(tmp, _countof(tmp), cur);

    BOOL    found = FALSE;
    BOOL    first = TRUE;
    wchar_t* ctx2 = NULL;
    wchar_t* tok = wcstok_s(tmp, L",", &ctx2);

    while (tok)
    {
        while (*tok == L' ') tok++;
        wchar_t* e = tok + wcslen(tok) - 1;
        while (e > tok && (*e == L' ' || *e == L'\r' || *e == L'\n'))
        {
            *e = L'\0'; e--;
        }

        if (_wcsicmp(tok, h) == 0)
        {
            found = TRUE; /* skip — this is the one we're removing */
        }
        else
        {
            if (!first) wcscat_s(newVal, _countof(newVal), L",");
            wcscat_s(newVal, _countof(newVal), tok);
            first = FALSE;
        }
        tok = wcstok_s(NULL, L",", &ctx2);
    }

    if (!found)
    {
        LogWarn(L"'%s' not found in TrustedHosts.", h);
        return TRUE;
    }

    if (!RegWriteTrustedHosts(newVal)) return FALSE;

    if (newVal[0])
        LogOK(L"Removed '%s'. TrustedHosts = %s", h, newVal);
    else
        LogOK(L"Removed '%s'. TrustedHosts is now empty.", h);
    return TRUE;
}

/* ─── Ping: IcmpSendEcho (pure WinAPI, no ping.exe) ────────── */
/*
 * PingHost
 *
 * Uses the Win32 ICMP helper API:
 *   IcmpCreateFile()  — open an ICMP handle
 *   IcmpSendEcho()    — send one echo request, block up to 2 s
 *   IcmpCloseHandle() — close the handle
 *
 * Works for IPv4. For IPv6, Icmp6CreateFile + Icmp6SendEcho2
 * would be needed, but WinRM targets are almost always IPv4.
 *
 * Requires: Iphlpapi.lib, Iphlpapi.h, Ws2_32.lib (for inet_pton).
 * Does NOT require raw-socket privileges on Vista+ when used via
 * the IcmpSendEcho API.
 */
static BOOL PingHost(const wchar_t* h)
{
    PrintSep();
    LogStep(L"Pinging %s (ICMP/IcmpSendEcho) ...", h);

    if (!g_wsaOk)
    {
        LogError(L"Winsock not initialized — cannot resolve host for ping.");
        return FALSE;
    }

    /* Resolve hostname → IPv4 address */
    char   hostA[MAX_HOSTNAME] = { 0 };
    W2A(h, hostA, sizeof hostA);

    struct addrinfo hints = { 0 }, * res = NULL;
    hints.ai_family = AF_INET;          /* IPv4 only for IcmpSendEcho */
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostA, NULL, &hints, &res) != 0)
    {
        LogError(L"DNS resolution failed for '%s'.", h);
        return FALSE;
    }

    IPAddr dest = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);

    /* Open ICMP handle */
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE)
    {
        LogError(L"IcmpCreateFile failed (%lu).", GetLastError());
        return FALSE;
    }

    /* Payload — 32 bytes, same as ping.exe default */
    const char payload[32] = "WinRM-Manager-ping-payload.....";

    /* Reply buffer: must be >= sizeof(ICMP_ECHO_REPLY) + payload */
    BYTE   replyBuf[sizeof(ICMP_ECHO_REPLY) + 32 + 8] = { 0 };

    DWORD  nReplies = IcmpSendEcho(
        hIcmp,
        dest,
        (LPVOID)payload, (WORD)sizeof payload,
        NULL,           /* default IP options */
        replyBuf, sizeof replyBuf,
        2000);          /* 2 000 ms timeout */

    IcmpCloseHandle(hIcmp);

    if (nReplies == 0)
    {
        DWORD err = GetLastError();
        /* IP_REQ_TIMED_OUT = 11010, IP_DEST_HOST_UNREACHABLE = 11003, etc. */
        LogWarn(L"No ICMP reply from %s (error %lu).", h, err);
        return FALSE;
    }

    ICMP_ECHO_REPLY* reply = (ICMP_ECHO_REPLY*)replyBuf;
    struct in_addr   ia;
    ia.s_addr = reply->Address;
    char addrStr[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &ia, addrStr, sizeof addrStr);

    LogOK(L"%s is reachable. Reply from %S: bytes=%lu TTL=%u RTT=%lums.",
        h,
        addrStr,
        reply->DataSize,
        reply->Options.Ttl,
        reply->RoundTripTime);
    return TRUE;
}

/* ─── TCP connectivity test (already pure WinAPI) ───────────── */
static BOOL TestTcp(const wchar_t* h, int port, int tms)
{
    char ha[MAX_HOSTNAME]; W2A(h, ha, sizeof ha);
    struct addrinfo hints = { 0 }, * res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ps[8]; sprintf_s(ps, "%d", port);
    if (getaddrinfo(ha, ps, &hints, &res) != 0)
    {
        LogError(L"DNS fail: %s", h); return FALSE;
    }
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return FALSE; }
    u_long m = 1; ioctlsocket(s, FIONBIO, &m);
    connect(s, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);
    fd_set w; FD_ZERO(&w); FD_SET(s, &w);
    struct timeval tv; tv.tv_sec = tms / 1000; tv.tv_usec = (tms % 1000) * 1000;
    int r = select(0, NULL, &w, NULL, &tv);
    closesocket(s);
    return r == 1;
}

/* ─── SSL Certificate: download via Schannel (already pure) ─── */
static PCCERT_CONTEXT DownloadCert(const wchar_t* h, int port)
{
    PrintSep();
    LogStep(L"Downloading SSL cert from %s:%d (Schannel) ...", h, port);

    char ha[MAX_HOSTNAME]; W2A(h, ha, sizeof ha);
    struct addrinfo hints = { 0 }, * res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ps[8]; sprintf_s(ps, "%d", port);
    if (getaddrinfo(ha, ps, &hints, &res) != 0)
    {
        LogError(L"DNS fail"); return NULL;
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return NULL; }
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0)
    {
        LogError(L"TCP connect failed %s:%d", h, port);
        freeaddrinfo(res); closesocket(s); return NULL;
    }
    freeaddrinfo(res);
    LogOK(L"TCP connected.");

    SCHANNEL_CRED sc; ZeroMemory(&sc, sizeof sc);
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_1_CLIENT;
    sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;

    CredHandle hCred; TimeStamp ts;
    if (AcquireCredentialsHandleA(NULL, (LPSTR)UNISP_NAME_A,
        SECPKG_CRED_OUTBOUND, NULL, &sc, NULL, NULL, &hCred, &ts) != SEC_E_OK)
    {
        LogError(L"AcquireCredHandle failed"); closesocket(s); return NULL;
    }

    CtxtHandle hCtx; DWORD attr = 0; BOOL first = TRUE;
    static char net[RECV_BUFSIZE]; DWORD used = 0;
    PCCERT_CONTEXT pc = NULL; SECURITY_STATUS ss;

    SecBuffer    oB[1]; SecBufferDesc oD;
    SecBuffer    iB[2]; SecBufferDesc iD;
    ZeroMemory(oB, sizeof oB);
    oB[0].BufferType = SECBUFFER_TOKEN;
    oD.ulVersion = SECBUFFER_VERSION; oD.cBuffers = 1; oD.pBuffers = oB;

    while (TRUE)
    {
        iB[0].cbBuffer = used; iB[0].BufferType = SECBUFFER_TOKEN; iB[0].pvBuffer = net;
        iB[1].cbBuffer = 0;    iB[1].BufferType = SECBUFFER_EMPTY; iB[1].pvBuffer = NULL;
        iD.ulVersion = SECBUFFER_VERSION; iD.cBuffers = 2; iD.pBuffers = iB;

        ss = InitializeSecurityContextA(
            &hCred, first ? NULL : &hCtx, ha,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
            ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
            ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION,
            0, SECURITY_NATIVE_DREP,
            first ? NULL : &iD, 0,
            &hCtx, &oD, &attr, &ts);
        first = FALSE;

        if (oB[0].cbBuffer && oB[0].pvBuffer)
        {
            send(s, (char*)oB[0].pvBuffer, (int)oB[0].cbBuffer, 0);
            FreeContextBuffer(oB[0].pvBuffer);
            oB[0].pvBuffer = NULL; oB[0].cbBuffer = 0;
        }

        if (ss == SEC_E_OK) { LogOK(L"TLS handshake complete."); break; }
        if (ss == SEC_I_CONTINUE_NEEDED)
            used = (iB[1].BufferType == SECBUFFER_EXTRA) ? iB[1].cbBuffer : 0;
        else if (ss != SEC_E_INCOMPLETE_MESSAGE)
        {
            LogError(L"TLS error: 0x%08X", (DWORD)ss); break;
        }

        int r = recv(s, net + used, (int)(sizeof net - used), 0);
        if (r <= 0) { LogError(L"Connection lost."); break; }
        used += (DWORD)r;
    }

    if (ss == SEC_E_OK)
    {
        QueryContextAttributesA(&hCtx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pc);
        if (pc)
        {
            LogOK(L"Certificate retrieved.");
            wchar_t sub[256] = { 0 }, iss[256] = { 0 };
            CertGetNameStringW(pc, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sub, 256);
            CertGetNameStringW(pc, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG, NULL, iss, 256);
            SYSTEMTIME nb, na;
            FileTimeToSystemTime(&pc->pCertInfo->NotBefore, &nb);
            FileTimeToSystemTime(&pc->pCertInfo->NotAfter, &na);
            LogInfo(L" Subject: %s", sub);
            LogInfo(L" Issuer : %s", iss);
            LogInfo(L" Valid  : %02d/%02d/%04d - %02d/%02d/%04d",
                nb.wDay, nb.wMonth, nb.wYear,
                na.wDay, na.wMonth, na.wYear);
        }
    }
    DeleteSecurityContext(&hCtx);
    FreeCredentialsHandle(&hCred);
    closesocket(s);
    return pc;
}

/* ─── Certificate: import to Local Machine Trusted Root ─────── */
static BOOL ImportCert(PCCERT_CONTEXT pc)
{
    PrintSep();
    LogStep(L"Importing cert into Local Machine Trusted Root CA...");
    if (!pc) { LogError(L"No cert."); return FALSE; }

    HCERTSTORE st = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"ROOT");
    if (!st) { LogError(L"Cannot open ROOT store (%lu).", GetLastError()); return FALSE; }

    DWORD tsz = 20; BYTE tp[20] = { 0 };
    CertGetCertificateContextProperty(pc, CERT_HASH_PROP_ID, tp, &tsz);
    CRYPT_HASH_BLOB hb = { tsz, tp };
    PCCERT_CONTEXT ex = CertFindCertificateInStore(
        st, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
    if (ex)
    {
        LogWarn(L"Certificate already in Trusted Root CA.");
        CertFreeCertificateContext(ex);
        CertCloseStore(st, 0);
        return TRUE;
    }

    BOOL ok = CertAddCertificateContextToStore(
        st, pc, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
    CertCloseStore(st, 0);

    if (ok) LogOK(L"Certificate imported successfully.");
    else    LogError(L"Import failed (%lu).", GetLastError());
    return ok;
}

/* ─── Certificate: export to .cer file ──────────────────────── */
static BOOL ExportCert(PCCERT_CONTEXT pc, const wchar_t* h)
{
    if (!pc) return FALSE;
    PrintSep();
    wchar_t p[MAX_PATH];
    swprintf_s(p, _countof(p), L"%s_cert.cer", h);
    LogStep(L"Exporting certificate to %s ...", p);

    HANDLE f = CreateFileW(p, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
    {
        LogError(L"Cannot create file (%lu).", GetLastError()); return FALSE;
    }

    DWORD wr = 0;
    WriteFile(f, pc->pbCertEncoded, pc->cbCertEncoded, &wr, NULL);
    CloseHandle(f);

    LogOK(L"Saved to %s (%lu bytes).", p, wr);
    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 11 — Target + Menu
   ═══════════════════════════════════════════════════════════════ */

static BOOL IsAdmin(void)
{
    BOOL e = FALSE; HANDLE tok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    {
        TOKEN_ELEVATION te; DWORD sz = sizeof te;
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof te, &sz))
            e = te.TokenIsElevated;
        CloseHandle(tok);
    }
    return e;
}

typedef struct
{
    wchar_t host[MAX_HOSTNAME];
    wchar_t user[MAX_USERNAME];
    wchar_t userNorm[MAX_USERNAME];
    wchar_t pass[MAX_PASSWORD];
    int     port;
    BOOL    ssl;
} TARGET;

static BOOL GetTarget(TARGET* t)
{
    PrintSep();
    SetColor(COLOR_CYAN); wprintf(L"\n [ Target Information ]\n\n"); SetColor(COLOR_RESET);

    ReadLine(t->host, MAX_HOSTNAME, L"Target Hostname / IP");
    if (!t->host[0]) { LogError(L"Hostname required."); return FALSE; }
    for (wchar_t* p = t->host; *p; p++) *p = towlower(*p);

    wchar_t ps[16] = { 0 };
    ReadLine(ps, _countof(ps), L"Port [Enter = auto: HTTPS=5986 / HTTP=5985]");
    if (!ps[0])
    {
        wchar_t pr[8] = { 0 };
        ReadLine(pr, _countof(pr), L"Use HTTPS? (y/n) [y]");
        t->ssl = (pr[0] != L'n' && pr[0] != L'N');
        t->port = t->ssl ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;
    }
    else
    {
        t->port = _wtoi(ps);
        t->ssl = (t->port == DEFAULT_HTTPS_PORT);
    }

    ReadLine(t->user, MAX_USERNAME, L"Username [Administrator]");
    if (!t->user[0]) wcscpy_s(t->user, MAX_USERNAME, L"Administrator");
    ReadPass(t->pass, MAX_PASSWORD);

    if (wcschr(t->user, L'\\') || wcschr(t->user, L'@'))
        wcscpy_s(t->userNorm, MAX_USERNAME, t->user);
    else
        swprintf_s(t->userNorm, MAX_USERNAME, L"%s\\%s", t->host, t->user);

    SetColor(COLOR_MAGENTA);
    wprintf(L"\n +-------------------------------------------------+\n");
    wprintf(L" | Host     : %-35s|\n", t->host);
    wprintf(L" | Port     : %-5d (%s)                    |\n", t->port, t->ssl ? L"HTTPS" : L"HTTP ");
    wprintf(L" | User     : %-35s|\n", t->userNorm);
    wprintf(L" | Password : (hidden)                             |\n");
    wprintf(L" +-------------------------------------------------+\n\n");
    SetColor(COLOR_RESET);

    SetColor(COLOR_GREEN);
    wprintf(L" Equivalent winrs command:\n");
    wprintf(L"   winrs -r:%s://%s:%d -u:%s -p:**** cmd\n\n",
        t->ssl ? L"https" : L"http", t->host, t->port, t->user);
    SetColor(COLOR_RESET);
    return TRUE;
}

static void PrintMenu(const TARGET* t)
{
    PrintSep();
    SetColor(COLOR_CYAN);  wprintf(L"\n Host: ");
    SetColor(COLOR_WHITE); wprintf(L"%s:%d (%s)", t->host, t->port, t->ssl ? L"HTTPS" : L"HTTP");
    SetColor(COLOR_CYAN);  wprintf(L"  User: ");
    SetColor(COLOR_WHITE); wprintf(L"%s\n\n", t->userNorm);
    SetColor(COLOR_RESET);

    static const struct { int id; WORD col; const wchar_t* lbl; } M[] =
    {
        { 1, COLOR_WHITE,  L"Test TCP port connectivity"            },
        { 2, COLOR_WHITE,  L"Ping target (ICMP/IcmpSendEcho)"      },
        { 3, COLOR_WHITE,  L"Show TrustedHosts (registry)"         },
        { 4, COLOR_WHITE,  L"Add target to TrustedHosts (registry)"},
        { 5, COLOR_WHITE,  L"Remove target from TrustedHosts (reg)"},
        { 6, COLOR_WHITE,  L"Download SSL certificate (Schannel)"  },
        { 7, COLOR_WHITE,  L"Import certificate -> Trusted Root CA"},
        { 8, COLOR_WHITE,  L"Export certificate -> .cer file"      },
        { 9, COLOR_WHITE,  L"Execute remote command [WSMan]"       },
        {10, COLOR_WHITE,  L"Interactive CMD session [WSMan REPL]" },
        {11, COLOR_GREEN,  L"Run all setup steps (1+3+4+6+7)"      },
        {12, COLOR_YELLOW, L"Change target / credentials"          },
        { 0, COLOR_RED,    L"Exit"                                 },
    };
    for (int i = 0; i < (int)_countof(M); i++)
    {
        SetColor(M[i].col); wprintf(L" [%2d] %s\n", M[i].id, M[i].lbl);
    }
    SetColor(COLOR_RESET); wprintf(L"\n");
}

/* ═══════════════════════════════════════════════════════════════
   SECTION 12 — wmain
   ═══════════════════════════════════════════════════════════════ */

int wmain(void)
{
    g_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    CONSOLE_SCREEN_BUFFER_INFO ci;
    GetConsoleScreenBufferInfo(g_hCon, &ci);
    if (ci.dwSize.X < 80) { COORD z = { 80,1000 }; SetConsoleScreenBufferSize(g_hCon, z); }

    _wfopen_s(&g_log, LOG_FILE, L"a, ccs=UTF-8");
    Banner();

    if (!IsAdmin())
    {
        LogError(L"Administrator privileges required!");
        wprintf(L"\n Press Enter to exit..."); getwchar(); return 1;
    }
    LogOK(L"Running as Administrator.");

    /* Initialize Winsock — needed for DNS resolution in PingHost too */
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) == 0) g_wsaOk = TRUE;
    else LogWarn(L"WSAStartup failed.");

    /* Initialize WSMan API — required for options 9 and 10 only */
    HRESULT hr = WSManInitialize(WSMAN_FLAG_REQUESTED_API_VERSION_1_1, &g_api);
    if (FAILED(hr))
    {
        LogError(L"WSManInitialize failed 0x%08X - run: winrm quickconfig", (DWORD)hr);
        LogWarn(L"Options 9, 10 disabled.");
    }
    else LogOK(L"WSMan API ready.");

    PCCERT_CONTEXT pCert = NULL;
    TARGET t; ZeroMemory(&t, sizeof t);
    if (!GetTarget(&t)) goto done;

    while (TRUE)
    {
        PrintMenu(&t);
        wchar_t ch[8] = { 0 };
        ReadLine(ch, _countof(ch), L"Select option");
        if (ch[0] == L'\0' || ch[0] == L'\n') continue;

        switch (_wtoi(ch))
        {
        case 0: goto done;

        case 1:
            PrintSep();
            LogStep(L"Testing TCP %s:%d ...", t.host, t.port);
            if (TestTcp(t.host, t.port, TCP_TIMEOUT_MS))
                LogOK(L"Port %d OPEN on %s.", t.port, t.host);
            else
                LogError(L"Port %d CLOSED / unreachable on %s.", t.port, t.host);
            break;

        case 2:
            /* Pure IcmpSendEcho — no ping.exe spawned */
            PingHost(t.host);
            break;

        case 3:
            /* Pure registry read — no winrm.exe spawned */
            ShowTrustedHosts();
            break;

        case 4:
            /* Pure registry write — no winrm.exe spawned */
            AddTrustedHost(t.host);
            break;

        case 5:
            /* Pure registry write — no winrm.exe spawned */
            RemoveTrustedHost(t.host);
            break;

        case 6:
            if (pCert) { CertFreeCertificateContext(pCert); pCert = NULL; }
            if (!t.ssl) LogWarn(L"Port %d may be HTTP — cert retrieval is for HTTPS.", t.port);
            pCert = DownloadCert(t.host, t.port);
            if (!pCert) LogError(L"Failed to retrieve certificate.");
            break;

        case 7:
            if (!pCert)
            {
                LogWarn(L"No cert cached — downloading first...");
                pCert = DownloadCert(t.host, t.port);
            }
            if (pCert) ImportCert(pCert);
            break;

        case 8:
            if (!pCert)
            {
                LogWarn(L"No cert cached — downloading first...");
                pCert = DownloadCert(t.host, t.port);
            }
            if (pCert) ExportCert(pCert, t.host);
            break;

        case 9:
            if (!g_api) { LogError(L"WSMan not initialized."); break; }
            {
                PrintSep();
                wchar_t cmd[MAX_COMMAND] = { 0 };
                ReadLine(cmd, MAX_COMMAND, L"Command (e.g. whoami /all)");
                if (!cmd[0]) { LogWarn(L"Empty command."); break; }
                LogStep(L"Executing: %s", cmd);
                wchar_t obuf[65536] = { 0 }; DWORD ex = 0;
                if (RunWSManCommand(t.host, t.port, t.ssl,
                    t.user, t.pass,
                    cmd, obuf, _countof(obuf), &ex) != (DWORD)-1)
                    LogOK(L"Done. Exit code %lu.", ex);
                else
                    LogError(L"Command failed.");
            }
            break;

        case 10:
            if (!g_api) { LogError(L"WSMan not initialized."); break; }
            RunInteractive(t.host, t.port, t.ssl, t.user, t.pass);
            break;

        case 11:
            LogStep(L"=== All setup steps ===");
            if (!TestTcp(t.host, t.port, TCP_TIMEOUT_MS))
            {
                LogError(L"Port closed — aborting setup."); break;
            }
            ShowTrustedHosts();
            AddTrustedHost(t.host);
            if (t.ssl)
            {
                if (pCert) { CertFreeCertificateContext(pCert); pCert = NULL; }
                pCert = DownloadCert(t.host, t.port);
                if (pCert) { ImportCert(pCert); ExportCert(pCert, t.host); }
            }
            LogOK(L"Setup complete. Try option [9] or [10].");
            SetColor(COLOR_GREEN);
            wprintf(L"\n  winrs -r:%s://%s:%d -u:%s -p:**** cmd\n\n",
                t.ssl ? L"https" : L"http", t.host, t.port, t.user);
            SetColor(COLOR_RESET);
            break;

        case 12:
        {
            if (pCert) { CertFreeCertificateContext(pCert); pCert = NULL; }
            TARGET n; ZeroMemory(&n, sizeof n);
            if (GetTarget(&n)) t = n;
        }
        break;

        default:
            LogWarn(L"Invalid selection.");
            break;
        }

        wprintf(L"\n Press Enter to continue..."); getwchar();
    }

done:
    if (pCert) CertFreeCertificateContext(pCert);
    SecureZeroMemory(t.pass, sizeof t.pass);
    if (g_api) { WSManDeinitialize(g_api, 0); g_api = NULL; }
    if (g_wsaOk) WSACleanup();
    if (g_log) fclose(g_log);
    LogOK(L"Exited cleanly. Log: %s", LOG_FILE);
    return 0;
}