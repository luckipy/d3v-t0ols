#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <winreg.h>
#include <oleauto.h>
#include <ocidl.h>
#include <comdef.h>
#include <objbase.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <wintrust.h>
#include <Softpub.h>
#include <shlwapi.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================
//  ANSI colour
// ============================================================
#define C_RST  L"\033[0m"
#define C_BOLD L"\033[1m"
#define C_DIM  L"\033[2m"
#define C_RED  L"\033[91m"
#define C_YEL  L"\033[93m"
#define C_GRN  L"\033[92m"
#define C_CYN  L"\033[96m"
#define C_MAG  L"\033[95m"
#define C_BLU  L"\033[94m"
#define C_WHT  L"\033[97m"
#define C_ORG  L"\033[38;5;208m"

static bool g_color = true;
#define CC(c) (g_color ? (c) : L"")

static void EnableVT()
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  m = 0;
    if (!GetConsoleMode(h, &m)) { g_color = false; return; }
    if (!SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        g_color = false;
}

// ============================================================
//  Exec-keyword classification engine
// ============================================================
enum class ExecRisk { None, Low, Medium, High, Critical };

struct ExecKeyword {
    const wchar_t* word;
    ExecRisk        risk;
    const wchar_t* reason;
};

static const ExecKeyword kExecKeywords[] = {
    { L"shell",          ExecRisk::Critical, L"ShellExecute - launch arbitrary process/URL" },
    { L"execute",          ExecRisk::Critical, L"ShellExecute - launch arbitrary process/URL" },
    { L"shellexecute",          ExecRisk::Critical, L"ShellExecute - launch arbitrary process/URL" },
    { L"shellexecuteex",        ExecRisk::Critical, L"ShellExecuteEx - launch with elevated privs" },
    { L"createobject",          ExecRisk::Critical, L"CreateObject - instantiate arbitrary COM" },
    { L"wscript",               ExecRisk::Critical, L"WScript interface - scripting host execute" },
    { L"getobject",             ExecRisk::Critical, L"GetObject - bind moniker, WMI, ADSI exec" },
    { L"invoke",                ExecRisk::Critical, L"Invoke/InvokeVerb - shell verb execution" },
    { L"invokeverb",            ExecRisk::Critical, L"InvokeVerb - shell verb (open,runas,etc.)" },
    { L"execute",               ExecRisk::Critical, L"Execute - generic execute surface" },
    { L"execquery",             ExecRisk::Critical, L"ExecQuery - WMI query / command exec" },
    { L"execmethod",            ExecRisk::Critical, L"ExecMethod - WMI method invocation" },
    { L"execnotificationquery", ExecRisk::Critical, L"ExecNotificationQuery - WMI async exec" },
    { L"run",                   ExecRisk::Critical, L"Run - process launch (WScript.Shell)" },
    { L"exec",                  ExecRisk::Critical, L"Exec - child process with I/O pipes" },
    { L"createprocess",         ExecRisk::Critical, L"CreateProcess - direct process creation" },
    { L"winexec",               ExecRisk::Critical, L"WinExec - legacy process launch" },
    { L"spawn",                 ExecRisk::Critical, L"Spawn - process spawn" },
    { L"launchapplication",     ExecRisk::Critical, L"LaunchApplication - app launch surface" },
    { L"startapplication",      ExecRisk::Critical, L"StartApplication - app launch surface" },
    { L"openapplication",       ExecRisk::Critical, L"OpenApplication - app launch surface" },
    { L"eval",                  ExecRisk::High,     L"Eval - dynamic code evaluation" },
    //{ L"addcode",               ExecRisk::High,     L"AddCode - inject script code" },
    { L"addtypelib",            ExecRisk::High,     L"AddTypeLib - load type library" },
    { L"parsescripttext",       ExecRisk::High,     L"ParseScriptText - inject script" },
    { L"executescripttext",     ExecRisk::High,     L"ExecuteScriptText - run injected script" },
    { L"loadtypelib",           ExecRisk::High,     L"LoadTypeLib - load arbitrary TLB" },
    //{ L"regsvr",                ExecRisk::High,     L"Regsvr* - DLL registration" },
    { L"runscript",             ExecRisk::High,     L"RunScript - run scripting code" },
    { L"runmacro",              ExecRisk::High,     L"RunMacro - macro execution" },
    { L"executemacro",          ExecRisk::High,     L"ExecuteMacro - macro execution" },
    { L"application",           ExecRisk::High,     L"Application property - COM app object access" },
    { L"loadlibrary",           ExecRisk::High,     L"LoadLibrary - load arbitrary DLL" },
    { L"loadmodule",            ExecRisk::High,     L"LoadModule - load executable module" },
    { L"loadfile",              ExecRisk::High,     L"LoadFile - arbitrary file load" },
    //{ L"loadurl",               ExecRisk::High,     L"LoadURL - remote code load" },
    //{ L"navigate",              ExecRisk::High,     L"Navigate - browser navigation (exec risk)" },
    //{ L"navigate2",             ExecRisk::High,     L"Navigate2 - browser navigation v2" },
    //{ L"open",                  ExecRisk::High,     L"Open - file/process/url open" },
    //{ L"openfile",              ExecRisk::High,     L"OpenFile - open file by path" },
    //{ L"openurl",               ExecRisk::High,     L"OpenURL - open/execute URL" },
    { L"download",              ExecRisk::High,     L"Download - fetch and store file" },
    { L"downloadfile",          ExecRisk::High,     L"DownloadFile - remote file fetch" },
    { L"schedule",              ExecRisk::Medium,   L"Schedule - task scheduler interface" },
    { L"registertask",          ExecRisk::Medium,   L"RegisterTask - create scheduled task" },
    { L"createtask",            ExecRisk::Medium,   L"CreateTask - create task (older API)" },
    { L"runtask",               ExecRisk::Medium,   L"RunTask - run scheduled task" },
    //{ L"sendinput",             ExecRisk::Medium,   L"SendInput - synthesize keyboard/mouse" },
    //{ L"sendkeys",              ExecRisk::Medium,   L"SendKeys - inject keystrokes" },
    //{ L"postmessage",           ExecRisk::Medium,   L"PostMessage - inject window messages" },
    //{ L"sendmessage",           ExecRisk::Medium,   L"SendMessage - inject window messages" },
    //{ L"setclipboarddata",      ExecRisk::Medium,   L"SetClipboardData - clipboard manipulation" },
    //{ L"getclipboarddata",      ExecRisk::Medium,   L"GetClipboardData - clipboard read" },
    //{ L"regwrite",              ExecRisk::Medium,   L"RegWrite - registry write (persistence)" },
    //{ L"regread",               ExecRisk::Medium,   L"RegRead - registry read" },
    //{ L"regdelete",             ExecRisk::Medium,   L"RegDelete - registry delete" },
    //{ L"writefile",             ExecRisk::Medium,   L"WriteFile - arbitrary file write" },
    //{ L"copyfile",              ExecRisk::Medium,   L"CopyFile - file copy" },
    //{ L"movefile",              ExecRisk::Medium,   L"MoveFile - file move/rename" },
    //{ L"deletefile",            ExecRisk::Medium,   L"DeleteFile - file deletion" },
    //{ L"createfile",            ExecRisk::Medium,   L"CreateFile - create/open file handle" },
    //{ L"connect",               ExecRisk::Medium,   L"Connect - network connection" },
    //{ L"send",                  ExecRisk::Medium,   L"Send - data send (network/msg)" },
    //{ L"post",                  ExecRisk::Medium,   L"Post - HTTP/data post" },
    //{ L"getresponse",           ExecRisk::Medium,   L"GetResponse - HTTP response" },
    //{ L"setheader",             ExecRisk::Medium,   L"SetHeader - HTTP header manipulation" },
    //{ L"commandline",           ExecRisk::Low,      L"CommandLine property - process cmdline access" },
    //{ L"path",                  ExecRisk::Low,      L"Path property - filesystem path" },
    //{ L"filename",              ExecRisk::Low,      L"FileName property - file path access" },
    //{ L"workingdirectory",      ExecRisk::Low,      L"WorkingDirectory - can affect process launch" },
    //{ L"environment",           ExecRisk::Low,      L"Environment - env variable access/set" },
    //{ L"stdin",                 ExecRisk::Low,      L"StdIn - stdin pipe (with Exec)" },
    //{ L"stdout",                ExecRisk::Low,      L"StdOut - stdout pipe" },
    //{ L"stderr",                ExecRisk::Low,      L"StdErr - stderr pipe" },
};

static ExecRisk ClassifyName(const std::wstring& name)
{
    if (name.empty()) return ExecRisk::None;
    std::wstring low = name;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    ExecRisk best = ExecRisk::None;
    for (auto& kw : kExecKeywords)
        if (low.find(kw.word) != std::wstring::npos)
            if ((int)kw.risk > (int)best) best = kw.risk;
    return best;
}

static const wchar_t* ExecRiskStr(ExecRisk r) {
    switch (r) {
    case ExecRisk::Critical: return L"CRITICAL";
    case ExecRisk::High:     return L"HIGH    ";
    case ExecRisk::Medium:   return L"MEDIUM  ";
    case ExecRisk::Low:      return L"LOW     ";
    default:                 return L"NONE    ";
    }
}
static const wchar_t* ExecRiskColor(ExecRisk r) {
    switch (r) {
    case ExecRisk::Critical: return C_RED;
    case ExecRisk::High:     return C_RED;
    case ExecRisk::Medium:   return C_ORG;
    case ExecRisk::Low:      return C_YEL;
    default:                 return C_DIM;
    }
}
static const wchar_t* ExecRiskReason(const std::wstring& name)
{
    if (name.empty()) return L"";
    std::wstring low = name;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    for (auto& kw : kExecKeywords)
        if (low.find(kw.word) != std::wstring::npos) return kw.reason;
    return L"";
}

// ============================================================
//  VARTYPE -> string
// ============================================================
static std::wstring VarTypeStr(VARTYPE vt)
{
    bool byref = !!(vt & VT_BYREF);
    bool arr = !!(vt & VT_ARRAY);
    vt &= VT_TYPEMASK;
    std::wstring s;
    switch (vt) {
    case VT_EMPTY:      s = L"void";        break;
    case VT_NULL:       s = L"null";        break;
    case VT_I1:         s = L"i8";          break;
    case VT_I2:         s = L"i16";         break;
    case VT_I4:         s = L"i32";         break;
    case VT_I8:         s = L"i64";         break;
    case VT_UI1:        s = L"u8";          break;
    case VT_UI2:        s = L"u16";         break;
    case VT_UI4:        s = L"u32";         break;
    case VT_UI8:        s = L"u64";         break;
    case VT_R4:         s = L"f32";         break;
    case VT_R8:         s = L"f64";         break;
    case VT_BOOL:       s = L"BOOL";        break;
    case VT_BSTR:       s = L"BSTR";        break;
    case VT_VARIANT:    s = L"VARIANT";     break;
    case VT_DISPATCH:   s = L"IDispatch";   break;
    case VT_UNKNOWN:    s = L"IUnknown";    break;
    case VT_HRESULT:    s = L"HRESULT";    break;
    case VT_PTR:        s = L"PTR";         break;
    case VT_SAFEARRAY:  s = L"SAFEARRAY";   break;
    case VT_CARRAY:     s = L"CARRAY";     break;
    case VT_USERDEFINED:s = L"USERDEFINED"; break;
    case VT_LPSTR:      s = L"LPSTR";      break;
    case VT_LPWSTR:     s = L"LPWSTR";     break;
    case VT_DECIMAL:    s = L"DECIMAL";    break;
    case VT_DATE:       s = L"DATE";        break;
    case VT_CY:         s = L"CURRENCY";   break;
    case VT_ERROR:      s = L"SCODE";       break;
    default: { wchar_t b[16]; swprintf_s(b, L"vt%u", vt); s = b; }
    }
    if (arr) s = L"SAFEARRAY(" + s + L")";
    if (byref) s = s + L"*";
    return s;
}

// ============================================================
//  TYPEKIND -> string
// ============================================================
static const wchar_t* TypeKindStr(TYPEKIND tk)
{
    switch (tk) {
    case TKIND_ENUM:       return L"enum";
    case TKIND_RECORD:     return L"struct";
    case TKIND_MODULE:     return L"module";
    case TKIND_INTERFACE:  return L"interface";
    case TKIND_DISPATCH:   return L"dispinterface";
    case TKIND_COCLASS:    return L"coclass";
    case TKIND_ALIAS:      return L"alias";
    case TKIND_UNION:      return L"union";
    default:               return L"unknown";
    }
}

// ============================================================
//  Data structures
// ============================================================
struct MethodInfo {
    std::wstring  name;
    std::wstring  invokeKind;
    std::wstring  retType;
    std::vector<std::pair<std::wstring, std::wstring>> params;
    MEMBERID      memid = 0;
    bool          isHidden = false;
    bool          isRestricted = false;
    ExecRisk      execRisk = ExecRisk::None;
    std::wstring  execReason;
};

struct InterfaceInfo {
    std::wstring            name;
    std::wstring            typeKind;
    std::wstring            iid;
    std::vector<MethodInfo> methods;
    int                     execMethodCount = 0;
    ExecRisk                worstRisk = ExecRisk::None;
};

struct TypeLibInfo {
    std::wstring               name;
    std::wstring               path;
    std::wstring               guid;
    std::vector<InterfaceInfo> interfaces;
    int                        totalMethods = 0;
    int                        execRiskMethods = 0;
    ExecRisk                   worstRisk = ExecRisk::None;
    bool                       loadedOk = false;
    std::wstring               errorMsg;
    std::wstring               loadedVia; // describes how it was loaded
};

// ============================================================
//  Forward declarations
// ============================================================
static bool         IsMicrosoftSigned(const std::wstring& filePath);
static std::wstring RegReadString(HKEY root, const wchar_t* path, const wchar_t* name);
static std::wstring RegReadStringOrDword(HKEY root, const wchar_t* path, const wchar_t* name);
static DWORD        RegReadDWORD(HKEY root, const wchar_t* path, const wchar_t* name, DWORD def = 0);
static bool         RegReadBinary(HKEY root, const wchar_t* path, const wchar_t* name, std::vector<BYTE>& out);
static std::vector<std::wstring> RegEnumSubkeys(HKEY root, const wchar_t* path);
static bool         RegKeyExists(HKEY root, const wchar_t* path);
static std::wstring ExpandEnv(const std::wstring& src);
static bool         IsFile(const std::wstring& path);
static std::wstring GetExecutablePath(const std::wstring& alreadyExpanded);
static std::wstring CLSIDtoAppID(const std::wstring& clsid);
static std::vector<std::wstring> FindCLSIDs(const std::wstring& appid, const std::wstring& hintCLSID);
static TypeLibInfo  AnalyzeTypeLib(ITypeLib* pTL, const std::wstring& srcPath, const std::wstring& via = L"");
static TypeLibInfo  LoadAndAnalyzeTypeLib(const std::wstring& path);

// ============================================================
//  Registry helpers
// ============================================================
static std::wstring RegReadString(HKEY root, const wchar_t* path, const wchar_t* name)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return L"";
    // First query size, then read — supports paths >4096
    DWORD type = 0, sz = 0;
    if (RegQueryValueExW(hk, name, NULL, &type, NULL, &sz) != ERROR_SUCCESS || sz == 0)
    {
        RegCloseKey(hk); return L"";
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ)
    {
        RegCloseKey(hk); return L"";
    }
    std::vector<wchar_t> buf(sz / sizeof(wchar_t) + 2, 0);
    if (RegQueryValueExW(hk, name, NULL, NULL, (LPBYTE)buf.data(), &sz) != ERROR_SUCCESS)
    {
        RegCloseKey(hk); return L"";
    }
    RegCloseKey(hk);
    // Sanitise non-printable (but keep tabs/CR/LF as space)
    for (auto& c : buf) if (c != 0 && c < 0x20) c = L' ';
    return buf.data();
}

static std::wstring RegReadStringOrDword(HKEY root, const wchar_t* path, const wchar_t* name)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return L"";
    DWORD type = 0, sz = 0;
    RegQueryValueExW(hk, name, NULL, &type, NULL, &sz);
    std::wstring result;
    if (type == REG_DWORD) {
        DWORD val = 0; sz = sizeof(DWORD);
        if (RegQueryValueExW(hk, name, NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS) {
            wchar_t buf[32]; swprintf_s(buf, L"%lu", val);
            result = buf;
        }
    }
    else if (type == REG_SZ || type == REG_EXPAND_SZ) {
        if (sz > 0) {
            std::vector<wchar_t> buf(sz / sizeof(wchar_t) + 2, 0);
            if (RegQueryValueExW(hk, name, NULL, NULL, (LPBYTE)buf.data(), &sz) == ERROR_SUCCESS)
                result = buf.data();
        }
    }
    RegCloseKey(hk);
    return result;
}

static DWORD RegReadDWORD(HKEY root, const wchar_t* path, const wchar_t* name, DWORD def)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return def;
    DWORD val = def, sz = sizeof(DWORD);
    RegQueryValueExW(hk, name, NULL, NULL, (LPBYTE)&val, &sz);
    RegCloseKey(hk);
    return val;
}

static bool RegReadBinary(HKEY root, const wchar_t* path, const wchar_t* name, std::vector<BYTE>& out)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = 0;
    LONG r = RegQueryValueExW(hk, name, NULL, &type, NULL, &size);
    if (r != ERROR_SUCCESS || type != REG_BINARY || size == 0) { RegCloseKey(hk); return false; }
    out.resize(size);
    r = RegQueryValueExW(hk, name, NULL, NULL, out.data(), &size);
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

static std::vector<std::wstring> RegEnumSubkeys(HKEY root, const wchar_t* path)
{
    std::vector<std::wstring> keys;
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return keys;
    wchar_t name[512]; DWORD idx = 0, sz;
    while (true) {
        sz = 512;
        if (RegEnumKeyExW(hk, idx++, name, &sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        keys.push_back(name);
    }
    RegCloseKey(hk);
    return keys;
}

static bool RegKeyExists(HKEY root, const wchar_t* path)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return false;
    RegCloseKey(hk); return true;
}

// ============================================================
//  Path / file helpers
// ============================================================
static std::wstring ExpandEnv(const std::wstring& src)
{
    if (src.empty()) return src;
    DWORD size = ExpandEnvironmentStringsW(src.c_str(), NULL, 0);
    if (!size) return src;
    std::vector<wchar_t> buf(size);
    ExpandEnvironmentStringsW(src.c_str(), buf.data(), size);
    return std::wstring(buf.data(), size - 1);
}

// Returns true if path is an existing regular file (not a directory)
static bool IsFile(const std::wstring& path)
{
    if (path.empty()) return false;
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

// Given an already-expanded command line (may have args or resource ID suffix),
// walk space-delimited tokens until we find one that is an existing file.
// Only accepts FILES, not directories.
static std::wstring GetExecutablePath(const std::wstring& alreadyExpanded)
{
    if (alreadyExpanded.empty()) return L"";
    const std::wstring& s = alreadyExpanded;

    // Quoted: "C:\path with spaces\foo.exe" [args]
    if (s[0] == L'"') {
        size_t en = s.find(L'"', 1);
        std::wstring candidate = (en != std::wstring::npos) ? s.substr(1, en - 1) : s.substr(1);
        return candidate; // return as-is; existence checked by caller
    }

    // Unquoted: walk token by token, accepting first existing FILE
    // e.g. "C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE /automation"
    size_t pos = 0;
    while (pos < s.size()) {
        size_t sp = s.find(L' ', pos);
        std::wstring candidate = (sp == std::wstring::npos) ? s : s.substr(0, sp);
        if (IsFile(candidate)) return candidate;
        if (sp == std::wstring::npos) break;
        pos = sp + 1;
    }

    // Fallback: first token (may not exist yet — caller checks)
    size_t sp = s.find(L' ');
    return (sp != std::wstring::npos) ? s.substr(0, sp) : s;
}

// Strip resource-index suffix and args, return clean file path.
// Handles: "C:\foo.dll\3", "C:\foo.exe /arg", etc.
static std::wstring StripToFilePath(const std::wstring& raw)
{
    if (raw.empty()) return L"";
    std::wstring expanded = ExpandEnv(raw);

    // If quoted, extract inner path
    if (!expanded.empty() && expanded[0] == L'"') {
        size_t en = expanded.find(L'"', 1);
        return (en != std::wstring::npos) ? expanded.substr(1, en - 1) : expanded.substr(1);
    }

    // Try to find known extension and cut there
    static const wchar_t* exts[] = { L".olb", L".tlb", L".dll", L".ocx", L".exe", nullptr };
    std::wstring lower = expanded;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    for (auto ext = exts; *ext; ++ext) {
        size_t pos = lower.find(*ext);
        if (pos != std::wstring::npos) {
            std::wstring candidate = expanded.substr(0, pos + wcslen(*ext));
            if (IsFile(candidate)) return candidate;
        }
    }

    // Fallback to token-walk
    return GetExecutablePath(expanded);
}

// ============================================================
//  CLSID / AppID resolution
// ============================================================
static std::wstring ProgIDtoCLSID(const std::wstring& progid)
{
    wchar_t p[512];
    swprintf_s(p, L"%s\\CLSID", progid.c_str());
    std::wstring r = RegReadString(HKEY_CLASSES_ROOT, p, L"");
    if (!r.empty()) return r;
    swprintf_s(p, L"SOFTWARE\\Classes\\%s\\CLSID", progid.c_str());
    return RegReadString(HKEY_LOCAL_MACHINE, p, L"");
}

static std::wstring CLSIDtoAppID(const std::wstring& clsid)
{
    wchar_t p[512];
    swprintf_s(p, L"CLSID\\%s", clsid.c_str());
    std::wstring r = RegReadString(HKEY_CLASSES_ROOT, p, L"AppID");
    if (!r.empty()) return r;
    swprintf_s(p, L"SOFTWARE\\Classes\\CLSID\\%s", clsid.c_str());
    return RegReadString(HKEY_LOCAL_MACHINE, p, L"AppID");
}

static std::vector<std::wstring> FindCLSIDs(const std::wstring& appid, const std::wstring& hintCLSID)
{
    std::vector<std::wstring> result;
    if (!hintCLSID.empty()) result.push_back(hintCLSID);
    if (appid.empty()) return result;
    HKEY hc = NULL;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hc) != ERROR_SUCCESS) return result;
    wchar_t cn[256]; DWORD idx = 0, sz;
    while (true) {
        sz = 256;
        if (RegEnumKeyExW(hc, idx++, cn, &sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        bool already = false;
        for (auto& c : result) if (_wcsicmp(c.c_str(), cn) == 0) { already = true; break; }
        if (already) continue;
        wchar_t su[512]; swprintf_s(su, L"CLSID\\%s", cn);
        std::wstring aid = RegReadString(HKEY_CLASSES_ROOT, su, L"AppID");
        if (!aid.empty() && _wcsicmp(aid.c_str(), appid.c_str()) == 0)
            result.push_back(cn);
    }
    RegCloseKey(hc);
    return result;
}

// ============================================================
//  TypeLib path resolution — comprehensive multi-strategy
// ============================================================

// Given a TypeLib GUID, find the best physical file path.
static std::wstring ResolveTypeLibGUIDToPath(const std::wstring& tlbid)
{
    if (tlbid.empty()) return L"";
    wchar_t tp[512];
    swprintf_s(tp, L"TypeLib\\%s", tlbid.c_str());
    auto vers = RegEnumSubkeys(HKEY_CLASSES_ROOT, tp);
    if (vers.empty()) return L"";

    // Sort descending to try newest version first
    std::sort(vers.rbegin(), vers.rend());

    for (auto& v : vers) {
        // Platforms to try in priority order
        const wchar_t* platforms[] = { L"win64", L"win32", L"", nullptr };
        for (auto plat = platforms; *plat != nullptr; ++plat) {
            wchar_t vp[512];
            if ((*plat)[0])
                swprintf_s(vp, L"TypeLib\\%s\\%s\\0\\%s", tlbid.c_str(), v.c_str(), *plat);
            else
                swprintf_s(vp, L"TypeLib\\%s\\%s\\0", tlbid.c_str(), v.c_str());
            std::wstring raw = RegReadString(HKEY_CLASSES_ROOT, vp, L"");
            if (raw.empty()) continue;
            std::wstring path = StripToFilePath(raw);
            if (!path.empty() && IsFile(path)) return path;
            // Even if file check fails, return the stripped path for the caller to try
            if (!path.empty()) return path;
        }
    }
    return L"";
}

// Main entry: given a CLSID, find where its TypeLib lives.
// Tries multiple strategies so even complex cases like Excel work.
static std::wstring GetTypeLibPath(const std::wstring& clsid)
{
    if (clsid.empty()) return L"";
    wchar_t p[512];

    // --- Strategy 1: CLSID -> TypeLib subkey -> resolve GUID ---
    swprintf_s(p, L"CLSID\\%s\\TypeLib", clsid.c_str());
    std::wstring tlbid = RegReadString(HKEY_CLASSES_ROOT, p, L"");
    if (!tlbid.empty()) {
        std::wstring path = ResolveTypeLibGUIDToPath(tlbid);
        if (!path.empty()) return path;
    }

    // --- Strategy 2: Sibling CLSIDs sharing same AppID may have TypeLib ---
    std::wstring appid = CLSIDtoAppID(clsid);
    if (!appid.empty()) {
        auto siblings = FindCLSIDs(appid, L"");
        for (auto& sib : siblings) {
            if (_wcsicmp(sib.c_str(), clsid.c_str()) == 0) continue;
            swprintf_s(p, L"CLSID\\%s\\TypeLib", sib.c_str());
            tlbid = RegReadString(HKEY_CLASSES_ROOT, p, L"");
            if (!tlbid.empty()) {
                std::wstring path = ResolveTypeLibGUIDToPath(tlbid);
                if (!path.empty()) return path;
            }
        }
    }

    // --- Strategy 3: Scan TypeLib registry by ProgID name prefix ---
    swprintf_s(p, L"CLSID\\%s\\ProgID", clsid.c_str());
    std::wstring progid = RegReadString(HKEY_CLASSES_ROOT, p, L"");
    if (!progid.empty()) {
        // Get prefix before first dot: "Excel.Application.16" -> "Excel"
        std::wstring prefix = progid.substr(0, progid.find(L'.'));
        std::wstring prefixLow = prefix;
        std::transform(prefixLow.begin(), prefixLow.end(), prefixLow.begin(), ::towlower);
        if (!prefixLow.empty()) {
            auto tlbKeys = RegEnumSubkeys(HKEY_CLASSES_ROOT, L"TypeLib");
            for (auto& tguid : tlbKeys) {
                wchar_t tp2[512];
                swprintf_s(tp2, L"TypeLib\\%s", tguid.c_str());
                std::wstring tlbName = RegReadString(HKEY_CLASSES_ROOT, tp2, L"");
                std::wstring tlbLow = tlbName;
                std::transform(tlbLow.begin(), tlbLow.end(), tlbLow.begin(), ::towlower);
                if (tlbLow.find(prefixLow) != std::wstring::npos) {
                    std::wstring path = ResolveTypeLibGUIDToPath(tguid);
                    if (!path.empty()) return path;
                }
            }
        }
    }

    // --- Strategy 4: VersionIndependentProgID scan ---
    swprintf_s(p, L"CLSID\\%s\\VersionIndependentProgID", clsid.c_str());
    std::wstring vipid = RegReadString(HKEY_CLASSES_ROOT, p, L"");
    if (!vipid.empty()) {
        // Try VersionIndependentProgID\CLSID -> TypeLib
        std::wstring altClsid = ProgIDtoCLSID(vipid);
        if (!altClsid.empty() && _wcsicmp(altClsid.c_str(), clsid.c_str()) != 0) {
            swprintf_s(p, L"CLSID\\%s\\TypeLib", altClsid.c_str());
            tlbid = RegReadString(HKEY_CLASSES_ROOT, p, L"");
            if (!tlbid.empty()) {
                std::wstring path = ResolveTypeLibGUIDToPath(tlbid);
                if (!path.empty()) return path;
            }
        }
    }

    // --- Strategy 5: Return binary path so LoadAndAnalyzeTypeLib can try resource IDs ---
    swprintf_s(p, L"CLSID\\%s\\InprocServer32", clsid.c_str());
    std::wstring ip = StripToFilePath(RegReadString(HKEY_CLASSES_ROOT, p, L""));
    if (!ip.empty()) return ip;

    swprintf_s(p, L"CLSID\\%s\\LocalServer32", clsid.c_str());
    std::wstring ls = StripToFilePath(RegReadString(HKEY_CLASSES_ROOT, p, L""));
    return ls;
}

// ============================================================
//  ITypeInfo -> MethodInfo extraction
// ============================================================
static std::wstring GetTypeName(ITypeInfo* pti, const TYPEDESC& td)
{
    if (td.vt == VT_PTR && td.lptdesc)
        return GetTypeName(pti, *td.lptdesc) + L"*";
    if (td.vt == VT_SAFEARRAY && td.lptdesc)
        return L"SAFEARRAY(" + GetTypeName(pti, *td.lptdesc) + L")";
    if (td.vt == VT_USERDEFINED && pti) {
        ITypeInfo* pRef = nullptr;
        if (SUCCEEDED(pti->GetRefTypeInfo(td.hreftype, &pRef)) && pRef) {
            BSTR bName = nullptr;
            pRef->GetDocumentation(MEMBERID_NIL, &bName, nullptr, nullptr, nullptr);
            std::wstring r = bName ? bName : L"USERDEFINED";
            SysFreeString(bName);
            pRef->Release();
            return r;
        }
    }
    return VarTypeStr(td.vt);
}

static std::vector<MethodInfo> ExtractMethods(ITypeInfo* pti)
{
    std::vector<MethodInfo> out;
    if (!pti) return out;
    TYPEATTR* ta = nullptr;
    if (FAILED(pti->GetTypeAttr(&ta)) || !ta) return out;
    WORD cFuncs = ta->cFuncs;
    WORD cVars = ta->cVars;
    pti->ReleaseTypeAttr(ta);

    for (WORD i = 0; i < cFuncs; i++) {
        FUNCDESC* fd = nullptr;
        if (FAILED(pti->GetFuncDesc(i, &fd)) || !fd) continue;
        MethodInfo mi;
        mi.memid = fd->memid;
        mi.isHidden = !!(fd->wFuncFlags & FUNCFLAG_FHIDDEN);
        mi.isRestricted = !!(fd->wFuncFlags & FUNCFLAG_FRESTRICTED);
        switch (fd->invkind) {
        case INVOKE_FUNC:           mi.invokeKind = L"method  "; break;
        case INVOKE_PROPERTYGET:    mi.invokeKind = L"propget "; break;
        case INVOKE_PROPERTYPUT:    mi.invokeKind = L"propput "; break;
        case INVOKE_PROPERTYPUTREF: mi.invokeKind = L"propputref"; break;
        default:                    mi.invokeKind = L"unknown "; break;
        }
        mi.retType = GetTypeName(pti, fd->elemdescFunc.tdesc);
        UINT cNames = fd->cParams + 1;
        std::vector<BSTR> names(cNames, nullptr);
        UINT gotNames = 0;
        pti->GetNames(fd->memid, names.data(), cNames, &gotNames);
        if (gotNames > 0 && names[0]) mi.name = names[0];
        for (SHORT par = 0; par < fd->cParams; par++) {
            std::wstring pType = GetTypeName(pti, fd->lprgelemdescParam[par].tdesc);
            std::wstring pName;
            if ((UINT)(par + 1) < gotNames && names[par + 1]) pName = names[par + 1];
            else { wchar_t buf[16]; swprintf_s(buf, L"p%d", par); pName = buf; }
            mi.params.emplace_back(pType, pName);
        }
        for (auto& b : names) SysFreeString(b);
        mi.execRisk = ClassifyName(mi.name);
        mi.execReason = ExecRiskReason(mi.name);
        pti->ReleaseFuncDesc(fd);
        out.push_back(std::move(mi));
    }

    for (WORD i = 0; i < cVars; i++) {
        VARDESC* vd = nullptr;
        if (FAILED(pti->GetVarDesc(i, &vd)) || !vd) continue;
        MethodInfo mi;
        mi.invokeKind = L"propget ";
        mi.retType = GetTypeName(pti, vd->elemdescVar.tdesc);
        mi.memid = vd->memid;
        BSTR bName = nullptr; UINT got = 0;
        pti->GetNames(vd->memid, &bName, 1, &got);
        if (got && bName) mi.name = bName;
        SysFreeString(bName);
        mi.execRisk = ClassifyName(mi.name);
        mi.execReason = ExecRiskReason(mi.name);
        pti->ReleaseVarDesc(vd);
        out.push_back(std::move(mi));
    }
    return out;
}

// ============================================================
//  TypeLib loading — multiple strategies including resource IDs
// ============================================================
static TypeLibInfo AnalyzeTypeLib(ITypeLib* pTL, const std::wstring& srcPath, const std::wstring& via)
{
    TypeLibInfo info;
    info.path = srcPath;
    info.loadedOk = true;
    info.loadedVia = via;

    BSTR bLibName = nullptr;
    pTL->GetDocumentation(-1, &bLibName, nullptr, nullptr, nullptr);
    if (bLibName) { info.name = bLibName; SysFreeString(bLibName); }

    TLIBATTR* la = nullptr;
    if (SUCCEEDED(pTL->GetLibAttr(&la)) && la) {
        wchar_t guid[64];
        StringFromGUID2(la->guid, guid, 64);
        info.guid = guid;
        pTL->ReleaseTLibAttr(la);
    }

    UINT count = pTL->GetTypeInfoCount();
    for (UINT i = 0; i < count; i++) {
        ITypeInfo* pTI = nullptr;
        if (FAILED(pTL->GetTypeInfo(i, &pTI)) || !pTI) continue;
        TYPEATTR* ta = nullptr;
        if (FAILED(pTI->GetTypeAttr(&ta)) || !ta) { pTI->Release(); continue; }
        TYPEKIND tk = ta->typekind;
        GUID iid = ta->guid;
        pTI->ReleaseTypeAttr(ta);

        InterfaceInfo iface;
        iface.typeKind = TypeKindStr(tk);
        wchar_t iidStr[64]; StringFromGUID2(iid, iidStr, 64);
        iface.iid = iidStr;
        BSTR bName = nullptr;
        pTL->GetDocumentation(i, &bName, nullptr, nullptr, nullptr);
        if (bName) { iface.name = bName; SysFreeString(bName); }

        if (tk == TKIND_INTERFACE || tk == TKIND_DISPATCH || tk == TKIND_COCLASS) {
            iface.methods = ExtractMethods(pTI);
            for (auto& m : iface.methods) {
                info.totalMethods++;
                if (m.execRisk >= ExecRisk::Medium) { info.execRiskMethods++; iface.execMethodCount++; }
                if ((int)m.execRisk > (int)iface.worstRisk) iface.worstRisk = m.execRisk;
                if ((int)m.execRisk > (int)info.worstRisk)  info.worstRisk = m.execRisk;
            }
        }
        pTI->Release();
        info.interfaces.push_back(std::move(iface));
    }
    return info;
}

static TypeLibInfo LoadAndAnalyzeTypeLib(const std::wstring& path)
{
    TypeLibInfo info;
    info.path = path;
    if (path.empty()) { info.errorMsg = L"No path provided"; return info; }

    // Resolve to a clean file path first
    std::wstring exe = StripToFilePath(path);
    if (exe.empty()) exe = path;

    // Helper: try a single path string
    auto TryLoad = [](const std::wstring& tryPath) -> ITypeLib* {
        ITypeLib* pTL = nullptr;
        if (SUCCEEDED(LoadTypeLib(tryPath.c_str(), &pTL)) && pTL) return pTL;
        if (SUCCEEDED(LoadTypeLibEx(tryPath.c_str(), REGKIND_NONE, &pTL)) && pTL) return pTL;
        return nullptr;
        };

    ITypeLib* pTL = nullptr;
    std::wstring via;

    // 1. Direct load (works for .tlb, .olb, and some DLLs)
    pTL = TryLoad(exe);
    if (pTL) { via = L"direct"; }

    // 2. Try resource IDs \1 .. \16  (DLLs/EXEs that embed typelib as Win32 resource)
    if (!pTL) {
        for (int rid = 1; rid <= 16 && !pTL; rid++) {
            std::wstring withRes = exe + L"\\" + std::to_wstring(rid);
            pTL = TryLoad(withRes);
            if (pTL) { via = L"resource \\" + std::to_wstring(rid); }
        }
    }

    // 3. If path came in with env vars still unexpanded, try again
    if (!pTL) {
        std::wstring expanded = ExpandEnv(path);
        std::wstring exe2 = StripToFilePath(expanded);
        if (!exe2.empty() && _wcsicmp(exe2.c_str(), exe.c_str()) != 0) {
            pTL = TryLoad(exe2);
            if (pTL) { exe = exe2; via = L"expanded direct"; }
            if (!pTL) {
                for (int rid = 1; rid <= 16 && !pTL; rid++) {
                    std::wstring withRes = exe2 + L"\\" + std::to_wstring(rid);
                    pTL = TryLoad(withRes);
                    if (pTL) { exe = exe2; via = L"expanded resource \\" + std::to_wstring(rid); }
                }
            }
        }
    }

    if (!pTL) {
        wchar_t msg[256];
        swprintf_s(msg, L"LoadTypeLib failed (tried direct + resource IDs \\1-\\16). HRESULT: checked.");
        info.errorMsg = msg;
        return info;
    }

    info = AnalyzeTypeLib(pTL, exe, via);
    pTL->Release();
    return info;
}

// ============================================================
//  IDispatch live probe
// ============================================================
struct DispatchProbe {
    bool         succeeded = false;
    std::wstring errorMsg;
    std::vector<MethodInfo> methods;
    ExecRisk     worstRisk = ExecRisk::None;
};

// Map common HRESULTs to readable strings
static std::wstring HrToStr(HRESULT hr)
{
    struct { HRESULT hr; const wchar_t* msg; } table[] = {
        { 0x80004002, L"E_NOINTERFACE" },
        { 0x80040154, L"REGDB_E_CLASSNOTREG" },
        { 0x80070005, L"E_ACCESSDENIED" },
        { 0x800706BA, L"RPC_S_SERVER_UNAVAILABLE" },
        { 0x80004005, L"E_FAIL" },
        { 0x80004001, L"E_NOTIMPL" },
        { 0x8007007E, L"ERROR_MOD_NOT_FOUND" },
        { 0x80040201, L"CO_E_SERVER_EXEC_FAILURE" },
    };
    for (auto& e : table) if (e.hr == (HRESULT)hr) return e.msg;
    wchar_t buf[32]; swprintf_s(buf, L"0x%08X", (unsigned)hr); return buf;
}

static DispatchProbe ProbeViaDispatch(const std::wstring& clsid)
{
    DispatchProbe result;
    CLSID cls = {};
    if (FAILED(CLSIDFromString(clsid.c_str(), &cls))) {
        result.errorMsg = L"Invalid CLSID"; return result;
    }

    IDispatch* pDisp = nullptr;
    HRESULT hr = E_FAIL;

    // 1. GetActiveObject: reuse existing instance (important for Excel, Word, etc.)
    IUnknown* pUnkActive = nullptr;
    if (SUCCEEDED(GetActiveObject(cls, nullptr, &pUnkActive)) && pUnkActive) {
        pUnkActive->QueryInterface(IID_IDispatch, (void**)&pDisp);
        pUnkActive->Release();
        if (pDisp) hr = S_OK;
    }

    // 2. CoCreateInstance -> IDispatch directly
    if (!pDisp)
        hr = CoCreateInstance(cls, nullptr, CLSCTX_ALL, IID_IDispatch, (void**)&pDisp);

    // 3. CoCreateInstance -> IUnknown -> QI IDispatch
    if (FAILED(hr) || !pDisp) {
        IUnknown* pUnk = nullptr;
        hr = CoCreateInstance(cls, nullptr, CLSCTX_ALL, IID_IUnknown, (void**)&pUnk);
        if (SUCCEEDED(hr) && pUnk) {
            hr = pUnk->QueryInterface(IID_IDispatch, (void**)&pDisp);
            pUnk->Release();
        }
    }

    if (FAILED(hr) || !pDisp) {
        result.errorMsg = L"Cannot instantiate: " + HrToStr(hr);
        return result;
    }

    // Get ITypeInfo from live object
    ITypeInfo* pTI = nullptr;
    hr = pDisp->GetTypeInfo(0, LOCALE_USER_DEFAULT, &pTI);
    if (SUCCEEDED(hr) && pTI) {
        result.methods = ExtractMethods(pTI);
        result.succeeded = true;
        for (auto& m : result.methods)
            if ((int)m.execRisk > (int)result.worstRisk) result.worstRisk = m.execRisk;
        pTI->Release();
    }
    else {
        result.errorMsg = L"GetTypeInfo failed: " + HrToStr(hr)
            + L" (object may need to be running first)";
    }
    pDisp->Release();
    return result;
}

// ============================================================
//  Print TypeLib analysis
// ============================================================
static void PrintTypeLibInfo(const TypeLibInfo& tl, bool execOnly, int indent = 2)
{
    wchar_t pad[33] = {};
    for (int i = 0; i < indent && i < 32; i++) pad[i] = L' ';

    if (!tl.loadedOk) {
        wprintf(L"%s%s[!] TypeLib load error: %s%s\n", pad, CC(C_RED), tl.errorMsg.c_str(), CC(C_RST));
        return;
    }

    wprintf(L"%s%sTypeLib%s : %s  (%s)\n", pad, CC(C_BOLD), CC(C_RST),
        tl.name.empty() ? L"(unnamed)" : tl.name.c_str(), tl.guid.c_str());
    wprintf(L"%sPath    : %s\n", pad, tl.path.c_str());
    if (!tl.loadedVia.empty())
        wprintf(L"%sLoaded  : via %s\n", pad, tl.loadedVia.c_str());
    wprintf(L"%sMethods : %d total,  %s%d with exec risk%s\n",
        pad, tl.totalMethods,
        tl.execRiskMethods > 0 ? CC(C_RED) : CC(C_GRN),
        tl.execRiskMethods, CC(C_RST));

    for (auto& iface : tl.interfaces) {
        if (execOnly && iface.execMethodCount == 0) continue;
        if (iface.methods.empty() && execOnly) continue;

        wprintf(L"\n%s  %s[%s]%s %s%s%s",
            pad, CC(C_CYN), iface.typeKind.c_str(), CC(C_RST),
            CC(C_WHT), iface.name.empty() ? L"(unnamed)" : iface.name.c_str(), CC(C_RST));
        if (!iface.iid.empty() && iface.iid != L"{00000000-0000-0000-0000-000000000000}")
            wprintf(L"  %s%s%s", CC(C_DIM), iface.iid.c_str(), CC(C_RST));
        if (iface.execMethodCount > 0)
            wprintf(L"  %s<-- %d exec-capable>%s",
                CC(ExecRiskColor(iface.worstRisk)), iface.execMethodCount, CC(C_RST));
        wprintf(L"\n");

        wprintf(L"%s    %s%-12s %-12s %-24s  Signature%s\n",
            pad, CC(C_DIM), L"Kind", L"ExecRisk", L"Name", CC(C_RST));
        wprintf(L"%s    %s%s%s\n", pad, CC(C_DIM),
            L"-----------------------------------------------------------------------", CC(C_RST));

        for (auto& m : iface.methods) {
            if (execOnly && m.execRisk < ExecRisk::Medium) continue;
            if (m.isRestricted && m.execRisk == ExecRisk::None) continue;

            const wchar_t* rColor = ExecRiskColor(m.execRisk);
            const wchar_t* rStr = (m.execRisk == ExecRisk::None) ? L"       " : ExecRiskStr(m.execRisk);
            std::wstring sig = m.retType + L" " + (m.name.empty() ? L"<unnamed>" : m.name) + L"(";
            for (size_t pi = 0; pi < m.params.size(); pi++) {
                if (pi) sig += L", ";
                sig += m.params[pi].first + L" " + m.params[pi].second;
            }
            sig += L")";

            wprintf(L"%s    %s%-12s%s %s%-12s%s %-24s  %s\n",
                pad, CC(C_DIM), m.invokeKind.c_str(), CC(C_RST),
                CC(rColor), rStr, CC(C_RST),
                m.name.empty() ? L"<unnamed>" : m.name.c_str(),
                sig.c_str());
            if (m.execRisk >= ExecRisk::Low && !m.execReason.empty())
                wprintf(L"%s      %s-> %s%s\n", pad, CC(rColor), m.execReason.c_str(), CC(C_RST));
        }
    }
}

// ============================================================
//  WinVerifyTrust
// ============================================================
static bool IsMicrosoftSigned(const std::wstring& filePath)
{
    if (filePath.empty() || !IsFile(filePath)) return false;
    WINTRUST_FILE_INFO fi = { sizeof(WINTRUST_FILE_INFO), filePath.c_str() };
    WINTRUST_DATA wd = { sizeof(WINTRUST_DATA) };
    wd.dwUIChoice = WTD_UI_NONE;
    wd.dwProvFlags = WTD_SAFER_FLAG | WTD_USE_DEFAULT_OSVER_CHECK;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    GUID pol = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    return (WinVerifyTrust(NULL, &pol, &wd) == ERROR_SUCCESS);
}

// ============================================================
//  Binary writable check — uses AccessCheck, not CreateFile open
//  Returns true only if a non-admin principal can write
// ============================================================
static bool CheckBinaryWritableByNonAdmin(const std::wstring& filePath)
{
    if (filePath.empty() || !IsFile(filePath)) return false;

    // Get file security descriptor
    DWORD sdSize = 0;
    GetFileSecurityW(filePath.c_str(),
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        NULL, 0, &sdSize);
    if (sdSize == 0) return false;

    std::vector<BYTE> sdBuf(sdSize);
    if (!GetFileSecurityW(filePath.c_str(),
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        sdBuf.data(), sdSize, &sdSize)) return false;

    PACL dacl = NULL; BOOL present = FALSE, defaulted = FALSE;
    GetSecurityDescriptorDacl(sdBuf.data(), &present, &dacl, &defaulted);
    if (!present || !dacl) return false;

    // Check each ACE: if a non-admin SID gets write rights, flag it
    // "Risky" write principals: Everyone, Users, Authenticated Users, Network, Interactive
    static const wchar_t* riskySids[] = {
        L"S-1-1-0",      // Everyone
        L"S-1-5-11",     // Authenticated Users
        L"S-1-5-32-545", // Users
        L"S-1-5-2",      // Network
        L"S-1-5-4",      // Interactive
        nullptr
    };

    ACL_SIZE_INFORMATION asi = {};
    GetAclInformation(dacl, &asi, sizeof(asi), AclSizeInformation);
    for (DWORD i = 0; i < asi.AceCount; i++) {
        LPVOID pAce = NULL;
        if (!GetAce(dacl, i, &pAce)) continue;
        ACE_HEADER* hdr = (ACE_HEADER*)pAce;
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        ACCESS_ALLOWED_ACE* ace = (ACCESS_ALLOWED_ACE*)pAce;
        if (!(ace->Mask & (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER | FILE_APPEND_DATA)))
            continue;
        PSID sid = (PSID)&ace->SidStart;
        LPWSTR sidStr = NULL;
        ConvertSidToStringSidW(sid, &sidStr);
        if (!sidStr) continue;
        for (auto rs = riskySids; *rs; ++rs) {
            if (_wcsicmp(sidStr, *rs) == 0) {
                LocalFree(sidStr);
                return true;
            }
        }
        LocalFree(sidStr);
    }
    return false;
}

// ============================================================
//  Impersonation / Auth level decode
// ============================================================
static std::wstring ImpLevelDecode(const std::wstring& raw)
{
    if (raw.empty()) return L"2 - Identify (system default)";
    DWORD val = (raw.size() > 1 && raw[0] == L'0' && (raw[1] == L'x' || raw[1] == L'X'))
        ? (DWORD)wcstoul(raw.c_str(), nullptr, 16)
        : (DWORD)wcstoul(raw.c_str(), nullptr, 10);
    switch (val) {
    case 1: return L"1 - Anonymous";
    case 2: return L"2 - Identify (system default)";
    case 3: return L"3 - Impersonate";
    case 4: return L"4 - Delegate";
    default: return L"0 - Default (usually Identify)";
    }
}
static std::wstring AuthLevelDecode(const std::wstring& raw)
{
    if (raw.empty()) return L"0 - Default";
    DWORD val = (raw.size() > 1 && raw[0] == L'0' && (raw[1] == L'x' || raw[1] == L'X'))
        ? (DWORD)wcstoul(raw.c_str(), nullptr, 16)
        : (DWORD)wcstoul(raw.c_str(), nullptr, 10);
    switch (val) {
    case 1: return L"1 - None";
    case 2: return L"2 - Connect";
    case 3: return L"3 - Call";
    case 4: return L"4 - Packet";
    case 5: return L"5 - PacketIntegrity";
    case 6: return L"6 - PacketPrivacy";
    default: return L"0 - Default (usually Packet)";
    }
}

// ============================================================
//  SID / ACE / SD helpers
// ============================================================
static std::wstring SidToName(PSID sid)
{
    if (!sid || !IsValidSid(sid)) return L"<invalid-SID>";
    wchar_t acct[256] = {}, dom[256] = {};
    DWORD as = 256, ds = 256; SID_NAME_USE use;
    if (LookupAccountSidW(NULL, sid, acct, &as, dom, &ds, &use)) {
        std::wstring r;
        if (ds > 1 && dom[0]) { r = dom; r += L"\\"; }
        r += acct; return r;
    }
    LPWSTR str = NULL; ConvertSidToStringSidW(sid, &str);
    std::wstring r = str ? str : L"<unknown>"; if (str) LocalFree(str); return r;
}
static std::wstring SidToStr(PSID sid)
{
    LPWSTR s = NULL; ConvertSidToStringSidW(sid, &s);
    std::wstring r = s ? s : L""; if (s) LocalFree(s); return r;
}

#define COM_RIGHTS_EXECUTE         0x01
#define COM_RIGHTS_EXECUTE_LOCAL   0x02
#define COM_RIGHTS_EXECUTE_REMOTE  0x04
#define COM_RIGHTS_ACTIVATE_LOCAL  0x08
#define COM_RIGHTS_ACTIVATE_REMOTE 0x10

static std::wstring ComMaskStr(DWORD mask)
{
    wchar_t buf[256] = {};
    if (mask & COM_RIGHTS_EXECUTE)         wcscat_s(buf, L"Execute ");
    if (mask & COM_RIGHTS_EXECUTE_LOCAL)   wcscat_s(buf, L"ExecLocal ");
    if (mask & COM_RIGHTS_EXECUTE_REMOTE)  wcscat_s(buf, L"ExecRemote ");
    if (mask & COM_RIGHTS_ACTIVATE_LOCAL)  wcscat_s(buf, L"ActLocal ");
    if (mask & COM_RIGHTS_ACTIVATE_REMOTE) wcscat_s(buf, L"ActRemote ");
    if (!buf[0]) swprintf_s(buf, L"0x%08X", mask);
    return buf;
}
static const wchar_t* AceTypeName(BYTE t)
{
    switch (t) {
    case ACCESS_ALLOWED_ACE_TYPE: return L"Allow";
    case ACCESS_DENIED_ACE_TYPE:  return L"Deny ";
    default:                      return L"Other";
    }
}
struct AceEntry { bool allow; DWORD mask; std::wstring sidStr, sidName; };

static std::vector<AceEntry> ExtractACEs(PACL acl)
{
    std::vector<AceEntry> out;
    if (!acl) return out;
    ACL_SIZE_INFORMATION asi = {};
    GetAclInformation(acl, &asi, sizeof(asi), AclSizeInformation);
    for (DWORD i = 0; i < asi.AceCount; i++) {
        LPVOID p = NULL; if (!GetAce(acl, i, &p)) continue;
        ACE_HEADER* h = (ACE_HEADER*)p;
        if (h->AceType != ACCESS_ALLOWED_ACE_TYPE && h->AceType != ACCESS_DENIED_ACE_TYPE &&
            h->AceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE && h->AceType != ACCESS_DENIED_OBJECT_ACE_TYPE) continue;
        ACCESS_ALLOWED_ACE* a = (ACCESS_ALLOWED_ACE*)p;
        PSID sid = (PSID)&a->SidStart;
        AceEntry e;
        e.allow = (h->AceType == ACCESS_ALLOWED_ACE_TYPE || h->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE);
        e.mask = a->Mask; e.sidStr = SidToStr(sid); e.sidName = SidToName(sid);
        out.push_back(e);
    }
    return out;
}
static std::vector<AceEntry> BinToACEs(const std::vector<BYTE>& bin)
{
    if (bin.empty()) return {};
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)(void*)bin.data();
    PACL acl = NULL; BOOL p = FALSE, d = FALSE;
    GetSecurityDescriptorDacl(sd, &p, &acl, &d);
    return ExtractACEs(acl);
}

static void PrintSD(BYTE* bin, DWORD, int indent)
{
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)bin;
    wchar_t pad[33] = {}; for (int i = 0; i < indent && i < 32; i++) pad[i] = L' ';
    LPWSTR sddl = NULL;
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
        sd, SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, &sddl, NULL))
    {
        wprintf(L"%s%sSDDL%s: %s\n", pad, CC(C_CYN), CC(C_RST), sddl); LocalFree(sddl);
    }

    PSID own = NULL; BOOL od = FALSE;
    if (GetSecurityDescriptorOwner(sd, &own, &od) && own)
        wprintf(L"%sOwner: %s\n", pad, SidToName(own).c_str());

    PACL dacl = NULL; BOOL dp = FALSE, dd = FALSE;
    GetSecurityDescriptorDacl(sd, &dp, &dacl, &dd);
    if (!dp) { wprintf(L"%s%sDACL: NULL (everyone granted)%s\n", pad, CC(C_YEL), CC(C_RST)); return; }
    if (!dacl) { wprintf(L"%s%sDACL: Empty (everyone denied)%s\n", pad, CC(C_RED), CC(C_RST)); return; }

    ACL_SIZE_INFORMATION asi = {};
    GetAclInformation(dacl, &asi, sizeof(asi), AclSizeInformation);
    wprintf(L"%sDACL: %lu ACE(s)%s\n", pad, asi.AceCount, dd ? L" [default]" : L"");
    for (DWORD i = 0; i < asi.AceCount; i++) {
        LPVOID p2 = NULL; if (!GetAce(dacl, i, &p2)) continue;
        ACE_HEADER* h = (ACE_HEADER*)p2;
        PSID sid = NULL; DWORD mask = 0;
        if (h->AceType == ACCESS_ALLOWED_ACE_TYPE || h->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE* a = (ACCESS_ALLOWED_ACE*)p2; mask = a->Mask; sid = (PSID)&a->SidStart;
        }
        bool isA = (h->AceType == ACCESS_ALLOWED_ACE_TYPE || h->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE);
        std::wstring sn = sid ? SidToName(sid) : L"<no-SID>";
        wprintf(L"%s  [%lu] %s%s%s  %-40s  %s%s%s\n",
            pad, i, isA ? CC(C_GRN) : CC(C_RED), AceTypeName(h->AceType), CC(C_RST),
            sn.c_str(), CC(C_MAG), ComMaskStr(mask).c_str(), CC(C_RST));
    }
}

// ============================================================
//  Server type detection
// ============================================================
enum class SrvType { Unknown, InProc, LocalServer, Service, Surrogate };
struct ServerInfo {
    SrvType      type = SrvType::Unknown;
    std::wstring imagePath, threadingModel, serviceName, serviceAccount, progID, typeLabel;
    bool         imgMissing = false, imgWritable = false, imgSigned = false;
};

static std::wstring ServiceAccount(const std::wstring& svcName)
{
    if (svcName.empty()) return L"";
    wchar_t p[512]; swprintf_s(p, L"SYSTEM\\CurrentControlSet\\Services\\%s", svcName.c_str());
    std::wstring acct = RegReadString(HKEY_LOCAL_MACHINE, p, L"ObjectName");
    if (acct.empty()) acct = RegReadString(HKEY_LOCAL_MACHINE, p, L"ServiceAccount");
    if (acct.empty()) {
        if (!RegReadString(HKEY_LOCAL_MACHINE, p, L"ImagePath").empty())
            acct = L"LocalSystem (default)";
    }
    return acct;
}

static void CheckImage(ServerInfo& si, const std::wstring& cmdLine)
{
    if (cmdLine.empty()) return;
    std::wstring expanded = ExpandEnv(cmdLine);
    std::wstring path;

    // Quoted path
    if (!expanded.empty() && expanded[0] == L'"') {
        size_t en = expanded.find(L'"', 1);
        path = (en != std::wstring::npos) ? expanded.substr(1, en - 1) : expanded.substr(1);
    }
    else {
        // Walk tokens, accept first existing FILE (not directory)
        size_t pos = 0;
        while (pos < expanded.size()) {
            size_t sp = expanded.find(L' ', pos);
            std::wstring candidate = (sp == std::wstring::npos) ? expanded : expanded.substr(0, sp);
            if (IsFile(candidate)) { path = candidate; break; }
            if (sp == std::wstring::npos) break;
            pos = sp + 1;
        }
        if (path.empty()) {
            size_t sp = expanded.find(L' ');
            path = (sp != std::wstring::npos) ? expanded.substr(0, sp) : expanded;
        }
    }

    si.imagePath = path;
    if (si.imagePath.empty()) return;

    DWORD attr = GetFileAttributesW(si.imagePath.c_str());
    si.imgMissing = (attr == INVALID_FILE_ATTRIBUTES);
    if (!si.imgMissing) {
        si.imgSigned = IsMicrosoftSigned(si.imagePath);
        si.imgWritable = CheckBinaryWritableByNonAdmin(si.imagePath);
    }
}

static ServerInfo DetectServerType(const std::wstring& clsid,
    const std::wstring& svcName, const std::wstring& dllSurrogate)
{
    ServerInfo si;
    wchar_t sub[600];
    if (!svcName.empty()) {
        si.type = SrvType::Service; si.serviceName = svcName;
        si.serviceAccount = ServiceAccount(svcName);
        if (si.serviceAccount.empty()) si.serviceAccount = L"LocalSystem (default)";
        si.typeLabel = L"Windows Service";
        if (!clsid.empty()) {
            swprintf_s(sub, L"CLSID\\%s\\LocalServer32", clsid.c_str());
            std::wstring img = RegReadString(HKEY_CLASSES_ROOT, sub, L"");
            if (!img.empty()) CheckImage(si, img);
        }
        return si;
    }
    if (clsid.empty()) { si.typeLabel = L"Unknown"; return si; }

    swprintf_s(sub, L"CLSID\\%s\\LocalServer32", clsid.c_str());
    std::wstring ls32 = RegReadString(HKEY_CLASSES_ROOT, sub, L"");
    if (!ls32.empty()) {
        si.type = SrvType::LocalServer;
        si.typeLabel = L"LocalServer32 (out-of-process EXE)";
        CheckImage(si, ls32); return si;
    }

    swprintf_s(sub, L"CLSID\\%s\\InprocServer32", clsid.c_str());
    std::wstring ip32 = RegReadString(HKEY_CLASSES_ROOT, sub, L"");
    std::wstring tm = RegReadString(HKEY_CLASSES_ROOT, sub, L"ThreadingModel");
    if (!ip32.empty()) {
        si.type = dllSurrogate.empty() ? SrvType::InProc : SrvType::Surrogate;
        si.typeLabel = dllSurrogate.empty()
            ? L"InprocServer32 (in-process DLL)"
            : L"DLL Surrogate (dllhost.exe)";
        si.threadingModel = tm;
        CheckImage(si, ip32); return si;
    }
    si.typeLabel = L"Unknown (no LocalServer32/InprocServer32)";
    return si;
}

// ============================================================
//  Identity / Attack Surface / Risk
// ============================================================
struct Identity {
    std::wstring account, resolved, remark;
    bool isPrivileged = false;
};

static Identity ResolveIdentity(const std::wstring& runas, const ServerInfo& sv)
{
    Identity id;
    if (!sv.serviceAccount.empty()) {
        id.account = L"(service) " + sv.serviceName;
        id.resolved = sv.serviceAccount;
        std::wstring low = sv.serviceAccount;
        std::transform(low.begin(), low.end(), low.begin(), ::towlower);
        id.isPrivileged = (low.find(L"localsystem") != std::wstring::npos || low == L"system");
        id.remark = id.isPrivileged
            ? L"SYSTEM service - PrivEsc risk if non-admin can launch"
            : L"Service: " + sv.serviceAccount;
        return id;
    }
    id.account = runas;
    if (runas.empty()) { id.resolved = L"Launching User"; id.remark = L"No privilege boundary"; return id; }
    std::wstring low = runas;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    if (low == L"interactive user") { id.resolved = L"Interactive User"; id.remark = L"No privilege boundary"; }
    else if (low == L"system" || low == L"nt authority\\system") {
        id.resolved = L"NT AUTHORITY\\SYSTEM"; id.isPrivileged = true;
        id.remark = L"SYSTEM - HIGH privilege escalation risk";
    }
    else { id.resolved = runas; id.remark = L"Specific account - verify manually"; }
    return id;
}

static const struct { const wchar_t* sid; const wchar_t* name; } kPrincipals[] = {
    { L"S-1-1-0",      L"Everyone"              },
    { L"S-1-5-11",     L"Authenticated Users"   },
    { L"S-1-5-7",      L"Anonymous Logon"       },
    { L"S-1-5-18",     L"SYSTEM"                },
    { L"S-1-5-32-544", L"Administrators"        },
    { L"S-1-5-32-562", L"Distributed COM Users" },
    { L"S-1-5-4",      L"Interactive"           },
    { L"S-1-5-2",      L"Network"               },
};

struct SurfaceRow { std::wstring principal; bool ll, rl, la, ra; };

static DWORD EffMask(const std::vector<AceEntry>& aces, const wchar_t* sid)
{
    DWORD allow = 0, deny = 0;
    for (auto& a : aces) if (_wcsicmp(a.sidStr.c_str(), sid) == 0) {
        if (a.allow) allow |= a.mask; else deny |= a.mask;
    }
    return allow & ~deny;
}

static std::vector<SurfaceRow> ComputeSurface(
    const std::vector<AceEntry>& la, const std::vector<AceEntry>& aa,
    const std::vector<AceEntry>& mlr, const std::vector<AceEntry>& mar)
{
    std::vector<SurfaceRow> rows;
    for (auto& pr : kPrincipals) {
        DWORD lm = EffMask(la, pr.sid), am = EffMask(aa, pr.sid);
        DWORD lrm = EffMask(mlr, pr.sid), arm = EffMask(mar, pr.sid);
        if (!lm && !am && !lrm && !arm) continue;
        DWORD effL = lrm ? (lm & lrm) : lm;
        DWORD effA = arm ? (am & arm) : am;
        SurfaceRow r;
        r.principal = pr.name;
        r.ll = !!(effL & (COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL | COM_RIGHTS_ACTIVATE_LOCAL));
        r.rl = !!(effL & (COM_RIGHTS_EXECUTE_REMOTE | COM_RIGHTS_ACTIVATE_REMOTE));
        r.la = !!(effA & (COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL));
        r.ra = !!(effA & COM_RIGHTS_EXECUTE_REMOTE);
        rows.push_back(r);
    }
    return rows;
}

enum class RiskLevel { None, Low, Medium, High, Critical };
struct RiskResult {
    RiskLevel level = RiskLevel::None;
    bool privesc = false, lateral = false, hijack = false, autoElev = false, dcomOpen = false;
    std::vector<std::wstring> reasons, mitigations;
};

static const wchar_t* RiskLevelStr(RiskLevel l)
{
    switch (l) {
    case RiskLevel::Critical: return L"CRITICAL";
    case RiskLevel::High:     return L"HIGH    ";
    case RiskLevel::Medium:   return L"MEDIUM  ";
    case RiskLevel::Low:      return L"LOW     ";
    default:                  return L"NONE    ";
    }
}
static const wchar_t* RiskLevelColor(RiskLevel l)
{
    switch (l) {
    case RiskLevel::Critical:
    case RiskLevel::High:   return C_RED;
    case RiskLevel::Medium: return C_ORG;
    case RiskLevel::Low:    return C_YEL;
    default:                return C_GRN;
    }
}

static RiskResult EvaluateRisk(const Identity& id, const ServerInfo& sv,
    const std::vector<SurfaceRow>& surf, bool elevEnabled, const TypeLibInfo& tl)
{
    RiskResult r;
    bool anyRemote = false;
    for (auto& row : surf) if (row.rl || row.ra) { anyRemote = true; break; }
    r.dcomOpen = anyRemote;

    if (id.isPrivileged)
        for (auto& row : surf)
            if ((row.principal == L"Everyone" || row.principal == L"Authenticated Users" ||
                row.principal == L"Interactive" || row.principal == L"Network") && (row.ll || row.rl)) {
                r.privesc = true;
                r.reasons.push_back(L"Server runs as [" + id.resolved + L"] and [" + row.principal + L"] can launch");
            }

    for (auto& row : surf)
        if (row.principal == L"Everyone" || row.principal == L"Authenticated Users" || row.principal == L"Network") {
            if (row.rl) { r.lateral = true; r.reasons.push_back(L"Remote LAUNCH for " + row.principal); }
            if (row.ra) { r.lateral = true; r.reasons.push_back(L"Remote ACCESS for " + row.principal); }
        }

    if (sv.imgMissing) { r.hijack = true; r.reasons.push_back(L"Binary NOT FOUND: " + sv.imagePath); }
    if (sv.imgWritable) { r.hijack = true; r.reasons.push_back(L"Binary WRITABLE by non-admin: " + sv.imagePath); }
    if (elevEnabled) { r.autoElev = true; r.reasons.push_back(L"Elevation\\Enabled=1 - UAC bypass surface"); }

    if (tl.loadedOk && tl.execRiskMethods > 0) {
        r.reasons.push_back(L"TypeLib exposes " + std::to_wstring(tl.execRiskMethods) +
            L" exec-capable method(s) - worst: " + ExecRiskStr(tl.worstRisk));
        if (tl.worstRisk == ExecRisk::Critical && id.isPrivileged)
            r.reasons.push_back(L"CRITICAL exec method on privileged server - direct PrivEsc/RCE surface");
    }

    if (!anyRemote)       r.mitigations.push_back(L"Remote activation blocked");
    if (!id.isPrivileged) r.mitigations.push_back(L"Runs as calling user - no privilege gain");
    if (!sv.imgMissing && !sv.imgWritable && !sv.imagePath.empty())
        r.mitigations.push_back(L"Binary exists and not writable by non-admin");
    if (sv.imgSigned && !sv.imgMissing)
        r.mitigations.push_back(L"Binary is Authenticode-signed");

    int score = 0;
    if (r.privesc)  score += 40;
    if (r.lateral)  score += 25;
    if (r.hijack)   score += 30;
    if (r.autoElev) score += 20;
    if (tl.loadedOk && tl.worstRisk >= ExecRisk::Critical) score += 20;
    else if (tl.loadedOk && tl.worstRisk >= ExecRisk::High) score += 10;

    if (score >= 60) r.level = RiskLevel::Critical;
    else if (score >= 40) r.level = RiskLevel::High;
    else if (score >= 20) r.level = RiskLevel::Medium;
    else if (score > 0)  r.level = RiskLevel::Low;
    else                  r.level = RiskLevel::None;
    return r;
}

// ============================================================
//  ResolvedCOM + Resolve()
// ============================================================
struct ResolvedCOM { std::wstring appid, clsid, progid, note; };

static ResolvedCOM Resolve(const std::wstring& input)
{
    ResolvedCOM r;
    if (input.size() >= 38 && input[0] == L'{') {
        wchar_t t1[512], t2[512];
        swprintf_s(t1, L"SOFTWARE\\Classes\\AppID\\%s", input.c_str());
        swprintf_s(t2, L"AppID\\%s", input.c_str());
        if (RegKeyExists(HKEY_LOCAL_MACHINE, t1) || RegKeyExists(HKEY_CLASSES_ROOT, t2)) {
            r.appid = input; r.note = L"GUID -> AppID key found"; return r;
        }
        std::wstring aid = CLSIDtoAppID(input);
        if (!aid.empty()) { r.clsid = input; r.appid = aid; r.note = L"CLSID -> AppID"; return r; }
        r.appid = input; r.note = L"GUID (trying anyway)"; return r;
    }
    std::wstring clsid = ProgIDtoCLSID(input);
    if (!clsid.empty()) {
        r.progid = input; r.clsid = clsid;
        r.appid = CLSIDtoAppID(clsid);
        r.note = L"ProgID -> CLSID -> AppID"; return r;
    }
    auto keys = RegEnumSubkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\AppID");
    for (auto& k : keys) {
        wchar_t p2[512]; swprintf_s(p2, L"SOFTWARE\\Classes\\AppID\\%s", k.c_str());
        std::wstring fn = RegReadString(HKEY_LOCAL_MACHINE, p2, L"");
        if (_wcsicmp(fn.c_str(), input.c_str()) == 0) { r.appid = k; r.note = L"Friendly name"; return r; }
    }
    r.note = L"Could not resolve"; return r;
}

// ============================================================
//  DumpAppID — main analysis for one AppID
// ============================================================
static void DumpAppID(const ResolvedCOM& res, bool brief,
    bool doTypelib, bool execOnly, bool doDispatch, bool scanMode = false)
{
    if (!scanMode) {
        wprintf(L"\n%s+===========================================================+%s\n", CC(C_YEL), CC(C_RST));
        if (!res.progid.empty()) wprintf(L"%s  Input : %s%s\n", CC(C_YEL), res.progid.c_str(), CC(C_RST));
        if (!res.clsid.empty())  wprintf(L"%s  CLSID : %s%s\n", CC(C_YEL), res.clsid.c_str(), CC(C_RST));
        wprintf(L"%s  AppID : %s%s\n", CC(C_YEL), res.appid.empty() ? L"(not resolved)" : res.appid.c_str(), CC(C_RST));
        wprintf(L"%s  Via   : %s%s\n", CC(C_YEL), res.note.c_str(), CC(C_RST));
        wprintf(L"%s+===========================================================+%s\n", CC(C_YEL), CC(C_RST));
    }
    if (res.appid.empty()) return;

    // Locate AppID registry key (prefer HKLM, fallback HKCR)
    wchar_t hklmPath[512], hkcrPath[512];
    swprintf_s(hklmPath, L"SOFTWARE\\Classes\\AppID\\%s", res.appid.c_str());
    swprintf_s(hkcrPath, L"AppID\\%s", res.appid.c_str());
    HKEY hive = HKEY_LOCAL_MACHINE; const wchar_t* regPath = hklmPath;
    HKEY probe = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, hklmPath, 0, KEY_READ, &probe) == ERROR_SUCCESS)
    {
        RegCloseKey(probe);
    }
    else {
        if (probe) RegCloseKey(probe); probe = NULL;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, hkcrPath, 0, KEY_READ, &probe) == ERROR_SUCCESS)
        {
            RegCloseKey(probe); hive = HKEY_CLASSES_ROOT; regPath = hkcrPath;
        }
        else {
            if (probe) RegCloseKey(probe);
            if (!scanMode) wprintf(L"  %s[!] AppID key not found%s\n", CC(C_RED), CC(C_RST));
            return;
        }
    }

    auto Rs = [&](const wchar_t* v) { return RegReadString(hive, regPath, v); };
    auto Rb = [&](const wchar_t* v, std::vector<BYTE>& o) { return RegReadBinary(hive, regPath, v, o); };

    std::wstring friendly = Rs(L"");
    std::wstring runas = Rs(L"RunAs");
    std::wstring svc = Rs(L"LocalService");
    std::wstring dllsur = Rs(L"DllSurrogate");
    std::wstring remSvr = Rs(L"RemoteServerName");
    std::wstring authLvRaw = Rs(L"AuthenticationLevel");
    std::wstring impLvRaw = Rs(L"ImpersonationLevel");

    wchar_t elevPath[512]; swprintf_s(elevPath, L"%s\\Elevation", regPath);
    DWORD elevEnabled = RegReadDWORD(hive, elevPath, L"Enabled", 0);

    std::vector<std::wstring> clsids = FindCLSIDs(res.appid, res.clsid);
    std::wstring canonCLSID = clsids.empty() ? L"" : clsids[0];
    ServerInfo sv = DetectServerType(canonCLSID, svc, dllsur);
    Identity   id = ResolveIdentity(runas, sv);

    // Permissions
    std::vector<BYTE> binLaunch, binAccess, binDefLaunch, binDefAccess, binMLR, binMAR;
    bool hasLaunch = Rb(L"LaunchPermission", binLaunch);
    bool hasAccess = Rb(L"AccessPermission", binAccess);
    const wchar_t* olePath = L"SOFTWARE\\Microsoft\\Ole";
    RegReadBinary(HKEY_LOCAL_MACHINE, olePath, L"DefaultLaunchPermission", binDefLaunch);
    RegReadBinary(HKEY_LOCAL_MACHINE, olePath, L"DefaultAccessPermission", binDefAccess);
    RegReadBinary(HKEY_LOCAL_MACHINE, olePath, L"MachineLaunchRestriction", binMLR);
    RegReadBinary(HKEY_LOCAL_MACHINE, olePath, L"MachineAccessRestriction", binMAR);

    auto launchACEs = hasLaunch ? BinToACEs(binLaunch) : BinToACEs(binDefLaunch);
    auto accessACEs = hasAccess ? BinToACEs(binAccess) : BinToACEs(binDefAccess);
    auto mlrACEs = BinToACEs(binMLR);
    auto marACEs = BinToACEs(binMAR);
    auto surf = ComputeSurface(launchACEs, accessACEs, mlrACEs, marACEs);

    // ---- TypeLib analysis ------------------------------------------------
    TypeLibInfo tlInfo;
    if (doTypelib) {
        std::wstring tlPath;

        // Try canonCLSID first
        if (!canonCLSID.empty())
            tlPath = GetTypeLibPath(canonCLSID);

        // Try sibling CLSIDs
        if (tlPath.empty()) {
            for (auto& sib : clsids) {
                if (!canonCLSID.empty() && _wcsicmp(sib.c_str(), canonCLSID.c_str()) == 0) continue;
                tlPath = GetTypeLibPath(sib);
                if (!tlPath.empty()) break;
            }
        }

        if (!tlPath.empty())
            tlInfo = LoadAndAnalyzeTypeLib(tlPath);

        // Last resort: try binary directly (resource IDs handled inside)
        if (!tlInfo.loadedOk && !sv.imagePath.empty() && IsFile(sv.imagePath))
            tlInfo = LoadAndAnalyzeTypeLib(sv.imagePath);
    }

    RiskResult risk = EvaluateRisk(id, sv, surf, elevEnabled != 0, tlInfo);

    // ---- Scan mode -------------------------------------------------------
    if (scanMode) {
        if (risk.level == RiskLevel::None && tlInfo.execRiskMethods == 0)
            return;
        
        wprintf(L"\n%s[%s]%s AppID: %s%s%s",
            CC(RiskLevelColor(risk.level)),
            RiskLevelStr(risk.level),
            CC(C_RST),
            CC(C_CYN), res.appid.c_str(), CC(C_RST));

        if (!res.progid.empty()) {
            wprintf(L"hihi\n");
            wprintf(L"  ProgID: %s%s%s",
                CC(C_GRN), res.progid.c_str(), CC(C_RST));
        }
        wprintf(L"  ProgID: %s" , res.progid.c_str());


        wprintf(L" (%s)\n", friendly.c_str());   // friendly name giữ nguyên

        if (!sv.imagePath.empty())
            wprintf(L" Image : %s\n", sv.imagePath.c_str());

        wprintf(L" RunAs : %s\n", id.resolved.c_str());

        if (tlInfo.loadedOk && tlInfo.execRiskMethods > 0) {
            wprintf(L" %sExec methods: %d worst: %s%s\n",
                CC(ExecRiskColor(tlInfo.worstRisk)),
                tlInfo.execRiskMethods,
                ExecRiskStr(tlInfo.worstRisk),
                CC(C_RST));
        }

        for (auto& r2 : risk.reasons)
            wprintf(L" %s-> %s%s\n",
                CC(RiskLevelColor(risk.level)),
                r2.c_str(),
                CC(C_RST));

        return;
    }

    if (brief) {
        if (!friendly.empty()) wprintf(L"    Name : %s\n", friendly.c_str());
        if (!runas.empty())    wprintf(L"    RunAs: %s\n", runas.c_str());
        return;
    }

    // ======== FULL OUTPUT ========

    wprintf(L"\n  %s[Metadata]%s\n", CC(C_BOLD), CC(C_RST));
    if (!friendly.empty())  wprintf(L"    Name          : %s\n", friendly.c_str());
    if (!runas.empty())     wprintf(L"    %sRunAs%s         : %s\n", CC(C_GRN), CC(C_RST), runas.c_str());
    if (!svc.empty())       wprintf(L"    %sLocalService%s  : %s\n", CC(C_GRN), CC(C_RST), svc.c_str());
    if (!dllsur.empty())    wprintf(L"    %sDllSurrogate%s  : %s\n", CC(C_MAG), CC(C_RST), dllsur.c_str());
    if (!remSvr.empty())    wprintf(L"    %sRemoteServer%s  : %s\n", CC(C_RED), CC(C_RST), remSvr.c_str());
    if (!authLvRaw.empty()) wprintf(L"    AuthLevel      : %s\n", AuthLevelDecode(authLvRaw).c_str());
    if (!impLvRaw.empty())  wprintf(L"    ImpLevel       : %s\n", ImpLevelDecode(impLvRaw).c_str());

    wprintf(L"\n  %s[Server Type]%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"    %s%s%s\n", CC(C_WHT), sv.typeLabel.c_str(), CC(C_RST));
    if (!sv.imagePath.empty())
        wprintf(L"    Image          : %s%s%s\n",
            sv.imgMissing ? CC(C_RED) : (sv.imgWritable ? CC(C_YEL) : CC(C_RST)),
            sv.imagePath.c_str(), CC(C_RST));
    if (!sv.threadingModel.empty())
        wprintf(L"    ThreadingModel : %s\n", sv.threadingModel.c_str());
    if (!sv.serviceName.empty()) {
        wprintf(L"    Service Name   : %s\n", sv.serviceName.c_str());
        wprintf(L"    Service Acct   : %s%s%s\n",
            sv.serviceAccount.find(L"SYSTEM") != std::wstring::npos ? CC(C_RED) : CC(C_RST),
            sv.serviceAccount.c_str(), CC(C_RST));
    }
    if (sv.imgMissing)  wprintf(L"    %s[!] Binary NOT FOUND%s\n", CC(C_RED), CC(C_RST));
    if (sv.imgWritable) wprintf(L"    %s[!] Binary WRITABLE by non-admin%s\n", CC(C_YEL), CC(C_RST));
    if (!sv.imgMissing && sv.imgSigned) wprintf(L"    %s[+] Binary is signed%s\n", CC(C_GRN), CC(C_RST));

    wprintf(L"\n  %s[Identity]%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"    Resolved : %s%s%s\n",
        id.isPrivileged ? CC(C_RED) : CC(C_RST), id.resolved.c_str(), CC(C_RST));
    wprintf(L"    Remark   : %s\n", id.remark.c_str());

    wprintf(L"\n  %s[UAC Auto-Elevation]%s\n", CC(C_BOLD), CC(C_RST));
    if (elevEnabled)
        wprintf(L"    %s[!] Elevation\\Enabled = 1 - UAC bypass surface%s\n", CC(C_RED), CC(C_RST));
    else
        wprintf(L"    %s(not configured)%s\n", CC(C_DIM), CC(C_RST));

    wprintf(L"\n  %s[Associated CLSIDs]%s\n", CC(C_BOLD), CC(C_RST));
    for (auto& cid : clsids) {
        wchar_t base[512]; swprintf_s(base, L"CLSID\\%s", cid.c_str());
        std::wstring fn = RegReadString(HKEY_CLASSES_ROOT, base, L"");
        wprintf(L"\n    %s%s%s  (%s)\n", CC(C_CYN), cid.c_str(), CC(C_RST), fn.c_str());
        struct { const wchar_t* sk; const wchar_t* v; const wchar_t* lbl; } subs[] = {
            { L"LocalServer32",  L"",               L"LocalServer32  " },
            { L"InprocServer32", L"",               L"InprocServer32 " },
            { L"InprocServer32", L"ThreadingModel", L"ThreadingModel " },
            { L"ProgID",         L"",               L"ProgID         " },
            { L"TypeLib",        L"",               L"TypeLib        " },
        };
        for (auto& se : subs) {
            wchar_t fs[600]; swprintf_s(fs, L"CLSID\\%s\\%s", cid.c_str(), se.sk);
            std::wstring v = RegReadString(HKEY_CLASSES_ROOT, fs, se.v);
            if (!v.empty()) wprintf(L"      %-16s: %s\n", se.lbl, v.c_str());
        }
    }

    wprintf(L"\n  %s[LaunchPermission]%s %s\n", CC(C_BOLD), CC(C_RST),
        hasLaunch ? L"" : L"(using system default)");
    if (hasLaunch) PrintSD(binLaunch.data(), (DWORD)binLaunch.size(), 4);
    else if (!binDefLaunch.empty()) PrintSD(binDefLaunch.data(), (DWORD)binDefLaunch.size(), 6);

    wprintf(L"\n  %s[AccessPermission]%s %s\n", CC(C_BOLD), CC(C_RST),
        hasAccess ? L"" : L"(using system default)");
    if (hasAccess) PrintSD(binAccess.data(), (DWORD)binAccess.size(), 4);
    else if (!binDefAccess.empty()) PrintSD(binDefAccess.data(), (DWORD)binDefAccess.size(), 6);
    else wprintf(L"    %s(DefaultAccessPermission not set - only server process + SYSTEM)%s\n",
        CC(C_YEL), CC(C_RST));

    wprintf(L"\n  %s[Attack Surface Matrix]%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"    %-26s  LocLaunch  RemLaunch  LocAccess  RemAccess\n", L"Principal");
    wprintf(L"    %s-------------------------------------------------------------------%s\n", CC(C_DIM), CC(C_RST));
    for (auto& row : surf) {
        auto yn = [](bool v) { return v ? L"YES " : L"no  "; };
        auto col = [](bool v) { return v ? C_GRN : C_DIM; };
        wprintf(L"    %-26s  %s%s%s  %s%s%s  %s%s%s  %s%s%s\n",
            row.principal.c_str(),
            CC(col(row.ll)), yn(row.ll), CC(C_RST),
            CC(col(row.rl)), yn(row.rl), CC(C_RST),
            CC(col(row.la)), yn(row.la), CC(C_RST),
            CC(col(row.ra)), yn(row.ra), CC(C_RST));
    }

    // COM Interface & Method Analysis
    wprintf(L"\n%s+===========================================================+%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"%s  COM Interface & Method Analysis%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"%s+===========================================================+%s\n", CC(C_BOLD), CC(C_RST));

    if (doTypelib) {
        wprintf(L"\n  %s[TypeLib - static analysis]%s\n", CC(C_BOLD), CC(C_RST));
        if (tlInfo.loadedOk) {
            PrintTypeLibInfo(tlInfo, execOnly, 4);
        }
        else if (!tlInfo.path.empty()) {
            wprintf(L"    %s[!] Load failed: %s%s\n", CC(C_YEL), tlInfo.errorMsg.c_str(), CC(C_RST));
            wprintf(L"    Path attempted: %s\n", tlInfo.path.c_str());
        }
        else {
            wprintf(L"    %s(no TypeLib path found for CLSID %s)%s\n",
                CC(C_DIM), canonCLSID.c_str(), CC(C_RST));
        }
    }

    if (doDispatch && !canonCLSID.empty()) {
        wprintf(L"\n  %s[IDispatch - live object probe]%s\n", CC(C_BOLD), CC(C_RST));
        DispatchProbe dp = ProbeViaDispatch(canonCLSID);
        if (dp.succeeded) {
            wprintf(L"    %s[+] IDispatch instantiation succeeded%s\n", CC(C_GRN), CC(C_RST));
            wprintf(L"    %-12s %-12s %-28s  Signature\n", L"Kind", L"ExecRisk", L"Name");
            wprintf(L"    %s---------------------------------------------------------------------------%s\n", CC(C_DIM), CC(C_RST));
            for (auto& m : dp.methods) {
                if (execOnly && m.execRisk < ExecRisk::Medium) continue;
                const wchar_t* rc = ExecRiskColor(m.execRisk);
                const wchar_t* rs = (m.execRisk == ExecRisk::None) ? L"       " : ExecRiskStr(m.execRisk);
                std::wstring sig = m.retType + L" " + (m.name.empty() ? L"<unnamed>" : m.name) + L"(";
                for (size_t pi = 0; pi < m.params.size(); pi++) {
                    if (pi) sig += L", ";
                    sig += m.params[pi].first + L" " + m.params[pi].second;
                }
                sig += L")";
                wprintf(L"    %-12s %s%-12s%s %-28s  %s\n",
                    m.invokeKind.c_str(), CC(rc), rs, CC(C_RST),
                    m.name.empty() ? L"<unnamed>" : m.name.c_str(), sig.c_str());
                if (m.execRisk >= ExecRisk::Low && !m.execReason.empty())
                    wprintf(L"      %s-> %s%s\n", CC(rc), m.execReason.c_str(), CC(C_RST));
            }
        }
        else {
            wprintf(L"    %s[!] %s%s\n", CC(C_YEL), dp.errorMsg.c_str(), CC(C_RST));
        }
    }

    // Risk Assessment
    wprintf(L"\n%s+===========================================================+%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"%s  RISK ASSESSMENT%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"%s+===========================================================+%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"  Overall Level : %s%s%s\n",
        CC(RiskLevelColor(risk.level)), RiskLevelStr(risk.level), CC(C_RST));
    if (tlInfo.loadedOk && tlInfo.execRiskMethods > 0)
        wprintf(L"  Exec Methods  : %s%d method(s) with exec risk  (worst: %s)%s\n",
            CC(ExecRiskColor(tlInfo.worstRisk)), tlInfo.execRiskMethods,
            ExecRiskStr(tlInfo.worstRisk), CC(C_RST));
    wprintf(L"\n");
    auto flag = [](bool v, const wchar_t* label, const wchar_t* tc) {
        wprintf(L"  %-22s: %s%-3s%s\n", label, v ? CC(tc) : CC(C_DIM), v ? L"YES" : L"NO", CC(C_RST));
        };
    flag(risk.privesc, L"PrivEsc", C_RED);
    flag(risk.lateral, L"LateralMove", C_ORG);
    flag(risk.hijack, L"Hijack", C_RED);
    flag(risk.autoElev, L"AutoElevate", C_YEL);
    flag(risk.dcomOpen, L"DCOM Exposed", C_YEL);
    if (!risk.reasons.empty()) {
        wprintf(L"\n  %sFindings:%s\n", CC(C_BOLD), CC(C_RST));
        for (auto& r2 : risk.reasons)
            wprintf(L"    %s[!]%s %s\n", CC(RiskLevelColor(risk.level)), CC(C_RST), r2.c_str());
    }
    if (!risk.mitigations.empty()) {
        wprintf(L"\n  %sMitigations:%s\n", CC(C_BOLD), CC(C_RST));
        for (auto& m : risk.mitigations)
            wprintf(L"    %s[+]%s %s\n", CC(C_GRN), CC(C_RST), m.c_str());
    }
    if (risk.level == RiskLevel::None && tlInfo.execRiskMethods == 0)
        wprintf(L"\n  %s[OK] No significant risk indicators found%s\n", CC(C_GRN), CC(C_RST));
    wprintf(L"%s+===========================================================+%s\n", CC(C_BOLD), CC(C_RST));
}

// ============================================================
//  --typelib <path>
// ============================================================
static void DumpTypeLibFile(const std::wstring& path, bool execOnly)
{
    wprintf(L"\n%s[TypeLib Analysis]%s  %s\n", CC(C_BOLD), CC(C_RST), path.c_str());
    TypeLibInfo tl = LoadAndAnalyzeTypeLib(path);
    if (!tl.loadedOk) {
        wprintf(L"  %s[!] %s%s\n", CC(C_RED), tl.errorMsg.c_str(), CC(C_RST));
        return;
    }
    PrintTypeLibInfo(tl, execOnly, 2);
    wprintf(L"\n%s[Summary]%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"  Interfaces   : %zu\n", tl.interfaces.size());
    wprintf(L"  Total methods: %d\n", tl.totalMethods);
    wprintf(L"  Exec-risk    : %s%d%s  (worst: %s)\n",
        tl.execRiskMethods > 0 ? CC(ExecRiskColor(tl.worstRisk)) : CC(C_GRN),
        tl.execRiskMethods, CC(C_RST), ExecRiskStr(tl.worstRisk));
}

// ============================================================
//  --methods <CLSID|ProgID>
// ============================================================
static void DumpMethods(const std::wstring& input, bool execOnly, bool doDispatch)
{
    ResolvedCOM r = Resolve(input);
    std::wstring clsid = r.clsid.empty() ? input : r.clsid;

    wprintf(L"\n%s[Method Analysis]%s  %s%s%s\n",
        CC(C_BOLD), CC(C_RST), CC(C_CYN), input.c_str(), CC(C_RST));
    if (!r.clsid.empty()) wprintf(L"  CLSID  : %s\n", r.clsid.c_str());
    if (!r.appid.empty()) wprintf(L"  AppID  : %s\n", r.appid.c_str());

    wprintf(L"\n  %s[TypeLib - static]%s\n", CC(C_BOLD), CC(C_RST));
    std::wstring tlPath = GetTypeLibPath(clsid);

    // Also try sibling CLSIDs if direct lookup failed
    if (tlPath.empty() && !r.appid.empty()) {
        auto sibs = FindCLSIDs(r.appid, L"");
        for (auto& sib : sibs) {
            if (_wcsicmp(sib.c_str(), clsid.c_str()) == 0) continue;
            tlPath = GetTypeLibPath(sib);
            if (!tlPath.empty()) break;
        }
    }

    if (!tlPath.empty()) {
        TypeLibInfo tl = LoadAndAnalyzeTypeLib(tlPath);
        PrintTypeLibInfo(tl, execOnly, 4);
    }
    else {
        wprintf(L"    %s(no TypeLib path found)%s\n", CC(C_DIM), CC(C_RST));
    }

    if (doDispatch) {
        wprintf(L"\n  %s[IDispatch - live]%s\n", CC(C_BOLD), CC(C_RST));
        DispatchProbe dp = ProbeViaDispatch(clsid);
        if (dp.succeeded) {
            wprintf(L"    %s[+] Live probe OK - %zu methods%s\n",
                CC(C_GRN), dp.methods.size(), CC(C_RST));
            for (auto& m : dp.methods) {
                if (execOnly && m.execRisk < ExecRisk::Medium) continue;
                const wchar_t* rc = ExecRiskColor(m.execRisk);
                const wchar_t* rs = (m.execRisk == ExecRisk::None) ? L"       " : ExecRiskStr(m.execRisk);
                wprintf(L"    %s%-12s%s %s%-12s%s %s\n",
                    CC(C_DIM), m.invokeKind.c_str(), CC(C_RST),
                    CC(rc), rs, CC(C_RST),
                    m.name.empty() ? L"<unnamed>" : m.name.c_str());
                if (m.execRisk >= ExecRisk::Low && !m.execReason.empty())
                    wprintf(L"      %s-> %s%s\n", CC(rc), m.execReason.c_str(), CC(C_RST));
            }
        }
        else {
            wprintf(L"    %s[!] %s%s\n", CC(C_YEL), dp.errorMsg.c_str(), CC(C_RST));
        }
    }
}

// ============================================================
//  System defaults
// ============================================================
static void DumpDefaults()
{
    wprintf(L"\n%s+===========================================================+%s\n", CC(C_YEL), CC(C_RST));
    wprintf(L"%s  System-Wide Default COM/DCOM Permissions%s\n", CC(C_YEL), CC(C_RST));
    wprintf(L"%s+===========================================================+%s\n", CC(C_YEL), CC(C_RST));
    const wchar_t* olePath = L"SOFTWARE\\Microsoft\\Ole";
    const wchar_t* perms[] = {
        L"DefaultLaunchPermission", L"DefaultAccessPermission",
        L"MachineLaunchRestriction", L"MachineAccessRestriction"
    };
    for (auto p : perms) {
        wprintf(L"\n  %s[%s]%s\n", CC(C_BOLD), p, CC(C_RST));
        std::vector<BYTE> bin;
        if (RegReadBinary(HKEY_LOCAL_MACHINE, olePath, p, bin) && !bin.empty())
            PrintSD(bin.data(), (DWORD)bin.size(), 4);
        else
            wprintf(L"    %s(not set)%s\n", CC(C_DIM), CC(C_RST));
    }
    const wchar_t* sv[] = {
        L"EnableDCOM", L"LegacyAuthenticationLevel", L"LegacyImpersonationLevel",
        L"DefaultAuthenticationLevel", L"DefaultImpersonationLevel"
    };
    wprintf(L"\n  %s[Global OLE/DCOM Settings]%s\n", CC(C_BOLD), CC(C_RST));
    for (auto v : sv) {
        std::wstring val = RegReadStringOrDword(HKEY_LOCAL_MACHINE, olePath, v);
        if (!val.empty()) {
            std::wstring display = val;
            std::wstring vlow = v;
            std::transform(vlow.begin(), vlow.end(), vlow.begin(), ::towlower);
            if (vlow.find(L"impersonation") != std::wstring::npos)
                display = val + L"  (" + ImpLevelDecode(val) + L")";
            else if (vlow.find(L"authentication") != std::wstring::npos && _wcsicmp(v, L"EnableDCOM") != 0)
                display = val + L"  (" + AuthLevelDecode(val) + L")";
            wprintf(L"    %-38s: %s\n", v, display.c_str());
        }
    }
}

// ============================================================
//  Scan / Enum all AppIDs
// ============================================================
static void ScanAll(bool doTypelib, bool execOnly)
{
    wprintf(L"\n%s[SCAN MODE]%s Checking all AppIDs...\n", CC(C_BOLD), CC(C_RST));
    // Scan both HKLM and HKCR to avoid missing any
    std::set<std::wstring> seen;
    std::vector<std::wstring> allKeys;

    auto addKeys = [&](HKEY root, const wchar_t* path) {
        auto keys = RegEnumSubkeys(root, path);
        for (auto& k : keys) {
            std::wstring kl = k;
            std::transform(kl.begin(), kl.end(), kl.begin(), ::towlower);
            if (seen.insert(kl).second && k.size() > 2 && k[0] == L'{')
                allKeys.push_back(k);
        }
        };
    addKeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\AppID");
    addKeys(HKEY_CLASSES_ROOT, L"AppID");

    for (auto& k : allKeys) {
        ResolvedCOM r; r.appid = k; r.note = L"Scan";
        DumpAppID(r, false, doTypelib, execOnly, false, true);
    }
    wprintf(L"\n%s[*] Scan complete. %zu AppIDs checked.%s\n",
        CC(C_BOLD), allKeys.size(), CC(C_RST));
}

static void EnumAll(bool brief, bool doTypelib, bool execOnly)
{
    std::set<std::wstring> seen;
    std::vector<std::wstring> allKeys;
    auto addKeys = [&](HKEY root, const wchar_t* path) {
        auto keys = RegEnumSubkeys(root, path);
        for (auto& k : keys) {
            std::wstring kl = k;
            std::transform(kl.begin(), kl.end(), kl.begin(), ::towlower);
            if (seen.insert(kl).second && k.size() > 2 && k[0] == L'{')
                allKeys.push_back(k);
        }
        };
    addKeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\AppID");
    addKeys(HKEY_CLASSES_ROOT, L"AppID");

    wprintf(L"\n%s[*] %zu AppID entries%s\n", CC(C_BOLD), allKeys.size(), CC(C_RST));
    for (auto& k : allKeys) {
        ResolvedCOM r; r.appid = k; r.note = L"Enumeration";
        DumpAppID(r, brief, doTypelib, execOnly, false);
    }
    DumpDefaults();
}

// ============================================================
//  Entry point
// ============================================================
int wmain(int argc, wchar_t* argv[])
{
    EnableVT();
    // Set UTF-8 output so Unicode chars render correctly
    SetConsoleOutputCP(CP_UTF8);
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    wprintf(L"\n  COM Security Auditor v5.1\n");
    wprintf(L"  ProgID->CLSID->AppID | TypeLib Introspection | Method Exec Classifier\n");
    wprintf(L"  ======================================================================\n\n");
    fflush(stdout);

    if (argc < 2) {
        wprintf(
            L"Usage:\n"
            L"  comdump.exe <input>                  Audit AppID (ProgID / CLSID / AppID / name)\n"
            L"  comdump.exe <input> --methods        Also dump all methods (TypeLib + IDispatch)\n"
            L"  comdump.exe <input> --exec           Show only exec-capable methods\n"
            L"  comdump.exe <input> --live           Include live IDispatch probe\n"
            L"  comdump.exe <input> --methods --exec --live  Combined deep mode\n"
            L"\n"
            L"  comdump.exe --methods <input>        Deep method dump (no AppID audit)\n"
            L"  comdump.exe --typelib <path>         Analyse arbitrary TLB/DLL/EXE typelib\n"
            L"  comdump.exe --typelib <path> --exec  Exec methods only\n"
            L"\n"
            L"  comdump.exe --scan                   Scan all AppIDs for risk\n"
            L"  comdump.exe --scan --methods         Scan + include TypeLib analysis\n"
            L"  comdump.exe --all                    Dump every AppID\n"
            L"  comdump.exe --defaults               System-wide COM/DCOM defaults\n"
            L"\n"
            L"Examples:\n"
            L"  comdump.exe MMC20.Application --methods --exec --live\n"
            L"  comdump.exe Shell.Application --methods\n"
            L"  comdump.exe Excel.Application --methods --exec\n"
            L"  comdump.exe {72C24DD5-D70A-438B-8A42-98424B88AFB8} --methods --exec\n"
            L"  comdump.exe --typelib C:\\Windows\\System32\\wshom.ocx --exec\n"
            L"  comdump.exe --methods {72C24DD5-D70A-438B-8A42-98424B88AFB8} --live\n"
        );
        CoUninitialize();
        return 0;
    }

    std::wstring arg1 = argv[1];
    bool doMethods = false, execOnly = false, doDispatch = false, brief = false;
    for (int i = 2; i < argc; i++) {
        std::wstring a = argv[i];
        if (a == L"--methods") doMethods = true;
        if (a == L"--exec")    execOnly = true;
        if (a == L"--live")    doDispatch = true;
        if (a == L"--brief")   brief = true;
    }

    if (arg1 == L"--defaults") {
        DumpDefaults();
    }
    else if (arg1 == L"--all") {
        EnumAll(brief, doMethods, execOnly);
    }
    else if (arg1 == L"--scan") {
        ScanAll(doMethods, execOnly);
    }
    else if (arg1 == L"--typelib") {
        if (argc < 3) { wprintf(L"Error: --typelib requires a path\n"); CoUninitialize(); return 1; }
        DumpTypeLibFile(argv[2], execOnly);
    }
    else if (arg1 == L"--methods") {
        if (argc < 3) { wprintf(L"Error: --methods requires a CLSID/ProgID\n"); CoUninitialize(); return 1; }
        DumpMethods(argv[2], execOnly, doDispatch);
    }
    else {
        ResolvedCOM r = Resolve(arg1);
        DumpAppID(r, false, doMethods, execOnly, doDispatch, false);
        DumpDefaults();
    }

    wprintf(L"\n%sDone.%s\n", CC(C_DIM), CC(C_RST));
    fflush(stdout);
    CoUninitialize();
    return 0;
}