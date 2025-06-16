#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <shlobj.h>
#include <locale>
#include <codecvt>

#include <nlohmann/json.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../include/IVSDK.cpp"

typedef unsigned int(__stdcall* XLiveSetSponsorTokenFunc)(LPCWSTR, DWORD);

std::vector<std::pair<std::string, std::wstring>> pairs, pairs_offline = {
    {"f7a957f68a9ac890", L"FXRHK-T8PDY-FHBCH-G6YJG-XF8PJ"},
    {"fcc56b1292bdb323", L"WBV4B-MFGR4-Y9XY7-MKRPM-HHJ96"},
    {"3c9643c2bba342f3", L"M2RHB-TDC2R-MTHXH-GP662-XG33W"},
    {"6296508739319fec", L"WMBGX-HC2WR-JC92D-KVK2B-Q8YB3"},
    {"01dd52f4df371e92", L"W6Y9P-MKP4C-FHT83-GQMMC-FYQQQ"},
    {"98d5011194b44853", L"JX3JC-CC2HX-TRWCY-49BKF-2CKYY"},
    {"8dd9875da9765feb", L"XH3CX-7D382-4TWG7-D9YT9-FFJMJ"},
    {"91f25744e25778ec", L"V7HM9-K3YBQ-K3XVF-4K6JF-RXXHG"},
    {"4297ea16afe12c2b", L"DCKXY-JG4DH-JRDYB-KMT97-GPKPG"},
    {"a79f1149fdb3bfd8", L"QGTD9-VM883-83FPP-KYKD2-FK3JD"},
    {"977bc03034344939", L"MVKG6-8BPRK-93FPR-GTH9Y-GQJWT"},
    {"80bce0c8e78c5294", L"P72WF-GXDQM-8YTP4-7TYYB-72YGT"},
    {"7626ef2d926d531c", L"JY6GC-GD69H-G4TC2-BF9MJ-FW9YJ"},
    {"f5f8b883dec12691", L"Q38PK-B9WCR-8D8WP-C8Y28-9DW73"},
    {"e805ed18e22fb0f7", L"GXTHG-JCQMJ-WVBCP-MDVPV-JBX43"},
    // new
    {"b14faa6d0cc91a7e", L"RHQV3-7G3FM-9T4CD-F9H8B-FT66Q"},
    {"901d4677395549ab", L"CMBMJ-CG3PC-R2HY8-6RYGG-CRWTY"},
    {"fdb3f9aab7dfbdd9", L"CPTJV-PYQRR-VY79Y-7PMM6-DWBF3"},
    {"f28339115ea1f140", L"22TBG-D3PF4-YPMDJ-MMJ8Q-9Y68G"},
    {"61b3e22c13cc28ad", L"CTJG4-V3MQY-3K272-6MHCV-R4GG6"},
    {"2e2687943de6c3e3", L"V3K6V-QTKQD-RDWCJ-X3WM2-G8XP8"},
    {"454445ce461937f8", L"DPQ7P-646DC-DM63Q-X4YD3-MPBMB"},
    {"fe652e37b51c5924", L"CHYXY-QYRXP-WR22C-8B47X-DGF93"},
    {"5d9826ad3b3a4071", L"RRQ6J-B2G7T-GMW8M-Q7QYX-3VJVQ"},
    {"f5859541b9879ed0", L"FYGQP-F7GQP-X6CX6-BFYVK-WQBBG"},
    {"315a08a59b7e0c86", L"HJKY7-6TQD6-6FPXT-DG9J3-K7YQD"},
    {"3b07abed3e68fadf", L"VY43Y-JYC9Q-84T4P-M22G8-WVBR6"},
    {"a336f7a9647a37b6", L"BYMGW-K33C2-WDDDD-VQ98P-DJC4M"},
    {"8591facd9387b18c", L"G8FFP-FRBT6-DCKT9-HRMMX-XCMBJ"},
    {"b3458a367eaaa484", L"DW9FC-B2DFG-TQB9Y-P3YKC-V8P7Y"},
    {"61261e406f8501f6", L"VDQBM-TYB29-QTRG6-WY7VB-YRD7J"},
    {"88e6bb52581dc88a", L"W8D7H-F2RBK-PRHCG-PRTQW-CHPDB"},
    {"fd976d0abd336d49", L"HJ4GH-T9MQK-JRDRB-JP8WB-C6MFJ"},
    {"17c969da5f9efc94", L"HJ4GH-T9MQK-JRDRB-JP8WB-C6MFJ"},
    {"4844fbf85f4157c0", L"HJ4GH-T9MQK-JRDRB-JP8WB-C6MFJ"},
    {"a9b01e5cfa0bba9e", L"HJ4GH-T9MQK-JRDRB-JP8WB-C6MFJ"},
    {"f83e97f5dc54fab9", L"HJ4GH-T9MQK-JRDRB-JP8WB-C6MFJ"},
    {"9d344d75b591d73a", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"c12815c6cdc3b202", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"69c0c3636b587fe3", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"f89950ebe8f29e3d", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"022f00792daff490", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"bd40d7ed3d4fb1d3", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"efdd66f876ce23aa", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"54debc6bb3867c3f", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"e8921653047f7dfa", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"2d6e813f6fd14cab", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"a6462b79328dcb2e", L"XTWX9-G6CP9-HFF3J-GJFBG-GDJCG"},
    {"cfcfc47148a423cb", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"fe896b525ab172b4", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"6a58548b1c3331b3", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"77c8e85b81a5711d", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"69ebb87dea59c6c4", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"713728deb2639da2", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"ba54f7ba6bff5550", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"b18a759fc29b5f69", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"241741fc0d6f39e0", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"74da96e152cfca1c", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"99675accdff045ff", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"f65ecb0fb1f43bb5", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"6815794a4f88d459", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"c22b30e89ba91e71", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"e2421be6a381f938", L"FFD9H-C2JMD-VCDV4-DDPFT-8H4P7"},
    {"7d331075b1eaa7aa", L"D99H6-G4XMC-Q62J8-CWY44-P3DV7"},
};

static std::wstring string_to_wstring(const std::string& str) {
    std::wstring ws(str.begin(), str.end());
    return ws;
}

static std::string format_winsock_error(int err) {
    char* msg{};
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msg, 0, nullptr
    );
    return std::string(msg);
}

static std::string format_openssl_error() {
    std::string result;
    unsigned long errCode;

    while ((errCode = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(errCode, buf, sizeof(buf));
        result += buf;
        result += '\n';
    }

    return result;
}

static bool wait_for_socket(SOCKET sock, bool for_write, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int result = select(0, for_write ? nullptr : &fds, for_write ? &fds : nullptr, nullptr, &tv);
    return result > 0;
}

static std::string https_get(const char* hostname, const char* path) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0)
        throw std::runtime_error("WSAStartup failed");

    struct hostent* host = gethostbyname(hostname);
    if (!host || !host->h_addr)
        throw std::runtime_error("Failed to resolve hostname");

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        throw std::runtime_error(format_winsock_error(WSAGetLastError()));

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(443);
    server.sin_addr.s_addr = *(u_long*)host->h_addr;

    connect(sock, (sockaddr*)&server, sizeof(server));

    if (!wait_for_socket(sock, true, 5000)) {
        closesocket(sock);
        throw std::runtime_error("Connection timed out");
    }

    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);

    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        closesocket(sock);
        throw std::runtime_error(format_openssl_error());
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(sock);
        throw std::runtime_error("SSL_connect failed: " + format_openssl_error());
    }

    std::string request = "GET ";
    request += path;
    request += " HTTP/1.1\r\nHost: ";
    request += hostname;
    request += "\r\nConnection: close\r\n\r\n";

    if (SSL_write(ssl, request.c_str(), (int)request.length()) <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(sock);
        throw std::runtime_error("SSL_write failed: " + format_openssl_error());
    }

    std::string response;
    char buffer[4096];
    int bytes;

    while (true) {
        if (!wait_for_socket(sock, false, 5000)) {
            throw std::runtime_error("SSL_read timed out");
        }
        bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes > 0) {
            response.append(buffer, bytes);
        }
        else {
            int err = SSL_get_error(ssl, bytes);
            if (err == SSL_ERROR_ZERO_RETURN || bytes == 0)
                break;
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                throw std::runtime_error("SSL_read failed: " + format_openssl_error());
            break;
        }
    }

    size_t header_end = response.find("\r\n\r\n");
    if (header_end != std::string::npos)
        response = response.substr(header_end + 4);
    else
        response.clear();

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(sock);
    WSACleanup();
    return response;
}

void plugin::gameStartupEvent() {

    // Set FixPCIDKickbug to 0

    std::fstream file("ZolikaPatch.ini", std::ios::in | std::ios::out);
    if (file) {
        std::string line;
        std::streampos pos;
        while (pos = file.tellg(), std::getline(file, line)) {
            if (line == "FixPCIDKickbug=1") {
                file.seekp(pos);
                file << "FixPCIDKickbug=0";
                break;
            }
        }
    }

    // Download PCID-key pairs

    nlohmann::json jsonData;
    const char url[] = "http://gist.githubusercontent.com/Yilmaz4/354e733972d8a55b04007c53ff0f9ce4/raw";

    try {
        std::string data = https_get("gist.githubusercontent.com", "Yilmaz4/354e733972d8a55b04007c53ff0f9ce4/raw");
        jsonData = nlohmann::json::parse(data);
        for (const auto& pair : jsonData) {
            std::string pcid = pair["pcid"];
            std::wstring key = string_to_wstring(pair["key"]);
            pairs.push_back({ pcid, key });
        }
    }
    catch (std::exception& e) {
        std::string err = "Failed to fetch PCIDs from GitHub. Falling back to cache. You are more likely to experience PCID conflict.\n\n" + std::string(e.what());
        MessageBox(NULL, err.c_str(), "Warning", MB_OK | MB_ICONINFORMATION);
        pairs = pairs_offline;
    }

    // Choose PCID-key pair

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, pairs.size() - 1);

    std::pair<std::string, std::wstring> pair = pairs[dist(gen)];

    // Delete previous token.bin

    char path[MAX_PATH];

    if (!SUCCEEDED(SHGetFolderPath(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path))) {
        MessageBox(NULL, "Failed to locate %localappdata%", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    strcat(path, "\\Microsoft\\XLive\\Titles\\5454083b");
    
    std::filesystem::path folderPath = path;

    if (std::filesystem::exists(folderPath)) {
        std::error_code ec;
        std::filesystem::remove_all(folderPath, ec);
        if (ec) {
            MessageBox(NULL, ec.message().c_str(), "Failed to delete file", MB_OK | MB_ICONERROR);
            return;
        }
    }

    // Activate GFWL

    HMODULE hModule = LoadLibrary("LiveTokenHelper.dll");
    if (!hModule) {
        MessageBox(NULL, "Failed to load LiveTokenHelper.dll", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    auto XLiveSetSponsorToken = reinterpret_cast<XLiveSetSponsorTokenFunc>(GetProcAddress(hModule, "XLiveSetSponsorToken"));
    if (!XLiveSetSponsorToken) {
        MessageBox(NULL, "Failed to find XLiveSetSponsorToken function in LiveTokenHelper.dll", "Error", MB_OK | MB_ICONERROR);
        FreeLibrary(hModule);
        return;
    }

    uint8_t titleIDbytes[] = { 0x3B, 0x08, 0x54, 0x54 };
    uint32_t titleID;
    std::memcpy(&titleID, titleIDbytes, sizeof(titleID));
    
    try {
        XLiveSetSponsorToken(pair.second.c_str(), titleID);
    }
    catch (const std::exception& e) {
        MessageBox(NULL, e.what(), "Error", MB_OK | MB_ICONERROR);
        FreeLibrary(hModule);
        return;
    }
    FreeLibrary(hModule);

    // Write PCID to registry

    HKEY hKey;
    LONG result = RegCreateKeyEx(
        HKEY_CURRENT_USER,
        "Software\\Classes\\SOFTWARE\\Microsoft\\XLive",
        NULL,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hKey,
        nullptr
    );

    if (result != ERROR_SUCCESS) {
        MessageBox(NULL, "Failed to open registry", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::uint64_t val = std::stoull(pair.first, nullptr, 16);
    result = RegSetValueEx(
        hKey,
        "PCID",
        NULL,
        REG_QWORD,
        reinterpret_cast<const BYTE*>(&val),
        sizeof(val)
    );

    if (result != ERROR_SUCCESS) {
        MessageBox(NULL, "Failed to write to registry", "Error", MB_OK | MB_ICONERROR);
    }

    RegCloseKey(hKey);
}