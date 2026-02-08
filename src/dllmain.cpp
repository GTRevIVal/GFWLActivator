#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <shlobj.h>
#include <locale>
#include <thread>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include "minhook/MinHook.h"
#include "IVSDK.cpp"

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

    // new
    {"30372378dd64c533", L"QKH8F-MQGRB-BK84C-PQDKX-WYHDD"},
    {"65d34194039b7fab", L"QKH8F-MQGRB-BK84C-PQDKX-WYHDD"},
    {"b0633a3104122d67", L"QKH8F-MQGRB-BK84C-PQDKX-WYHDD"},
    {"e12e097fb62d5ee3", L"QKH8F-MQGRB-BK84C-PQDKX-WYHDD"},
    {"e14b8ec65d92fd14", L"QKH8F-MQGRB-BK84C-PQDKX-WYHDD"},
    {"375d9f5e673155e2", L"QKH8F-MQGRB-BK84C-PQDKX-WYHDD"},
    {"be7e1183bfa0c68a", L"QKH8F-MQGRB-BK84C-PQDKX-WYHDD"},
    {"3db08f7f0aa1a255", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"8588eeaab73a4027", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"43f9fb4a2dbe33e6", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"fe91ce113e376b6d", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"9e65dcb9dfce669c", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"97076195f62d640d", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"b395bf8df18ff1a9", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"e73fc60d680912c0", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"323c597b34d50427", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"2b7230302b5d6639", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"bffb617d5874c87d", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"b18a8b7da38f4978", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"6d3fb7bef6f9d923", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},
    {"029dbf419f4d926e", L"Q7JJ3-6DGH3-KQRP7-7JFFH-GK6V3"},

};

static std::wstring string_to_wstring(const std::string& str) {
    std::wstring ws(str.begin(), str.end());
    return ws;
}

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    std::string* buffer = static_cast<std::string*>(userp);
    buffer->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

std::string download_from_web(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }

    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code >= 400) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("HTTP error: " + std::to_string(http_code));
    }

    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error(curl_easy_strerror(res));
    }
    curl_easy_cleanup(curl);
    return response;
}

void plugin::gameStartupEvent() {}

BOOL(WINAPI* original_ShowWindow)(HWND hWnd, int nCmdShow) = nullptr;
std::atomic<bool> gfwl_activated = false;

BOOL WINAPI hooked_ShowWindow(HWND hWnd, int nCmdShow) {
    gfwl_activated.wait(false);
    return original_ShowWindow(hWnd, nCmdShow);
}

DWORD WINAPI InstallHookThread(LPVOID) {
    if (MH_Initialize() != MH_OK) return 1;

    if (MH_CreateHook(
        &ShowWindow,
        &hooked_ShowWindow,
        reinterpret_cast<void**>(&original_ShowWindow)
    ) != MH_OK) return 2;

    if (MH_EnableHook(&ShowWindow) != MH_OK) return 3;

    return 0;
}

void activate_gfwl() {

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
        std::string data = download_from_web("gist.githubusercontent.com/Yilmaz4/354e733972d8a55b04007c53ff0f9ce4/raw");
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
        ExitProcess(1);
    }
    strcat(path, "\\Microsoft\\XLive\\Titles\\5454083b");

    std::filesystem::path folderPath = path;

    if (std::filesystem::exists(folderPath)) {
        std::error_code ec;
        std::filesystem::remove_all(folderPath, ec);
        if (ec) {
            MessageBox(NULL, ec.message().c_str(), "Failed to delete file", MB_OK | MB_ICONERROR);
            ExitProcess(1);
        }
    }

    // Activate GFWL

    HMODULE hModule = LoadLibrary("LiveTokenHelper.dll");
    if (!hModule) {
        MessageBox(NULL, "Failed to load LiveTokenHelper.dll", "Error", MB_OK | MB_ICONERROR);
        ExitProcess(1);
    }

    auto XLiveSetSponsorToken = reinterpret_cast<XLiveSetSponsorTokenFunc>(GetProcAddress(hModule, "XLiveSetSponsorToken"));
    if (!XLiveSetSponsorToken) {
        MessageBox(NULL, "Failed to find XLiveSetSponsorToken function in LiveTokenHelper.dll", "Error", MB_OK | MB_ICONERROR);
        FreeLibrary(hModule);
        ExitProcess(1);
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
        ExitProcess(1);
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
        ExitProcess(1);
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
        ExitProcess(1);
    }

    RegCloseKey(hKey);

    gfwl_activated.store(true);
    gfwl_activated.notify_all();
}

BOOL WINAPI DllMain(const HMODULE instance, const uintptr_t reason, const void* lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        std::thread(&activate_gfwl).detach();

        DisableThreadLibraryCalls(instance);
        CreateThread(nullptr, 0, InstallHookThread, nullptr, 0, nullptr);

        plugin::Init();
    }
    return TRUE;
}
