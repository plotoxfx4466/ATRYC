#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Psapi.lib")

struct ConnInfo {
    std::string localAddr;
    DWORD localPort;
    std::string remoteAddr;
    DWORD remotePort;
    std::string state;
    DWORD pid;
    std::string processName;
    std::string remoteName;
};


void printHeader() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::cout << R"(  
        _______ _______     _______ 
     /\|__   __|  __ \ \   / / ____|
    /  \  | |  | |__) \ \_/ / |     
   / /\ \ | |  |  _  / \   /| |     
  / ____ \| |  | | \ \  | | | |____ 
 /_/    \_\_|  |_|  \_\ |_|  \_____|
                                    
                                    
)" << "\n";
}


std::string tcpStateToString(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED: return "CLOSED";
    case MIB_TCP_STATE_LISTEN: return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
    default: return "UNKNOWN";
    }
}

std::string resolveDNS(const std::string& ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    char host[NI_MAXHOST];
    if (getnameinfo((sockaddr*)&sa, sizeof(sa), host, sizeof(host), nullptr, 0, 0) == 0)
        return std::string(host);
    return "-";
}

std::string getProcessNameByPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return "-";

    char name[MAX_PATH];
    if (GetModuleBaseNameA(hProcess, nullptr, name, sizeof(name))) {
        CloseHandle(hProcess);
        return std::string(name);
    }
    CloseHandle(hProcess);
    return "-";
}

std::vector<ConnInfo> getConnections() {
    std::vector<ConnInfo> conns;
    PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;
    DWORD size = 0;

    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER)
        tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);

    if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID row = tcpTable->table[i];
            ConnInfo c;

            char localIP[INET_ADDRSTRLEN], remoteIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &row.dwLocalAddr, localIP, sizeof(localIP));
            inet_ntop(AF_INET, &row.dwRemoteAddr, remoteIP, sizeof(remoteIP));

            c.localAddr = localIP;
            c.remoteAddr = remoteIP;
            c.localPort = ntohs((u_short)row.dwLocalPort);
            c.remotePort = ntohs((u_short)row.dwRemotePort);
            c.state = tcpStateToString(row.dwState);
            c.pid = row.dwOwningPid;
            c.processName = getProcessNameByPID(row.dwOwningPid);
            c.remoteName = resolveDNS(c.remoteAddr);

            conns.push_back(c);
        }
    }

    if (tcpTable) free(tcpTable);
    return conns;
}


void scanNetwork() {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    hostent* host = gethostbyname(hostname);
    if (!host) {
        std::cout << "IP adresi alinamadi!\n";
        return;
    }

    in_addr addr;
    memcpy(&addr, host->h_addr_list[0], sizeof(in_addr));
    std::string localIP = inet_ntoa(addr);
    std::string baseIP = localIP.substr(0, localIP.rfind('.') + 1);

    std::cout << "Ag: " << baseIP << "0/24 taraniyor...\n\n";
    for (int i = 1; i <= 254; ++i) {
        std::string testIP = baseIP + std::to_string(i);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, testIP.c_str(), &sa.sin_addr);
        char hostbuf[NI_MAXHOST];
        if (getnameinfo((sockaddr*)&sa, sizeof(sa), hostbuf, sizeof(hostbuf), nullptr, 0, NI_NAMEREQD) == 0)
            std::cout << std::setw(16) << testIP << " -> " << hostbuf << "\n";
    }
}

bool isPortOpen(const std::string& ip, int port, int timeoutMs = 200) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    sa.sin_port = htons(port);

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    connect(sock, (sockaddr*)&sa, sizeof(sa));

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    int result = select(0, nullptr, &writeSet, nullptr, &tv);
    closesocket(sock);
    return result > 0;
}

void scanOpenPorts() {
    std::string targetIP;
    std::cout << "Hedef IP adresini girin: ";
    std::cin >> targetIP;
    int startPort = 1, endPort = 1024;
    std::cout << "Port araligini girin (ornek: 1 1024): ";
    std::cin >> startPort >> endPort;
    std::cout << "\n" << targetIP << " adresindeki acik portlar:\n";

    for (int port = startPort; port <= endPort; ++port)
        if (isPortOpen(targetIP, port)) std::cout << "Port " << port << " ACIK\n";

    std::cout << "Tarama tamamlandi.\n";
}

void scanLocalOpenPorts() {
    auto conns = getConnections();
    std::cout << "\nKendi sistemindeki acik portlar:\n";
    for (auto& c : conns)
        if (c.state == "LISTEN")
            std::cout << c.localAddr << ":" << c.localPort << " (" << c.processName << ")\n";
}


void pingHost() { std::string host; std::cout << "Ping atilacak adres: "; std::cin >> host; system(("ping " + host).c_str()); }
void traceRoute() { std::string host; std::cout << "Traceroute adresi: "; std::cin >> host; system(("tracert " + host).c_str()); }
void dnsLookup() {
    std::string domain;
    std::cout << "Domain girin: ";
    std::cin >> domain;
    hostent* he = gethostbyname(domain.c_str());
    if (!he) { std::cout << "DNS çözümlenemedi!\n"; return; }
    std::cout << "IP adresleri:\n";
    for (int i = 0; he->h_addr_list[i] != 0; ++i) {
        in_addr addr;
        memcpy(&addr, he->h_addr_list[i], sizeof(in_addr));
        std::cout << " - " << inet_ntoa(addr) << "\n";
    }
}
void showARPTable() { system("arp -a"); }
void liveConnectionsMonitor() {
    std::cout << "Canlı bağlantı takibi (Ctrl+C ile çıkabilirsiniz)\n";
    while (true) {
        system("cls");
        auto conns = getConnections();
        std::cout << std::left << std::setw(18) << "Local Address"
            << std::setw(18) << "Remote Address"
            << std::setw(14) << "State"
            << std::setw(8) << "PID"
            << std::setw(25) << "Process"
            << "Remote Host" << "\n";
        std::cout << std::string(100, '-') << "\n";
        for (auto& c : conns)
            std::cout << std::setw(18) << (c.localAddr + ":" + std::to_string(c.localPort))
            << std::setw(18) << (c.remoteAddr + ":" + std::to_string(c.remotePort))
            << std::setw(14) << c.state
            << std::setw(8) << c.pid
            << std::setw(25) << c.processName
            << c.remoteName << "\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}


int main() {
    SetConsoleTitleA("ATRYC");
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    while (true) {
        system("cls");
        printHeader();
        std::cout << "===== AG VE BAGLANTI GOZLEMLEYICI =====\n";
        std::cout << "1. Aga bagli cihazlari goster\n";
        std::cout << "2. Bilgisayarin yaptigi baglantilari goster\n";
        std::cout << "3. Agdaki acik portlari tara\n";
        std::cout << "4. Kendi acik portlarini tara\n";
        std::cout << "5. Ping at\n";
        std::cout << "6. Traceroute\n";
        std::cout << "7. DNS cozumleme\n";
        std::cout << "8. ARP tablosunu goster\n";
        std::cout << "9. Canli baglanti takibi\n";
        std::cout << "0. Cikis\n";
        std::cout << "Seciminiz: ";

        int secim;
        if (!(std::cin >> secim)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        std::cout << "\n";
        switch (secim) {
        case 1: scanNetwork(); break;
        case 2: {
            auto connections = getConnections();
            std::cout << std::left << std::setw(18) << "Local Address"
                << std::setw(18) << "Remote Address"
                << std::setw(14) << "State"
                << std::setw(8) << "PID"
                << std::setw(25) << "Process"
                << "Remote Host" << "\n";
            std::cout << std::string(100, '-') << "\n";
            for (auto& c : connections)
                std::cout << std::setw(18) << (c.localAddr + ":" + std::to_string(c.localPort))
                << std::setw(18) << (c.remoteAddr + ":" + std::to_string(c.remotePort))
                << std::setw(14) << c.state
                << std::setw(8) << c.pid
                << std::setw(25) << c.processName
                << c.remoteName << "\n";
            break;
        }
        case 3: scanOpenPorts(); break;
        case 4: scanLocalOpenPorts(); break;
        case 5: pingHost(); break;
        case 6: traceRoute(); break;
        case 7: dnsLookup(); break;
        case 8: showARPTable(); break;
        case 9: liveConnectionsMonitor(); break;
        case 0:
            std::cout << "Programdan cikiliyor...\n";
            WSACleanup();
            return 0;
        default:
            std::cout << "Gecersiz secim!\n";
            break;
        }

        std::cout << "\nDevam etmek icin bir tusa basin...";
        std::cin.ignore();
        std::cin.get();
    }   
}
