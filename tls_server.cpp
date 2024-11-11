//code from https://gist.github.com/mmozeiko/c0dfcc8fec527a90a02145d2cc0bfb6d

#define _WIN32_WINNT _WIN32_WINNT_WIN8
#define NTDDI_VERSION NTDDI_WIN8

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>
#include <assert.h>
#include <stdio.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <wincrypt.h>
#include <sstream>
#include <iomanip>
#include "leikaifeng.h"
#define SCH_USE_STRONG_CRYPTO 0x00400000

#define SP_PROT_TLS1_2_SERVER 0x00000400
#define SP_PROT_TLS1_2_CLIENT 0x00000800
#define SP_PROT_TLS1_2 (SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_2_CLIENT)
#define TLS_MAX_PACKET_SIZE (16384 + 512)

class MyServerCerd : Delete_Base
{

    HCERTSTORE hStore;

    PCCERT_CONTEXT pCertContext;

    static std::vector<char> readFile(const std::wstring &wfilePath)
    {
        auto filePath = ::UTF8::GetMultiByte(wfilePath);
        // 打开文件
        std::ifstream file(filePath, std::ios::binary);
        if (!file)
        {
            throw std::runtime_error("can not open: " + filePath);
        }

        // 读取文件内容
        file.seekg(0, std::ios::end);        // 移动到文件末尾
        std::streamsize size = file.tellg(); // 获取文件大小
        file.seekg(0, std::ios::beg);        // 移动回文件开头

        std::vector<char> buffer(size);
        if (!file.read(buffer.data(), size))
        {
            throw std::runtime_error("read error");
        }

        return buffer; // 返回文件内容
    }

public:
    MyServerCerd(std::vector<char> &buf)
    {

        // 创建用于存放 PFX 数据的 CRYPT_DATA_BLOB
        CRYPT_DATA_BLOB pfxBlob;
        pfxBlob.cbData = static_cast<DWORD>(buf.size());
        pfxBlob.pbData = reinterpret_cast<BYTE *>(buf.data());

        // 处理 PFX 数据
        hStore = PFXImportCertStore(&pfxBlob, L"", CRYPT_EXPORTABLE);
        if (hStore == NULL)
        {

            Exit("PFXImportCertStore error");
        }

        // 从存储中获取证书
        pCertContext = CertEnumCertificatesInStore(hStore, NULL);
        if (pCertContext == NULL)
        {
            Exit("CertEnumCertificatesInStore error");
        }
    }

    static auto Create()
    {

        std::vector<char> buf;
        try
        {

            std::wstring ws{LR"(C:\Users\PC\Desktop\测试的证书\server.p12)"};

            buf = readFile(ws);
            std::cout << "red ok size: " << buf.size() << " bytes" << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "error: " << e.what() << std::endl;
        }

        return std::make_unique<MyServerCerd>(buf);
    }

    auto &Get()
    {
        return pCertContext;
    }

    ~MyServerCerd()
    {
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
    }
};

void mylisn(std::function<void(SOCKET s)> func)
{

    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
    {
        Exit("WSAStartup error", WSAGetLastError());
    }

    auto sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        Exit("create socket error", WSAGetLastError());
    }

    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr("127.0.0.1");
    service.sin_port = htons(443);
    auto res = bind(sock, (SOCKADDR *)&service, sizeof(service));

    if (res == SOCKET_ERROR)
    {
        Exit("bind socket error", WSAGetLastError());
    }

    res = listen(sock, 6);

    if (res == SOCKET_ERROR)
    {
        Exit("listen socket error", WSAGetLastError());
    }

    while (true)
    {

        sockaddr_in client;
        int clientsize = sizeof(client);
        auto connct = accept(sock, (SOCKADDR *)&client, &clientsize);

        if (connct == INVALID_SOCKET)
        {
            Exit("accept socket error", WSAGetLastError());
        }

        func(connct);
    }
}

typedef struct
{
    SOCKET sock;
    CredHandle handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    int received;    // byte count in incoming buffer (ciphertext)传入缓冲区中的字节数（密文）
    int used;        // byte count used from incoming buffer to decrypt current packet传入缓冲区中用于解密当前数据包的字节数
    int available;   // byte count available for decrypted bytes可用于解密字节的字节数
    char *decrypted; // points to incoming buffer where data is decrypted inplace指向传入缓冲区，数据在此解密
    char incoming[TLS_MAX_PACKET_SIZE];
} tls_socket;

int mysend(SOCKET s, char *buffer, int size)
{

    while (size != 0)
    {
        int d = send(s, buffer, size, 0);
        if (d <= 0)
        {
            break;
        }
        size -= d;
        buffer += d;
    }

    if (size == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

// returns 0 on success or negative value on error成功时返回 0，错误时返回负值
static int tls_connect(tls_socket *s)
{
    auto myservercerd = ::MyServerCerd::Create();

    // initialize schannel
    {

        SCHANNEL_CRED cred = {};
        cred.dwVersion = SCHANNEL_CRED_VERSION;
        cred.dwFlags = SCH_USE_STRONG_CRYPTO;        // use only strong crypto alogorithms仅使用强大的加密算法
                                                     //| SCH_CRED_AUTO_CRED_VALIDATION  // automatically validate server certificate自动验证服务器证书
                                                     //| SCH_CRED_NO_DEFAULT_CREDS;     // no client certificate authentication无客户端证书身份验证
        cred.grbitEnabledProtocols = SP_PROT_TLS1_2; // allow only TLS v1.2仅允许 TLS v1.2

        cred.paCred = &myservercerd->Get();
        cred.cCreds = 1;

        if (AcquireCredentialsHandleW(NULL, UNISP_NAME_W, SECPKG_CRED_INBOUND, NULL, &cred, NULL, NULL, &s->handle, NULL) != SEC_E_OK)
        {
            Exit("AcquireCredentialsHandleW error");
        }
    }

    s->received = s->used = s->available = 0;
    s->decrypted = NULL;

    // perform tls handshake
    // 1) call InitializeSecurityContext to create/update schannel context
    // 2) when it returns SEC_E_OK - tls handshake completed
    // 3) when it returns SEC_I_INCOMPLETE_CREDENTIALS - server requests client certificate (not supported here)
    // 4) when it returns SEC_I_CONTINUE_NEEDED - send token to server and read data
    // 5) when it returns SEC_E_INCOMPLETE_MESSAGE - need to read more data from server
    // 6) otherwise read data from server and go to step 1

    // 执行 tls 握手
    // 1) 调用 InitializeSecurityContext 来创建/更新 schannel 上下文
    // 2) 当它返回 SEC_E_OK 时 - tls 握手已完成
    // 3) 当它返回 SEC_I_INCOMPLETE_CREDENTIALS 时 - 服务器请求客户端证书（此处不支持）
    // 4) 当它返回 SEC_I_CONTINUE_NEEDED 时 - 将令牌发送到服务器并读取数据
    // 5) 当它返回 SEC_E_INCOMPLETE_MESSAGE 时 - 需要从服务器读取更多数据
    // 6) 否则从服务器读取数据并转到步骤 1

    CtxtHandle *context = NULL;
    int result = 0;
    for (;;)
    {

        // read more data from server when possible尽可能从读取更多数据
        if (s->received == sizeof(s->incoming))
        {

            // server is sending too much data instead of proper handshake?对面发送了太多数据而不是正确的握手？
            result = -1;

            Print("server is sending too much data instead of proper handshake");
            break;
        }

        auto m_v = sizeof(s->incoming) - s->received;
        Print("read bytes from client");
        int r = recv(s->sock, s->incoming + s->received, static_cast<int>(m_v), 0);
        Print("red count", r);
        if (r == 0)
        {
            // server disconnected socket服务器断开套接字
            // 资源需要后续释放
            return 0;
        }
        else if (r < 0)
        {
            // socket error
            result = -1;
            break;
        }
        else
        {
            s->received += r;
        }

        SecBuffer inbuffers[2] = {0};
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = s->incoming;
        inbuffers[0].cbBuffer = s->received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        // 这个缓冲器会由系统分配ISC_REQ_ALLOCATE_MEMORY
        SecBuffer outbuffers[2] = {0};
        outbuffers[0].BufferType = SECBUFFER_TOKEN;
        outbuffers[1].BufferType = SECBUFFER_EMPTY;
        // 输入输出上下文的缓冲器如何使用跟上下文语义有关
        SecBufferDesc indesc = {SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers};
        SecBufferDesc outdesc = {SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers};

        DWORD flags = ASC_REQ_ALLOCATE_MEMORY |
         ASC_REQ_CONFIDENTIALITY |
          ASC_REQ_STREAM |
           ASC_REQ_REPLAY_DETECT | 
           ASC_REQ_SEQUENCE_DETECT;

        DWORD outFlage = 0;

        SECURITY_STATUS sec = AcceptSecurityContext(
            &s->handle,
            context,
            &indesc,
            flags,
            0,
            context ? NULL : &s->context,
            &outdesc,
            &outFlage,
            NULL);

        // after first call to InitializeSecurityContext context is available and should be reused for next calls
        // 第一次调用 InitializeSecurityContext 后上下文可用，并且应该在下次调用中重用
        Print("context == s->context", context == &s->context, &s->context);
        context = &s->context;

        // 安全包使用此值来指示消息中额外或未处理的字节数。
        // 应该是把已经使用的删掉, 把未使用的挪到开头, 读取更多后重新调用
        if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            Print("has can not use bytes");
            MoveMemory(s->incoming, s->incoming + (s->received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
            s->received = inbuffers[1].cbBuffer;
        }
        else
        {
            s->received = 0;
        }

        if (outbuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            Print("out has can not use bytes");
        }

        if (sec == SEC_E_INCOMPLETE_MESSAGE)
        {
            Print("AcceptSecurityContext ok but need bytes", outbuffers->cbBuffer);
        }
        else if (sec == SEC_I_CONTINUE_NEEDED)
        {
            Print("need send bytes to server");
            // need to send data to server需要发送数据到服务器
            char *buffer = static_cast<char *>(outbuffers[0].pvBuffer);
            int size = outbuffers[0].cbBuffer;

            int r = mysend(s->sock, buffer, size);
            FreeContextBuffer(outbuffers[0].pvBuffer);
            if (r != 0)
            {
                // failed to fully send data to server无法将数据完整发送到服务器
                result = -1;
                break;
            }
        }
        else if (sec == SEC_E_OK)
        {

            char *buffer = static_cast<char *>(outbuffers[0].pvBuffer);
            int size = outbuffers[0].cbBuffer;

            if (size != 0)
            {
                Print("tls ok but  need send bytes to server");
                // need to send data to server需要发送数据到服务器

                int r = mysend(s->sock, buffer, size);
                FreeContextBuffer(outbuffers[0].pvBuffer);
                if (r != 0)
                {
                    // failed to fully send data to server无法将数据完整发送到服务器
                    result = -1;
                    break;
                }
            }

            // tls handshake completed,  tls握手完成
            Print("tls handshake completed");
            break;
        }
        else
        {

            std::stringstream ss;
            ss << std::hex << std::uppercase << sec; // 使用十六进制格式，并将字母转换为大写
            std::string hexString = ss.str();

            Exit("tls connect other error" + hexString);
            // 其他错误
            result = -1;
            break;
        }
    }

    if (result != 0)
    {
        DeleteSecurityContext(context);
        FreeCredentialsHandle(&s->handle);
        closesocket(s->sock);
        return result;
    }

    QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &s->sizes);
    return 0;
}

// disconnects socket & releases resources (call this even if tls_write/tls_read function return error)断开套接字并释放资源（即使 tls_write/tls_read 函数返回错误也调用此函数）
static void tls_disconnect(tls_socket *s)
{
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = {SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers};
    ApplyControlToken(&s->context, &indesc);

    // 这个缓冲器会由系统分配ISC_REQ_ALLOCATE_MEMORY
    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = {SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers};
    DWORD flags = ASC_REQ_ALLOCATE_MEMORY |
         ASC_REQ_CONFIDENTIALITY |
          ASC_REQ_STREAM |
           ASC_REQ_REPLAY_DETECT | 
           ASC_REQ_SEQUENCE_DETECT;
    DWORD outFlags;
    auto sec = AcceptSecurityContext(
        &s->handle,
     &s->context,
      NULL, 
      flags,
      0,
      &s->context,
      &outdesc,
      &outFlags,
      NULL);
    if (sec == SEC_E_OK)
    {
        char *buffer = static_cast<char *>(outbuffers[0].pvBuffer);
        int size = outbuffers[0].cbBuffer;
        mysend(s->sock, buffer, size);
        FreeContextBuffer(outbuffers[0].pvBuffer);
    }
    else{

        std::stringstream ss;
        ss << std::hex << std::uppercase << sec; // 使用十六进制格式，并将字母转换为大写
        std::string hexString = ss.str();

        Exit("tls close other error" + hexString);
        // 其他错误
    }
    shutdown(s->sock, SD_BOTH);

    DeleteSecurityContext(&s->context);
    FreeCredentialsHandle(&s->handle);
    closesocket(s->sock);
}

// returns 0 on success or negative value on error
static int tls_write(tls_socket *s, const void *buffer, int size)
{
    while (size != 0)
    {
        int use = std::min(static_cast<unsigned long>(size), s->sizes.cbMaximumMessage);

        char wbuffer[TLS_MAX_PACKET_SIZE];
        assert(s->sizes.cbHeader + s->sizes.cbMaximumMessage + s->sizes.cbTrailer <= sizeof(wbuffer));

        SecBuffer buffers[3];
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = wbuffer;
        buffers[0].cbBuffer = s->sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = wbuffer + s->sizes.cbHeader;
        buffers[1].cbBuffer = use;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = wbuffer + s->sizes.cbHeader + use;
        buffers[2].cbBuffer = s->sizes.cbTrailer;

        CopyMemory(buffers[1].pvBuffer, buffer, use);

        SecBufferDesc desc = {SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers};
        SECURITY_STATUS sec = EncryptMessage(&s->context, 0, &desc, 0);
        if (sec != SEC_E_OK)
        {
            // this should not happen, but just in case check it这不应该发生，但为了以防万一，请检查一下
            return -1;
        }

        int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        int sent = 0;
        while (sent != total)
        {
            int d = send(s->sock, wbuffer + sent, total - sent, 0);
            if (d <= 0)
            {
                // error sending data to socket, or server disconnected
                return -1;
            }
            sent += d;
        }

        buffer = (char *)buffer + use;
        size -= use;
    }

    return 0;
}

// blocking read, waits & reads up to size bytes, returns amount of bytes received on success (<= size)
// returns 0 on disconnect or negative value on error
// 阻塞读取，等待并读取最多 size 个字节，成功时返回接收到的字节数 (<= size)
// 断开连接时返回 0，出错时返回负值
static int tls_read(tls_socket *s, void *buffer, int size)
{
    int result = 0;

    while (size != 0)
    {
        if (s->decrypted)
        {
            // if there is decrypted data available, then use it as much as possible如果有解密数据可用，则尽可能使用它
            int use = std::min(size, s->available);
            CopyMemory(buffer, s->decrypted, use);
            buffer = (char *)buffer + use;
            size -= use;
            result += use;

            if (use == s->available)
            {
                // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning所有解密数据都已使用，从传入缓冲区中删除密文，以便下次从头开始
                MoveMemory(s->incoming, s->incoming + s->used, s->received - s->used);
                s->received -= s->used;
                s->used = 0;
                s->available = 0;
                s->decrypted = NULL;
            }
            else
            {
                s->available -= use;
                s->decrypted += use;
            }
        }
        else
        {
            // if any ciphertext data available then try to decrypt it如果有密文数据可用，则尝试解密
            if (s->received != 0)
            {
                SecBuffer buffers[4];
                assert(s->sizes.cBuffers == ARRAYSIZE(buffers));

                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = s->incoming;
                buffers[0].cbBuffer = s->received;
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc = {SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers};

                SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, NULL);
                if (sec == SEC_E_OK)
                {
                    assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                    assert(buffers[1].BufferType == SECBUFFER_DATA);
                    assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                    s->decrypted = static_cast<char *>(buffers[1].pvBuffer);
                    s->available = buffers[1].cbBuffer;
                    s->used = s->received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                    // data is now decrypted, go back to beginning of loop to copy memory to output buffer数据现在已解密，返回循环开始处以将内存复制到输出缓冲区
                    continue;
                }
                else if (sec == SEC_I_CONTEXT_EXPIRED)
                {
                    // server closed TLS connection (but socket is still open)服务器关闭了 TLS 连接（但套接字仍然打开）
                    s->received = 0;
                    return result;
                }
                else if (sec == SEC_I_RENEGOTIATE)
                {
                    // server wants to renegotiate TLS connection, not implemented here服务器希望重新协商 TLS 连接，这里没有实现
                    return -1;
                }
                else if (sec != SEC_E_INCOMPLETE_MESSAGE)
                {
                    // some other schannel or TLS protocol error其他一些 schannel 或 TLS 协议错误
                    return -1;
                }
                // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data否则 sec == SEC_E_INCOMPLETE_MESSAGE 表示需要读取更多数据
            }
            // otherwise not enough data received to decrypt否则没有收到足够的数据来解密

            if (result != 0)
            {
                // some data is already copied to output buffer, so return that before blocking with recv一些数据已复制到输出缓冲区，因此在使用 recv 阻塞之前返回这些数据
                break;
            }

            if (s->received == sizeof(s->incoming))
            {
                // server is sending too much garbage data instead of proper TLS packet服务器发送了太多垃圾数据，而不是正确的 TLS 数据包
                return -1;
            }
            auto m_v = sizeof(s->incoming) - s->received;
            // wait for more ciphertext data from server等待服务器发送更多密文数据
            int r = recv(s->sock, s->incoming + s->received, static_cast<int>(m_v), 0);
            if (r == 0)
            {
                // server disconnected socket
                return 0;
            }
            else if (r < 0)
            {
                // error receiving data from socket
                result = -1;
                break;
            }
            s->received += r;
        }
    }

    return result;
}

int main()
{

    mylisn([](auto connect) -> void
    {
        
        tls_socket s = {};

        s.sock = connect;

        int r = tls_connect(&s);

        if (r == 0)
        {

            while (true)
            {

                char bf[81920];

                int r = tls_read(&s, bf, sizeof(bf));

                if (r > 0)
                {
                    r = tls_write(&s, bf, r);

                    if (r != 0)
                    {
                        Print("write error");

                        break;
                    }
                }
                else
                {
                    Print("red error or over");

                    break;
                }
            }
        }

        tls_disconnect(&s);
    });
}
