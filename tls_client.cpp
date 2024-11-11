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
#include "leikaifeng.h"

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "secur32.lib")
#pragma comment (lib, "shlwapi.lib")
#define SCH_USE_STRONG_CRYPTO 0x00400000

#define SP_PROT_TLS1_2_SERVER 0x00000400
#define SP_PROT_TLS1_2_CLIENT 0x00000800
#define SP_PROT_TLS1_2 (SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_2_CLIENT)

//有效载荷 + 标头/mac/填充的额外开销（可能估计过高）
#define TLS_MAX_PACKET_SIZE (16384+512) // payload + extra over head for header/mac/padding (probably an overestimate)

typedef struct {
    SOCKET sock;
    CredHandle handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    int received;    // byte count in incoming buffer (ciphertext)传入缓冲区中的字节数（密文）
    int used;        // byte count used from incoming buffer to decrypt current packet传入缓冲区中用于解密当前数据包的字节数
    int available;   // byte count available for decrypted bytes可用于解密字节的字节数
    char* decrypted; // points to incoming buffer where data is decrypted inplace指向传入缓冲区，数据在此解密
    char incoming[TLS_MAX_PACKET_SIZE];
} tls_socket;


static int sock_connect(tls_socket* s, const char* hostname, unsigned short port){
    // initialize windows sockets
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
    {
        return -1;
    }

    // create TCP IPv4 socket
    s->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    char sport[64];
    wnsprintfA(sport, sizeof(sport), "%u", port);
    std::string hostname2{hostname};
    // connect to server
    if (!WSAConnectByNameA(s->sock,  hostname2.data(), sport, NULL, NULL, NULL, NULL, NULL, NULL))
    {
        closesocket(s->sock);
        WSACleanup();
        return -1;
    }

    return 0;
}

// returns 0 on success or negative value on error成功时返回 0，错误时返回负值
static int tls_connect(tls_socket* s, const char* hostname, unsigned short port)
{
    
    // initialize schannel
    {


        SCHANNEL_CRED cred = {};
        cred.dwVersion = SCHANNEL_CRED_VERSION;
        cred.dwFlags = SCH_USE_STRONG_CRYPTO          // use only strong crypto alogorithms仅使用强大的加密算法
                     | SCH_CRED_AUTO_CRED_VALIDATION  // automatically validate server certificate自动验证服务器证书
                     | SCH_CRED_NO_DEFAULT_CREDS;     // no client certificate authentication无客户端证书身份验证
        cred.grbitEnabledProtocols = SP_PROT_TLS1_2;  // allow only TLS v1.2仅允许 TLS v1.2

        if (AcquireCredentialsHandleW(NULL, UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &s->handle, NULL) != SEC_E_OK)
        {
            closesocket(s->sock);
            WSACleanup();
            return -1;
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

    CtxtHandle* context = NULL;
    int result = 0;
    for (;;)
    {
        SecBuffer inbuffers[2] = { 0 };
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = s->incoming;
        inbuffers[0].cbBuffer = s->received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        //这个缓冲器会由系统分配ISC_REQ_ALLOCATE_MEMORY
        SecBuffer outbuffers[1] = { 0 };
        outbuffers[0].BufferType = SECBUFFER_TOKEN;
        //输入输出上下文的缓冲器如何使用跟上下文语义有关
        SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS //Schannel 不得尝试自动为客户端提供凭据。
        | ISC_REQ_ALLOCATE_MEMORY 
        | ISC_REQ_CONFIDENTIALITY   //上下文可以使用 EncryptMessage (General) 和 DecryptMessage (General) 函数在传输过程中保护数据。如果生成的上下文用于 Guest 帐户，则 CONFIDENTIALITY 标志不起作用。
        | ISC_REQ_REPLAY_DETECT    //安全包检测重放的数据包，并通知调用者数据包是否被重放。此标志的使用意味着 INTEGRITY 标志指定的所有条件。
        | ISC_REQ_SEQUENCE_DETECT //必须允许上下文稍后通过消息支持功能检测数据包的无序传送。使用此标志意味着 INTEGRITY 标志指定的所有条件。
        | ISC_REQ_STREAM;           //必须使用流语义

        auto w_hostname = ::UTF8::GetWideChar(hostname);
        SECURITY_STATUS sec = InitializeSecurityContextW(
            &s->handle,
            context,
            context ? NULL : w_hostname.data(),
            flags,
            0,
            0,
            context ? &indesc : NULL,
            0,
            context ? NULL : &s->context,
            &outdesc,
            &flags,
            NULL);

        // after first call to InitializeSecurityContext context is available and should be reused for next calls
        //第一次调用 InitializeSecurityContext 后上下文可用，并且应该在下次调用中重用
        Print("context == s->context", context == &s->context, &s->context);
        context = &s->context;

     
            //安全包使用此值来指示消息中额外或未处理的字节数。
            //应该是把已经使用的删掉, 把未使用的挪到开头, 读取更多后重新调用
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

        if (sec == SEC_E_OK)
        {
            // tls handshake completed,  tls握手完成
            break;
        }
        else if (sec == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            // server asked for client certificate, not supported here服务器要求提供客户端证书，此处不支持
            result = -1;
            break;
        }
        else if (sec == SEC_I_CONTINUE_NEEDED)
        {
             Print("need send bytes to server");
            // need to send data to server需要发送数据到服务器
            char* buffer = static_cast<char*>(outbuffers[0].pvBuffer);
            int size = outbuffers[0].cbBuffer;

            while (size != 0)
            {
                int d = send(s->sock, buffer, size, 0);
                if (d <= 0)
                {
                    break;
                }
                size -= d;
                buffer += d;
            }
            FreeContextBuffer(outbuffers[0].pvBuffer);
            if (size != 0)
            {
                // failed to fully send data to server无法将数据完整发送到服务器
                result = -1;
                break;
            }
        }
        else if (sec != SEC_E_INCOMPLETE_MESSAGE)
        {
            // SEC_E_CERT_EXPIRED - certificate expired or revoked
            // SEC_E_WRONG_PRINCIPAL - bad hostname
            // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
            // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms

            // SEC_E_CERT_EXPIRED - 证书已过期或被撤销
            // SEC_E_WRONG_PRINCIPAL - 主机名错误
            // SEC_E_UNTRUSTED_ROOT - 无法验证 CA 链
            // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - 无法协商加密算法
            result = -1;
            break;
        }

        Print("read bytes from server");
        // read more data from server when possible尽可能从服务器读取更多数据
        if (s->received == sizeof(s->incoming))
        {
            // server is sending too much data instead of proper handshake?服务器发送了太多数据而不是正确的握手？
            result = -1;
            break;
        }
        auto m_v = sizeof(s->incoming) - s->received;

        int r = recv(s->sock, s->incoming + s->received, static_cast<int>( m_v), 0);
        if (r == 0)
        {
            // server disconnected socket服务器断开套接字
            return 0;
        }
        else if (r < 0)
        {
            // socket error
            result = -1;
            break;
        }
        s->received += r;
    }

    if (result != 0)
    {
        DeleteSecurityContext(context);
        FreeCredentialsHandle(&s->handle);
        closesocket(s->sock);
        WSACleanup();
        return result;
    }

    QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &s->sizes);
    return 0;
}

// disconnects socket & releases resources (call this even if tls_write/tls_read function return error)断开套接字并释放资源（即使 tls_write/tls_read 函数返回错误也调用此函数）
static void tls_disconnect(tls_socket* s)
{
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    ApplyControlToken(&s->context, &indesc);

    //这个缓冲器会由系统分配ISC_REQ_ALLOCATE_MEMORY
    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    if (InitializeSecurityContextA(&s->handle, &s->context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
    {
        char* buffer = static_cast<char*>(outbuffers[0].pvBuffer);
        int size = outbuffers[0].cbBuffer;
        while (size != 0)
        {
            int d = send(s->sock, buffer, size, 0);
            if (d <= 0)
            {
                // ignore any failures socket will be closed anyway
                break;
            }
            buffer += d;
            size -= d;
        }
        FreeContextBuffer(outbuffers[0].pvBuffer);
    }
    shutdown(s->sock, SD_BOTH);

    DeleteSecurityContext(&s->context);
    FreeCredentialsHandle(&s->handle);
    closesocket(s->sock);
    WSACleanup();
}

// returns 0 on success or negative value on error
static int tls_write(tls_socket* s, const void* buffer, int size)
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

        SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
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

        buffer = (char*)buffer + use;
        size -= use;
    }

    return 0;
}

// blocking read, waits & reads up to size bytes, returns amount of bytes received on success (<= size)
// returns 0 on disconnect or negative value on error
// 阻塞读取，等待并读取最多 size 个字节，成功时返回接收到的字节数 (<= size)
// 断开连接时返回 0，出错时返回负值
static int tls_read(tls_socket* s, void* buffer, int size)
{
    int result = 0;

    while (size != 0)
    {
        if (s->decrypted)
        {
            // if there is decrypted data available, then use it as much as possible如果有解密数据可用，则尽可能使用它
            int use = std::min(size, s->available);
            CopyMemory(buffer, s->decrypted, use);
            buffer = (char*)buffer + use;
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

                SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

                SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, NULL);
                if (sec == SEC_E_OK)
                {
                    assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                    assert(buffers[1].BufferType == SECBUFFER_DATA);
                    assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                    s->decrypted = static_cast<char*>( buffers[1].pvBuffer);
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
            int r = recv(s->sock, s->incoming + s->received, static_cast<int>( m_v), 0);
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

int main2()
{
    const char* hostname = "www.baidu.com";
    //const char* hostname = "www.google.com";
    //const char* hostname = "badssl.com";
    //const char* hostname = "expired.badssl.com";
    //const char* hostname = "wrong.host.badssl.com";
    //const char* hostname = "self-signed.badssl.com";
    //const char* hostname = "untrusted-root.badssl.com";
    const char* path = "/";

    tls_socket s;
    if (tls_connect(&s, hostname, 443) != 0)
    {
        printf("Error connecting to %s\n", hostname);
        return -1;
    }

    printf("Connected!\n");

    // send request
    char req[1024];
    int len = sprintf(req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname);
    if (tls_write(&s, req, len) != 0)
    {
        tls_disconnect(&s);
        return -1;
    }

    // write response to file
    FILE* f = fopen("response.txt", "wb");
    int received = 0;
    for (;;)
    {
        char buf[65536];
        int r = tls_read(&s, buf, sizeof(buf));
        if (r < 0)
        {
            printf("Error receiving data\n");
            break;
        }
        else if (r == 0)
        {
            printf("Socket disconnected\n");
            break;
        }
        else
        {
            fwrite(buf, 1, r, f);
            fflush(f);
            received += r;
        }
    }
    fclose(f);

    printf("Received %d bytes\n", received);

    tls_disconnect(&s);

    return 0;
}


int loop()
{
    const char* hostname = "www.ts1234.com";
    //const char* hostname = "www.google.com";
    //const char* hostname = "badssl.com";
    //const char* hostname = "expired.badssl.com";
    //const char* hostname = "wrong.host.badssl.com";
    //const char* hostname = "self-signed.badssl.com";
    //const char* hostname = "untrusted-root.badssl.com";
  
    tls_socket s;

    if(sock_connect(&s, hostname, 443)!= 0){
         printf("Error sock connecting to %s\n", hostname);
        return -1;
    }

    
    if (tls_connect(&s, hostname, 443) != 0)
    {
        printf("Error connecting to %s\n", hostname);
        return -1;
    }

    printf("Connected!\n");

    
    for (;;)
    {
        char buf[65536];
        int r = tls_read(&s, buf, sizeof(buf));
        if (r < 0)
        {
            printf("Error receiving data\n");
            break;
        }
        else if (r == 0)
        {
            printf("Socket disconnected\n");
            break;
        }
        else{

           
            if (tls_write(&s, buf, r) != 0)
            {
                printf("write error\n");
               break;
            }
        }


    }
   
    tls_disconnect(&s);

    return 0;
}


int main(){

    for (size_t i = 0; i < 5; i++)
    {
        loop();
    }
    
}