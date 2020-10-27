#include <iostream>
#include <algorithm>
#include <string>
#include <array>
#include <vector>
#include <memory>

#define WIN32_LEAN_AND_MEAN   
#include <Windows.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <WinDNS.h>

#include "../../../include/leikaifeng.h"


#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Dnsapi.lib")



void WSAExit(const std::string& message) {
	Exit(message, WSAGetLastError());
}


class Win32SocketException : public Win32SysteamException {
public:
	using Win32SysteamException::Win32SysteamException;

	Win32SocketException() : Win32SysteamException(WSAGetLastError()) {

	}
};


template<typename ...TS>
class PBack {

};


template<typename T, typename ...TS>
class PBack<T, TS...> {
	T m_value;
	PBack<TS...> m_back;
public:

	PBack(T value, TS ...values)
		: m_value(value),
		m_back(values...) {

	}

	auto& GetValue() {
		return m_value;
	}

	auto& GetPBack() {
		return m_back;
	}


};

template <typename TF, typename T, typename ...TS, typename ...TPS>
constexpr void _Used_PBack_Call(TF tf, PBack<T, TS...> value, TPS ...tps) {
	if constexpr (sizeof...(TS) == 0) {
		tf(tps..., value.GetValue());
	}
	else {
		_Used_PBack_Call(tf, value.GetPBack(), tps..., value.GetValue());
	}
}

template <typename TF, typename ...TS>
constexpr void Used_PBack_Call(TF tf, PBack<TS...> value) requires(std::is_invocable_v<TF, TS...>) {
	if constexpr (sizeof...(TS) == 0) {
		tf();
	}
	else {
		
		if constexpr (sizeof...(TS) == 1) {
			tf(value.GetValue());
		}
		else {
			_Used_PBack_Call(tf, value.GetPBack(), value.GetValue());
		}
	}
}


enum class IOPortFlag : ULONG_PTR {
	FiberSwitch,
	FiberCreate,
	FiberDelete
};


class Info {

public:
	static auto CreateIPv4TcpSocket() {
		auto handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (handle == INVALID_SOCKET) {
			WSAExit("create socket error");
		}
		else {
			return handle;
		}
	}

private:
	template<typename TF>
	static auto GetFunctionAddress(GUID guid) {


		auto handle = Info::CreateIPv4TcpSocket();

		TF functionAddress = nullptr;

		DWORD outSize = 0;

		auto result = ::WSAIoctl(
			handle, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&guid, sizeof(guid),
			&functionAddress, sizeof(functionAddress),
			&outSize, nullptr, nullptr);

		closesocket(handle);


		if (result == SOCKET_ERROR) {
			WSAExit("get function address error");
		}
		else {
			return functionAddress;
		}
	}

	static auto CreateIoCompletionPort() {
		auto handle = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);

		if (handle == nullptr) {
			Exit("create Io Completion Port error");
		}
		else {
			return handle;
		}
	}


	inline static HANDLE s_portHandle;

	inline static LPFN_ACCEPTEX s_acceptex;

	inline static LPFN_CONNECTEX s_connectex;





	static void InitializationWSA() {
		WSADATA data;

		auto value = WSAStartup(MAKEWORD(2, 2), &data);

		if (value != 0) {
			Exit("Initialization error", value);
		}

		s_acceptex = Info::GetFunctionAddress<LPFN_ACCEPTEX>(WSAID_ACCEPTEX);

		s_connectex = Info::GetFunctionAddress<LPFN_CONNECTEX>(WSAID_CONNECTEX);
	}

	static void InitializationPort() {
		s_portHandle = Info::CreateIoCompletionPort();
	}


public:

	static void Initialization() {

		Info::InitializationWSA();

		Info::InitializationPort();
	}

	static void AddToIoCompletionPort(HANDLE fileHandle) {
		auto handle = ::CreateIoCompletionPort(fileHandle, s_portHandle, static_cast<ULONG_PTR>(IOPortFlag::FiberSwitch), 0);
		if (handle == nullptr) {
			Exit("add Io Completion Port error");
		}
	}

	static void PostToIoCompletionPort(IOPortFlag flag, LPVOID fiber) {
		if (0 == ::PostQueuedCompletionStatus(s_portHandle, 0, static_cast<ULONG_PTR>(flag), static_cast<LPOVERLAPPED>(fiber))) {
			Exit("post io Completion Port error");
		}
	}

	static auto GetPortHandle() {
		return s_portHandle;
	}

	static auto GetAcceptEx() {
		return s_acceptex;
	}

	static auto GetConnectEx() {
		return s_connectex;
	}
};



class IPEndPoint {


	sockaddr_in m_value;

public:
	IPEndPoint(UCHAR ip1, UCHAR ip2, UCHAR ip3, UCHAR ip4, USHORT port) {
		sockaddr_in value = {};

		value.sin_family = AF_INET;

		value.sin_addr.S_un.S_un_b.s_b1 = ip1;
		value.sin_addr.S_un.S_un_b.s_b2 = ip2;
		value.sin_addr.S_un.S_un_b.s_b3 = ip3;
		value.sin_addr.S_un.S_un_b.s_b4 = ip4;

		value.sin_port = htons(port);

		m_value = value;
	}

	IPEndPoint(DWORD ip, USHORT port) {
		sockaddr_in value = {};

		value.sin_family = AF_INET;

		value.sin_addr.S_un.S_addr = ip;

		value.sin_port = htons(port);

		m_value = value;
	}

	auto Get() const {
		return m_value;
	}
};


class Fiber {
	
public:
	template<typename ...TS>
	using FiberFuncType = std::decay_t<void(TS...)>;

private:

	template<typename ...TS>
	class Data {
	
		FiberFuncType<TS...> m_func;
		PBack<TS...> m_value;

	public:
		Data(FiberFuncType<TS...> func, TS ...value) : m_func(func), m_value(value...) {

		}

		auto& GetFunc() {
			return m_func;
		}

		auto& GetValue() {
			return m_value;
		}
	};


	inline static LPVOID s_fiber;

	template <typename ...TS>
	static void ForwardFunc(LPVOID p) {
		
		std::unique_ptr<Data<TS...>> data{ reinterpret_cast<Data<TS...>*>(p) };


		try {
			Used_PBack_Call(data->GetFunc(), data->GetValue());
		}
		catch (...) {
			Exit("Fiber trhow error");
		}
	}

	template<typename ...TS>
	static void WINAPI Fiber_Func(LPVOID p) {

		//本意是让参数在Fiber::ForwardFunc<T>方法中析构,因为当前方法不会正常结束
		//但不清楚编译器的实现
		Fiber::ForwardFunc<TS...>(p);

		Info::PostToIoCompletionPort(IOPortFlag::FiberDelete, GetCurrentFiber());

		Fiber::SwitchMain();
	}

public:
	static void Convert() {
		auto handle = ::ConvertThreadToFiberEx(nullptr, FIBER_FLAG_FLOAT_SWITCH);

		if (handle == nullptr) {
			Exit("Convert To Fiber Error");
		}
		else {
			s_fiber = handle;
		}
	}

	template <typename ...TS>
	static void Create(FiberFuncType<TS...> func, TS ...value) {
		//这个地方如果参数是万能引用会导致包装参数的类型字段也是引用
		auto data = new Data<TS...>{ func, value... };

		auto handle = ::CreateFiberEx(0, 0, FIBER_FLAG_FLOAT_SWITCH, Fiber::Fiber_Func<TS...>, data);

		if (handle == nullptr) {
			Exit("Create Fiber Error");
		}
		else {

			Info::PostToIoCompletionPort(IOPortFlag::FiberCreate, handle);

		}
	}

	static void SwitchMain() {
		Fiber::Switch(s_fiber);
	}

	static void Switch(LPVOID fiber) {
		if (fiber == GetCurrentFiber()) {
			Exit("Switch Fiber error");
		}

		::SwitchToFiber(fiber);
	}

	static void Delete(LPVOID fiber) {
		if (fiber == s_fiber) {
			Exit("delete fiber error");

		}

		::DeleteFiber(fiber);
	}
};

class OverLappedEx : public OVERLAPPED {
public:
	LPVOID other;
};

class TcpSocket : Delete_Base {
	SOCKET m_handle;

public:

	TcpSocket() {
		m_handle = Info::CreateIPv4TcpSocket();


		Info::AddToIoCompletionPort(reinterpret_cast<HANDLE>(m_handle));
	}

	ULONG Write(char* buffer, ULONG size) {
		WSABUF buf = {};

		buf.buf = buffer;
		
		buf.len = size;

		OverLappedEx overlapped = {};

		overlapped.other = GetCurrentFiber();

		WSASend(m_handle, &buf, 1, nullptr, 0, &overlapped, nullptr);

		Fiber::SwitchMain();

		DWORD count;
		DWORD flag;
		if (WSAGetOverlappedResult(m_handle, &overlapped, &count, false, &flag)) {

			return count;
		}
		else {

			throw Win32SocketException{ };
		}
	}

	ULONG Read(char* buffer, ULONG size) {

		WSABUF buf = {};

		buf.buf = buffer;

		buf.len = size;

		OverLappedEx overlapped = {};

		overlapped.other = GetCurrentFiber();

		DWORD flag = 0;
		
		//此方法同步完成也会从io完成端口出来
		WSARecv(m_handle, &buf, 1, nullptr, &flag, &overlapped, nullptr);
		
		Fiber::SwitchMain();

		
		DWORD count;
		
		if (WSAGetOverlappedResult(m_handle, &overlapped, &count, false, &flag)) {

			return count;
		}
		else {

			throw Win32SocketException{ };
		}

	}

	auto GetHandle() const {
		return m_handle;
	}

	static void Bind(SOCKET handle, const IPEndPoint& endPoint) {

		auto address = endPoint.Get();

		if (SOCKET_ERROR == ::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address))) {
			
			throw Win32SocketException{};
		}
	}

	static std::shared_ptr<TcpSocket> Connect(const IPEndPoint& endPoint) {
		
		auto handle = std::make_shared<TcpSocket>();

		TcpSocket::Bind(handle->GetHandle(), IPEndPoint{ 0,0,0,0,0 });

		auto address = endPoint.Get();

		OverLappedEx overlapped = {};

		overlapped.other = GetCurrentFiber();
		
		if (TRUE == Info::GetConnectEx()(handle->GetHandle(), reinterpret_cast<sockaddr*>(&address), sizeof(address), nullptr, 0, nullptr, &overlapped)) {
			WSAExit("connect 同步完成");
		}
		else {
			auto value = WSAGetLastError();

			if (value != ERROR_IO_PENDING) {
				throw Win32SocketException{ static_cast<DWORD>(value) };
			}
			else {
				Fiber::SwitchMain();

				DWORD count;
				DWORD flag;
				if (WSAGetOverlappedResult(handle->GetHandle(), &overlapped, &count, false, &flag)) {

					return handle;
				}
				else {

					throw Win32SocketException{ };
				}
			}
		}
	}

	void ShutDown() {

		::shutdown(m_handle, SD_BOTH);
	}

	~TcpSocket() {
		Print("close run");
		::closesocket(m_handle);
	}
};



class TcpSocketListen : Delete_Base {
	SOCKET m_handle;

	void CopyOptions(SOCKET source, SOCKET des) {
		
		if (SOCKET_ERROR == setsockopt(des, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, reinterpret_cast<char*>(&source), sizeof(source)))
		{
			WSAExit("Copy Options error");
		}
	}


public:

	TcpSocketListen() {

		m_handle = Info::CreateIPv4TcpSocket();

		Info::AddToIoCompletionPort(reinterpret_cast<HANDLE>(m_handle));
	}

	void Bind(const IPEndPoint& endPoint) {

		TcpSocket::Bind(m_handle, endPoint);
	}

	void Listen(int backlog) {
		if (SOCKET_ERROR == ::listen(m_handle, backlog)) {
			
			throw Win32SocketException{};
		}
	}

	std::shared_ptr<TcpSocket> Accept() {

		constexpr DWORD ADDRESSLENGTH = sizeof(sockaddr_in) + 16;
		constexpr DWORD BUFFERLENGTH = ADDRESSLENGTH * 2;

		auto handle = std::make_shared<TcpSocket>();


		char buffer[BUFFERLENGTH];
		
		DWORD length;
		
		OverLappedEx overlapped = {};

		overlapped.other = GetCurrentFiber();
		
		if (TRUE == Info::GetAcceptEx()(m_handle, handle->GetHandle(), buffer, 0, ADDRESSLENGTH, ADDRESSLENGTH, &length, &overlapped)) {
			WSAExit("accept 同步完成");
		}
		else {
			auto value = WSAGetLastError();

			if (value != ERROR_IO_PENDING) {
				throw Win32SocketException{ static_cast<DWORD>(value) };
			}
			else {
				Fiber::SwitchMain();
				
				DWORD count;
				DWORD flag;
				if (WSAGetOverlappedResult(m_handle, &overlapped, &count, false, &flag)) {
					
					TcpSocketListen::CopyOptions(m_handle, handle->GetHandle());

					return handle;
				}
				else {
					
					throw Win32SocketException{ };
				}	
			}	
		}
	}

	


	~TcpSocketListen() {
		
		::closesocket(m_handle);
	}
};


template<typename ...TS>
void Start(Fiber::FiberFuncType<TS...> func, TS ...value) {

	Info::Initialization();

	Fiber::Convert();


	Fiber::Create(func, value...);


	std::array<OVERLAPPED_ENTRY, 32> buffer;
	DWORD count;

	while (true)
	{
		if (TRUE != GetQueuedCompletionStatusEx(Info::GetPortHandle(), buffer.data(), static_cast<ULONG>(buffer.size()), &count, INFINITE, false)) {
			Exit("get io error");
		}
		else {
			for (DWORD i = 0; i < count; i++)
			{
				auto& item = buffer[i];
				
				auto flag = static_cast<IOPortFlag>(item.lpCompletionKey);

				if (flag == IOPortFlag::FiberSwitch) {
					
					Fiber::Switch(static_cast<OverLappedEx*>(item.lpOverlapped)->other);

				}
				else if(flag == IOPortFlag::FiberCreate) {
				
					Fiber::Switch(item.lpOverlapped);
				}
				else {
					Fiber::Delete(item.lpOverlapped);
				}
			}
		}
	}
}



std::vector<DWORD> GetIPv4AddressFromHostName(std::u8string name) {

	PDNS_RECORD next;

	auto error = DnsQuery_UTF8(reinterpret_cast<char*>(name.data()), DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr, &next, nullptr);

	if (error == 123) {

		return std::vector<DWORD>{};

	}
	else if (error != 0) {

		Exit("DnsQuery Error");

	}
	else {
		auto dns_free = [](auto p) {DnsRecordListFree(p, DnsFreeRecordList); };

		std::unique_ptr<DNS_RECORD, decltype(dns_free)> data{ next, dns_free };
		std::vector<DWORD> list{};


		for (auto item = next; item != nullptr; item = item->pNext) {

			if (item->wType == DNS_TYPE_A) {

				list.push_back(item->Data.A.IpAddress);
			}

		}


		return list;
	}
}



IPEndPoint GetIPEndPoint(const std::u8string& host) {
	auto list = GetIPv4AddressFromHostName(host);

	if (list.size() == 0) {
		Exit("dns error");
	}
	else {
		return IPEndPoint{ list[0], 443 };
	}
}



//last也是有效char
bool from_chars(const char* first, const char* last, int32_t& value)
{
	constexpr char map[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	int32_t memory = 0;
	auto end = last + 1;
	for (auto p = first; p != end; p++)
	{
		uint32_t i = *p;

		i -= 48;

		if (i < sizeof(map))
		{
			memory *= 10;

			memory += map[i];
		}
		else
		{
			return false;
		}
	}

	value = memory;
	return true;
}

template <typename T>
const char* Find(const char* first, const char* last, T func)
{
	auto end = last + 1;
	for (auto p = first; p != end; p++)
	{
		if (func(*p))
		{
			return p;
		}
	}

	return nullptr;
}

bool GetHostAndPortFrom(const char* first, const char* last, std::pair<std::string, uint16_t>& value)
{

	auto func = [](char c) { return c == ' '; };

	first = Find(first, last, func);

	if (first != nullptr)
	{
		first++;

		last = Find(first, last, func);

		if (last != nullptr)
		{
			last--;

			auto index = Find(first, last, [](char c) { return c == ':'; });

			if (index != nullptr)
			{

				int32_t port;

				if (from_chars(index + 1, last, port))
				{
					size_t length = index - first;
					std::string host{ first, length };

					value = std::make_pair(host, static_cast<uint16_t>(port));

					return true;
				}
			}
		}
	}

	return false;
}



void CopyFunc(std::shared_ptr<TcpSocket> left, std::shared_ptr<TcpSocket> right) {

	try {
		std::array<char, 4096> buffer;

		while (true)
		{
			auto length = left->Read(buffer.data(), buffer.size());

			if (length == 0) {
				return;
			}
			else {
				right->Write(buffer.data(), length);
			}
		}

	}
	catch (Win32SocketException& e) {
		
		left->ShutDown();
		right->ShutDown();

		Print("copy error", e.what());
	}
}

void AcceptFunc(std::shared_ptr<TcpSocket> sock) {

	
	std::array<char, 1024> buffer;

	auto length = sock->Read(buffer.data(), buffer.size());

	if (length == 0) {
		return;
	}
	else {
		std::pair<std::string, USHORT> value;
		if (GetHostAndPortFrom(buffer.data(), buffer.data() + length, value) ){
			

			char8_t buffer[] = u8"HTTP/1.1 200 OK \r\n\r\n";

			sock->Write(reinterpret_cast<char*>(buffer), 20);

			try {

				auto conn = TcpSocket::Connect(GetIPEndPoint(std::u8string{ reinterpret_cast<char8_t*>(value.first.data()), value.first.size() }));

				Fiber::Create(CopyFunc, sock, conn);
				Fiber::Create(CopyFunc, conn, sock);
			}
			catch (Win32SocketException& e) {
				
				Print("connect error", e.what());
			}


		}


	}
}

void ListenFunc() {
	
	TcpSocketListen listen{};

	listen.Bind(IPEndPoint(127, 0, 0, 1, 443));

	listen.Listen(8);

	try {
		while (true)
		{
			auto handle = listen.Accept();
			
			Fiber::Create(AcceptFunc, handle);
		}
	}
	catch (Win32SocketException& e) {
		Print("accet error", e.what());
	}

	
}


int main() {


	Start(ListenFunc);

}