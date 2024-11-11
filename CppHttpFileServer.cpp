#define _WIN32_WINNT _WIN32_WINNT_WIN8
#define NTDDI_VERSION NTDDI_WIN8
#include <limits>
#include <iostream>
#include <algorithm>
#include <string>
#include <array>
#include <vector>
#include <memory>
#include <queue>
#include <unordered_map>

#define WIN32_LEAN_AND_MEAN   
#include <windows.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
//#include <WinDNS.h>
#include <wininet.h>
#include <mstcpip.h>
#include "leikaifeng.h"
#define SIO_TCP_INFO _WSAIORW(IOC_VENDOR,39)

//#pragma comment(lib,"Ws2_32.lib")
//#pragma comment(lib,"Dnsapi.lib")
//#pragma comment(lib,"Wininet.lib")

template<typename TIn, typename TOut>
TOut Integer_cast(TIn v){
	
	if(v > std::numeric_limits<TOut>::max() || v< std::numeric_limits<TOut>::min()){
		throw std::overflow_error("Integer_cast Overflow");
	}
	else{
		return static_cast<TOut>(v);
	}
	
}


void WSAExit(const std::string& message) {
	Exit(message, WSAGetLastError());
}


class Win32SocketException : public Win32SysteamException {
public:
	using Win32SysteamException::Win32SysteamException;

	Win32SocketException(const std::string& message) : Win32SysteamException(message, WSAGetLastError()) {

	}
};

class SystemException : public std::exception {
std::string m_message;
public:

	SystemException(std::string message) : m_message(message) {

	}

	
	const char* what() const noexcept override {
		return m_message.c_str();
	}
};


class ArgumentException : public ::SystemException {


public:

	ArgumentException(std::string message) : SystemException(message) {

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

			throw Win32SocketException{};
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

			throw Win32SocketException{};
		}
		else {
			return functionAddress;
		}
	}

	static auto CreateIoCompletionPort() {
		auto handle = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);

		if (handle == nullptr) {
			Exit("create Io Completion Port error");

			throw Win32SysteamException{};
		}
		else {
			return handle;
		}
	}


	inline static HANDLE s_portHandle;

	inline static LPFN_ACCEPTEX s_acceptex;

	inline static LPFN_CONNECTEX s_connectex;

	inline static LPFN_TRANSMITPACKETS s_transmitpackets;

	inline static std::wstring s_folderPath;

	inline static int32_t s_on_run_sendfile_count;

	constexpr static int32_t MAX_ON_RUN_SENDFILE_COUNT=2;


	static void InitializationWSA() {
		WSADATA data;

		auto value = WSAStartup(MAKEWORD(2, 2), &data);

		if (value != 0) {
			Exit("Initialization error", value);
		}

		s_acceptex = Info::GetFunctionAddress<LPFN_ACCEPTEX>(WSAID_ACCEPTEX);

		s_connectex = Info::GetFunctionAddress<LPFN_CONNECTEX>(WSAID_CONNECTEX);

		s_transmitpackets = Info::GetFunctionAddress<LPFN_TRANSMITPACKETS>(WSAID_TRANSMITPACKETS);
	}

	static void InitializationPort() {
		s_portHandle = Info::CreateIoCompletionPort();
	}

	
public:
	
	
	static void InitializationSendFileCount(){
		s_on_run_sendfile_count=0;
	}

	static void AddSendFileCount(){
		s_on_run_sendfile_count+=1;
	}

	static void SubSendFileCount(){
		s_on_run_sendfile_count-=1;
	}

	static bool CanUseSendFile(){
		return s_on_run_sendfile_count < MAX_ON_RUN_SENDFILE_COUNT;
	}


	static void SetFolderPath(std::wstring& path){
		s_folderPath = path;
	}

	static const std::wstring& GetFolderPath(){
		return s_folderPath;
	}

	static auto& GetContentTypeMap() {

		static std::unordered_map<std::wstring, std::u8string> map{};

		return map;
	}

	static void InitializationMap() {

		decltype(auto) map = GetContentTypeMap();

		map.emplace(L".html", u8"text/html");
		map.emplace(L".mp4", u8"video/mp4");
		map.emplace(L".ts", u8"video/vnd.iptvforum.ttsmpeg2");
		map.emplace(L".jpg", u8"image/jpeg");
		map.emplace(L".jpeg", u8"image/jpeg");
	}



	static void Initialization() {

		Info::InitializationWSA();

		Info::InitializationPort();

		Info::InitializationMap();

		Info::InitializationSendFileCount();
	}

	static void AddToIoCompletionPort(HANDLE fileHandle) {
		auto handle = ::CreateIoCompletionPort(fileHandle, s_portHandle, static_cast<ULONG_PTR>(IOPortFlag::FiberSwitch), 0);
		if (handle == nullptr) {
			Exit("add Io Completion Port error");
		}
	}

	static void PostToIoCompletionPort(IOPortFlag flag, LPVOID value) {
		if (0 == ::PostQueuedCompletionStatus(s_portHandle, 0, static_cast<ULONG_PTR>(flag), static_cast<LPOVERLAPPED>(value))) {
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

	static auto GetTransmitPackets() {
		return s_transmitpackets;
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

	class IData {
	public:
		virtual void Call() = 0;
		virtual ~IData() {}
	};

	template<typename ...TS>
	class Data : public IData {
	
		FiberFuncType<TS...> m_func;
		PBack<TS...> m_value;

	public:
		Data(FiberFuncType<TS...> func, TS ...value) : m_func(func), m_value(value...) {

		}

		void Call() override {
			
			Used_PBack_Call(m_func, m_value);
		}
	};


	static auto& GetPQueue() {
		static std::deque<std::unique_ptr<IData>> queue{};

		return queue;
	}

	static auto& GetFiberQueue() {
		static std::deque<LPVOID> queue{};

		return queue;
	}

	constexpr static size_t FIBER_COUNT = 8;



	inline static LPVOID s_fiber;

	static void Fiber_Func() {
		
		decltype(auto) pqueue = Fiber::GetPQueue();


		auto p = std::move(pqueue.front());

		pqueue.pop_front();

		try {
			p->Call();
		}
		catch (Win32SocketException& e) {
			Print("socket throw");

			Exit(e.what());
		}
		catch (Win32SysteamException& e) {
			Print("system throw");
			Exit(e.what());
		}
		catch (...) {
			Exit("fiber throw error");
		}
		
	}

	
	static void WINAPI Fiber_Func(LPVOID) {

		//本意是让参数在Fiber::ForwardFunc<T>方法中析构,因为当前方法不会正常结束
		//但不清楚编译器的实现


		while (true)
		{
			Fiber::Fiber_Func();


			decltype(auto) queue = Fiber::GetFiberQueue();
			
			if (queue.size() > Fiber::FIBER_COUNT)
			{

				Info::PostToIoCompletionPort(IOPortFlag::FiberDelete, GetCurrentFiber());

			}
			else {
				queue.push_back(GetCurrentFiber());
			}

			Fiber::SwitchMain();
		}
		
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
		
		Fiber::GetPQueue().push_back(std::make_unique<Data<TS...>>(func, value...));

		decltype(auto) fiberqueue = Fiber::GetFiberQueue();

		LPVOID handle;

		if (fiberqueue.size() != 0) {

			handle = fiberqueue.front();

			fiberqueue.pop_front();
		}
		else {
			handle = ::CreateFiberEx(0, 0, FIBER_FLAG_FLOAT_SWITCH, Fiber::Fiber_Func, nullptr);

			if (handle == nullptr) {
				Exit("Create Fiber Error");
			}
		}
		
		Info::PostToIoCompletionPort(IOPortFlag::FiberCreate, handle);
	}

	static void PostMain(LPVOID fiber){

		::Info::PostToIoCompletionPort(IOPortFlag::FiberCreate, fiber);
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


class CreateReadOnlyFile : Delete_Base {

	HANDLE m_handle;

public:
	CreateReadOnlyFile(const std::wstring& path) {
		m_handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

		if (m_handle == INVALID_HANDLE_VALUE) {
			throw Win32SysteamException{};
		}
		Info::AddToIoCompletionPort(reinterpret_cast<HANDLE>(m_handle));
	}

	auto GetSize() {
		LARGE_INTEGER size;
		if (GetFileSizeEx(m_handle, &size)) {
			return size.QuadPart;
		}
		else {
			throw Win32SysteamException{};
		}
	}

	auto Read(char* buf, DWORD size, size_t offsetCount){

		OverLappedEx overlapped = {};

		{
			LARGE_INTEGER offset = {};
			offset.QuadPart=offsetCount;

			overlapped.Offset = offset.LowPart;
			overlapped.OffsetHigh = offset.HighPart;
		}
		
		
		overlapped.other = GetCurrentFiber();
		
		auto ret = ::ReadFile(m_handle, buf, size, nullptr, &overlapped);
		auto e = GetLastError();
		if(ret != 0 || e != ERROR_IO_PENDING){
			throw Win32SysteamException{"read file error:", e};
		}

		
		Fiber::SwitchMain();
	
		DWORD count;

		{

			auto ret = GetOverlappedResult(m_handle, &overlapped, &count, false);

			auto e = GetLastError();

			if (ret) {
				
				return static_cast<ULONG>(count);
			}
			else {

				throw Win32SocketException{ "Read file over error:", e };
			}
		}

		

	}

	auto GetHandle() {
		return m_handle;
	}

	~CreateReadOnlyFile()
	{
		CloseHandle(m_handle);
		Print("file close");
	}
};


typedef enum _TCPSTATE {
  TCPSTATE_CLOSED,
  TCPSTATE_LISTEN,
  TCPSTATE_SYN_SENT,
  TCPSTATE_SYN_RCVD,
  TCPSTATE_ESTABLISHED,
  TCPSTATE_FIN_WAIT_1,
  TCPSTATE_FIN_WAIT_2,
  TCPSTATE_CLOSE_WAIT,
  TCPSTATE_CLOSING,
  TCPSTATE_LAST_ACK,
  TCPSTATE_TIME_WAIT,
  TCPSTATE_MAX
} TCPSTATE;

typedef struct _TCP_INFO_v0 {
  TCPSTATE State;
  ULONG    Mss;
  ULONG64  ConnectionTimeMs;
  BOOLEAN  TimestampsEnabled;
  ULONG    RttUs;
  ULONG    MinRttUs;
  ULONG    BytesInFlight;
  ULONG    Cwnd;
  ULONG    SndWnd;
  ULONG    RcvWnd;
  ULONG    RcvBuf;
  ULONG64  BytesOut;
  ULONG64  BytesIn;
  ULONG    BytesReordered;
  ULONG    BytesRetrans;
  ULONG    FastRetrans;
  ULONG    DupAcksIn;
  ULONG    TimeoutEpisodes;
  UCHAR    SynRetrans;
} TCP_INFO_v0, *PTCP_INFO_v0;

class TcpSocket : Delete_Base {
	SOCKET m_handle;
	bool is_close;
	ULONG Read(char* buffer, ULONG size, DWORD flag) {
		this->OnClose_Throw();

		WSABUF buf = {};

		buf.buf = buffer;

		buf.len = size;

		OverLappedEx overlapped = {};

		overlapped.other = GetCurrentFiber();

		//此方法同步完成也会从io完成端口出来
		auto ret = WSARecv(m_handle, &buf, 1, nullptr, &flag, &overlapped, nullptr);
		auto e = WSAGetLastError();
		if (ret != 0 && e != WSA_IO_PENDING) {
			throw Win32SocketException{ static_cast<DWORD>(e) };
		}

		Fiber::SwitchMain();


		DWORD count;

		if (WSAGetOverlappedResult(m_handle, &overlapped, &count, false, &flag)) {

			return static_cast<ULONG>(count);
		}
		else {

			throw Win32SocketException{ "Read" };
		}

	}

public:

	TcpSocket() :is_close(false){
		m_handle = Info::CreateIPv4TcpSocket();


		Info::AddToIoCompletionPort(reinterpret_cast<HANDLE>(m_handle));
	}

	auto Write(char* buffer, DWORD len){

		WSABUF buf = {};

		buf.buf  = buffer;

		buf.len= len;

		return this->Write(&buf, 1);
	}


	ULONG Write(WSABUF* buf, DWORD bufCount) {
		this->OnClose_Throw();

		OverLappedEx overlapped = {};

		overlapped.other = GetCurrentFiber();
		
		auto ret = WSASend(m_handle, buf, bufCount, nullptr, 0, &overlapped, nullptr);
	
		auto e = WSAGetLastError();
		
		if (ret != 0 && e != WSA_IO_PENDING) {
			throw Win32SocketException{ static_cast<DWORD>(e) };
		}
		
		Fiber::SwitchMain();
	
		DWORD count;
		
		DWORD flag;
		
		if (WSAGetOverlappedResult(m_handle, &overlapped, &count, false, &flag)) {
			
			return static_cast<ULONG>(count);
		}
		else {

			throw Win32SocketException{ "Write send error:", static_cast<DWORD>(WSAGetLastError())};
		}
	}

	
	auto WriteFile(CreateReadOnlyFile& file, size_t offset, DWORD count){
		
		
		const size_t SIZEBUFF = 2097152;
		//const size_t SIZEBUFF = 8192;
		auto buf = std::make_unique<char[]>(SIZEBUFF);
		
		while (count > 0)
		{
			
			auto redCount = file.Read(buf.get(), SIZEBUFF, offset);

			if(redCount ==0){
				Print("file loop read 0");
				return;
			}
			DWORD canSendCount =0;
			if(count > redCount){
				canSendCount=redCount;
			}
			else{
				canSendCount =count;
			}

			auto n = this->Write(buf.get(), canSendCount);


			count-=n;

			offset+=n;
		}
		



	}


	void SendPack(LPTRANSMIT_PACKETS_ELEMENT packs, DWORD count) {
		this->OnClose_Throw();
		
		OverLappedEx overlapped = {};
		
		overlapped.other = GetCurrentFiber();
		// TF_USE_SYSTEM_THREAD  TF_USE_KERNEL_APC

		
		auto isok = Info::GetTransmitPackets()(m_handle, packs, count, 0, &overlapped, TF_USE_SYSTEM_THREAD);
	
		if (isok) {
			WSAExit("send pack syn over");
		}
		else {
			auto e = WSAGetLastError();

			if (e != WSA_IO_PENDING) {
				throw Win32SocketException{ static_cast<DWORD>(e) };
			}
			else {
				Print("TransmitPackets switch start");
				Info::AddSendFileCount();
				Fiber::SwitchMain();
				Info::SubSendFileCount();
				Print("TransmitPackets switch end");
				DWORD count;

				DWORD flag;

				if (WSAGetOverlappedResult(m_handle, &overlapped, &count, false, &flag)) {

					return;
				}
				else {

					throw Win32SocketException{ "SendPack",  static_cast<DWORD>(WSAGetLastError())};
				}

			}
		}
	}


	auto GetTcpInfo(TCP_INFO_v0& tcpInfo){
		this->OnClose_Throw();


		DWORD ver = 0;
		DWORD length =0;
		auto isok = ::WSAIoctl(
			m_handle, SIO_TCP_INFO,
			&ver, sizeof(ver),
			&tcpInfo, sizeof(tcpInfo),&length,
			nullptr, nullptr);

		if(isok == SOCKET_ERROR){
			throw Win32SocketException("tcp_info error", WSAGetLastError());
		}
		else{
			Print("get tcp_info ok");
		}
	}


	auto SetKeepAlive(){
		this->OnClose_Throw();


		tcp_keepalive v = {};

		v.onoff = 1;

		v.keepalivetime = 5000;

		v.keepaliveinterval = 1000;
		DWORD length =0;
		auto isok = ::WSAIoctl(
			m_handle,SIO_KEEPALIVE_VALS,
			&v, sizeof(v),
			nullptr,0,&length,
			nullptr, nullptr);


		if(isok == SOCKET_ERROR){
			throw Win32SocketException("tcp_keepalive error", WSAGetLastError());
		}
		else{
			Print("set tcp_keepalive ok");
		}
	}

	ULONG Read(char* buffer, ULONG size) {

		return this->Read(buffer, size, 0);
	}

	ULONG Peek(char* buffer, ULONG size) {

		return this->Read(buffer, size, MSG_PEEK);
	}

	auto GetHandle() const {
		
		return m_handle;
	}

	static void Bind(SOCKET handle, const IPEndPoint& endPoint) {

		auto address = endPoint.Get();

		if (SOCKET_ERROR == ::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address))) {
			
			throw Win32SocketException{ "bind" };
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

					throw Win32SocketException{ "Connect"};
				}
			}
		}
	}

	void ShutDown() {
		this->OnClose_Throw();
		::shutdown(m_handle, SD_BOTH);
	}

	void OnClose_Throw(){
		if(is_close){
			throw Win32SocketException{"socket is close can not use"};
		}
	}


	void Close(){

		if(is_close==false){

			is_close = true;

			auto isok = ::closesocket(m_handle);

			if(isok == SOCKET_ERROR){
				WSAExit("close socker error");
			}
			Print("socket close");
		}

		
	}

	~TcpSocket() {
		

		this->Close();
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

	/* auto SetSockOpt(){
		DWORD v = 1;
		auto isok = ::setsockopt(m_handle, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<char*>(&v), sizeof(v));

		if(isok == SOCKET_ERROR){
			throw Win32SocketException{ "set KEEPALIVE opt error", WSAGetLastError() };
		}
		else{
			Print("set KEEPALIVE opt ok");
		}
	}
 */

	void Listen(int backlog) {
		if (SOCKET_ERROR == ::listen(m_handle, backlog)) {
			
			throw Win32SocketException{ "listen" };
		}
	}

	std::shared_ptr<TcpSocket> Accept() {

		constexpr DWORD ADDRESSLENGTH = sizeof(sockaddr_in) + 16;
		
		constexpr DWORD BUFFERLENGTH = ADDRESSLENGTH * 2;

		auto handle = std::make_shared<TcpSocket>();


		char buffer[BUFFERLENGTH]{};
		
		DWORD length;
		
		OverLappedEx overlapped = {};

		overlapped.other = GetCurrentFiber();
		
		if (TRUE == Info::GetAcceptEx()(m_handle, handle->GetHandle(), buffer, 0, ADDRESSLENGTH, ADDRESSLENGTH, &length, &overlapped)) {
			WSAExit("accept syn over");

			throw Win32SocketException{};
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
					
					//TcpSocketListen::CopyOptions(m_handle, handle->GetHandle());

					return handle;

				}
				else {
					
					throw Win32SocketException{ "Accpet" };
				}	
			}	
		}
	}

	
	/* auto SetSockOpt(){

		DWORD v = 0;
		int length = sizeof(v);

		auto isok = ::getsockopt(handle->GetHandle(), SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<char *>(&v), &length);

		if (isok == SOCKET_ERROR)
		{
			throw Win32SocketException{"get SO_KEEPALIVE opt error", WSAGetLastError()};
		}
		else
		{
			Print("get SO_KEEPALIVE opt value:", v);
		}

		return handle;
	} */

	~TcpSocketListen() {
		
		::closesocket(m_handle);
	}
};


template<typename ...TS>
void Start(Fiber::FiberFuncType<TS...> func, TS ...value) {

	Info::Initialization();

	Fiber::Convert();


	Fiber::Create(func, value...);


	std::array<OVERLAPPED_ENTRY, 32> buffer{};
	
	DWORD count;

	while (true)
	{
		if (TRUE != GetQueuedCompletionStatusEx(Info::GetPortHandle(), buffer.data(), static_cast<ULONG>(buffer.size()), &count, INFINITE, true)) {
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


class Url {
	class Error {

	};

	uint32_t static GetNumber(uint32_t value) {

		constexpr uint32_t NUMBER_MAP[]{ 0,1,2,3,4,5,6,7,8,9 };

		constexpr uint32_t NUMBER_FIRST = u8'0';

		constexpr uint32_t NUMBER_LAST = u8'9';

		constexpr uint32_t _MAP[]{ 10,11,12,13,14,15 };

		constexpr uint32_t _FIRST = u8'A';

		constexpr uint32_t _LAST = u8'F';

		if (value >= NUMBER_FIRST && value <= NUMBER_LAST) {

			return NUMBER_MAP[value - NUMBER_FIRST];
		}
		else if (value >= _FIRST && value <= _LAST) {

			return _MAP[value - _FIRST];
		}
		else {
			throw Url::Error{};
		}
	}

	char8_t static GetCharFrom(const char8_t* buffer) {

		auto value_1 = static_cast<uint32_t>(*buffer);

		auto value_2 = static_cast<uint32_t>(*(buffer + 1));

		return static_cast<char8_t>((Url::GetNumber(value_1) * 16) + Url::GetNumber(value_2));
	}

	static std::u8string UrlDecode(const std::u8string_view& s) {

		constexpr size_t SIZE = 2;

		std::u8string ret{};

		ret.reserve(s.size());

		auto buffer = s.data();

		auto size = s.size();

		size_t index = 0;

		while (index < size)
		{
			if (buffer[index] == u8'%') {

				index++;

				if ((index + SIZE) <= size) {

					ret += Url::GetCharFrom(&buffer[index]);

					index += SIZE;
				}
				else {
					throw Url::Error{};
				}
			}
			else {
				ret += buffer[index];

				index++;
			}
		}


		return (ret);
	}

public:
	static bool UrlDecode(const std::u8string_view& s, std::u8string& out_s) {
		try {
			out_s = Url::UrlDecode(s);
			return true;
		}
		catch (Url::Error&) {
			return false;
		}
	}
};



class Number {
public:
	static bool Parse(const std::u8string_view& s, size_t& out_value) {

		constexpr size_t FIRST = u8'0';

		constexpr size_t LAST = u8'9';

		size_t value = 0;

		for (auto c : s)
		{
			size_t n = c;

			n -= FIRST;

			if (n <= LAST) {
				value *= 10;
				value += n;
			}
			else {
				return false;
			}
		}

		out_value = value;

		return true;
	}


	template<typename T>
	static void ToString(std::u8string& s, T value) requires(std::is_same_v<T, UINT16> || std::is_same_v<T, UINT32> || std::is_same_v<T, UINT64>) {

		constexpr char8_t MAP[] = u8"0123456789";

		constexpr T SIZE = 10;

		constexpr T ZEOR = 0;

		auto first = s.size();

		do
		{
			auto n = value % SIZE;

			value /= SIZE;

			s += (MAP[n]);

		} while (value != 0);

		auto last = s.size() - 1;

		while (first < last)
		{
			auto v = s[last];

			s[last] = s[first];

			s[first] = v;

			first++;
			last--;
		}
	}


};






class HttpReqest : Delete_Base {
	
public:
	class FormatException : public std::exception {

	std::string m_message;
public:

	FormatException(std::string message) :m_message(message){

	}


	const char* what() const noexcept override {
		return m_message.c_str();
	}
};

private:
	constexpr static size_t BUFFER_SIZE = 4096;


	std::u8string m_buffer;
	
	std::u8string m_path;
	
	std::unordered_map<std::u8string_view, std::u8string_view> m_dic;
	
	static std::u8string Path(std::u8string_view s) {

		auto first = s.find(u8' ');

		auto last = s.rfind(u8' ');

		if (first != decltype(s)::npos && first != last) {

			s.remove_suffix(s.size() - last);

			s.remove_prefix(first + 1);

			std::u8string ret{};

			if (Url::UrlDecode(s, ret)) {
				return ret;
			}
			else {
				throw HttpReqest::FormatException{"url decode error"};
			}
		}
		else {
			throw HttpReqest::FormatException{"find path error"};
		}
	}

	static bool Find(std::u8string_view& s, std::u8string_view& out_s) {
		
		auto index =  s.find(u8"\r\n");

		if (index == std::remove_reference_t<decltype(s)>::npos) {
		
			return false;
		}
		else if (index == 0) {
			
			s.remove_prefix(index + 2);

			return false;
		}
		else {

			

			out_s = std::u8string_view{ s.data(), index };

			s.remove_prefix(index + 2);

			return true;
		}
	}

	static void AddDic(std::unordered_map<std::u8string_view, std::u8string_view>& dic, std::u8string_view s) {
		
		auto index = s.find(u8": ");

		if (index == decltype(s)::npos) {
			throw HttpReqest::FormatException{"find header : error"};
		}
		else {

			auto value_first = s.data() + (index + 2);

			auto value_size = s.size() - (index + 2);

			dic.emplace(std::u8string_view{ s.data(), index }, std::u8string_view{ value_first, value_size });
		}
	}


	static bool ParseRange(std::u8string_view s, std::pair<size_t, std::pair<bool, size_t>>& out_value) {

		constexpr char8_t HEAD[] = u8"bytes=";

		constexpr size_t HEAD_SIZE = sizeof(HEAD) - 1;

		constexpr char8_t B = u8'-';

		constexpr size_t B_SIZE = 1;

		auto npos = decltype(s)::npos;

		auto index = s.find(HEAD);

		if (index == npos) {
			return false;
		}
		else {

			s.remove_prefix(index + HEAD_SIZE);

			index = s.find(B);

			if (index == npos) {
				return false;
			}
			else {

				size_t start_range;
				if (!Number::Parse(s.substr(0, index), start_range)) {
					return false;
				}
				else {
					s.remove_prefix(index + B_SIZE);

					size_t end_range;
					if (s.size() == 0 || !Number::Parse(s, end_range)) {
						out_value = std::make_pair(start_range, std::make_pair(false, 0));

						return true;
					}
					else {
						out_value = std::make_pair(start_range, std::make_pair(true, end_range));


						return true;
					}
				}
			}
		}
	}


public:
	
	HttpReqest() : m_buffer(), m_path(), m_dic() {

		m_buffer.resize(HttpReqest::BUFFER_SIZE);
	}

	auto& GetDic() const {
		return m_dic;
	}

	auto& GetPath() const {
		return m_path;
	}

	std::u8string GetValue(const std::u8string& key){
		
		decltype(auto) dic = this->GetDic();

		auto item = dic.find(key);

		
		if (item == dic.end()) {
			return u8"";
		}
		else {
			return std::u8string{ item->second};
		}
	}

	bool GetRange(std::pair<size_t, std::pair<bool, size_t>>& out_value) {
		
		std::u8string key{ u8"Range" };


		decltype(auto) dic = this->GetDic();

		auto item = dic.find(key);

		
		if (item == dic.end()) {
			return false;
		}
		else {
			return HttpReqest::ParseRange(item->second, out_value);
		}
	}

	static std::unique_ptr<HttpReqest> Read(std::shared_ptr<TcpSocket> socket) {
		

		auto ret = std::make_unique<HttpReqest>();

		auto& buffer = ret->m_buffer;
		
		auto& path = ret->m_path;

		auto& dic = ret->m_dic;

		auto length = socket->Peek(reinterpret_cast<char*>(buffer.data()), static_cast<ULONG>(buffer.size()));
		
		std::u8string_view view{ buffer.data(),static_cast<size_t>(length) };
		//Print(::UTF8::GetMultiByte(::UTF8::GetWideChar(std::u8string{ view})));
		std::u8string_view value{};
		
		if (!HttpReqest::Find(view, value)) {
		
			throw HttpReqest::FormatException{"find header line error length:"};
		}
		else {

			path = HttpReqest::Path(value);
			
			while (HttpReqest::Find(view, value))
			{
				HttpReqest::AddDic(dic, value);
			}

			std::array<char, HttpReqest::BUFFER_SIZE> buf{};

			socket->Read(buf.data(), static_cast<ULONG>(length - view.size()));

			return ret;
		}
	}
};


class HttpResponse : Delete_Base {

	std::u8string m_header;

protected:
	virtual void Send_(std::shared_ptr<TcpSocket> handle, char* header, DWORD size) = 0;
public:

	HttpResponse(size_t statusCode) : m_header() {
		
		m_header.reserve(1024);

		m_header.append(u8"HTTP/1.1 ");

		Number::ToString(m_header, statusCode);

		if(statusCode == 404){
			m_header.append(u8" Not Found\r\n");
		}
		else{
			m_header.append(u8" OK\r\n");
		}

		m_header.append(u8"Connection: keep-alive\r\n");
		m_header.append(u8"Keep-Alive: timeout=20, max=1000\r\n");
	}

	void SetContentRange(size_t start, size_t end, size_t size) {
		
		m_header.append(u8"Content-Range: bytes ");
		
		Number::ToString(m_header, start);
		
		m_header.push_back(u8'-');
		
		Number::ToString(m_header, end);

		m_header.push_back(u8'/');

		Number::ToString(m_header, size);

		m_header.append(u8"\r\n");
	}

	void SetContentLength(size_t size) {
		m_header.append(u8"Content-Length: ");

		Number::ToString(m_header, size);

		m_header.append(u8"\r\n");
	}

	void Set(const std::u8string& key, const std::u8string& value) {
		m_header.append(key).append(u8": ").append(value).append(u8"\r\n");
	}

	
	void SetContentType(const std::wstring& s) {

		decltype(auto) map = Info::GetContentTypeMap();

		auto item = map.find(s);

		m_header.append(u8"Content-Type: ");

		if (item == map.end()) {
			m_header.append(u8"application/octet-stream");
		}
		else {

			m_header.append(item->second);

		}

		m_header.append(u8"\r\n");
	}
	



	void Send(std::shared_ptr<TcpSocket> handle) {
	
		m_header.append(u8"\r\n");

		auto buf = reinterpret_cast<char*>(m_header.data());

		auto size = ::Integer_cast<size_t, DWORD>(m_header.size());

		this->Send_(handle, buf, size);
	
	}

	virtual ~HttpResponse()
	{

	}
};

class HttpResponseStrContent : public HttpResponse {

	std::u8string m_str;


protected:
	void Send_(std::shared_ptr<TcpSocket> handle, char* header, DWORD size) override {
		

		WSABUF bufArray[2]{};

		bufArray[0].buf = header;
		bufArray[0].len = size;

		bufArray[1].buf =  reinterpret_cast<char*>(m_str.data());
		bufArray[1].len = ::Integer_cast<size_t, DWORD>(m_str.size());

		handle->Write(bufArray, 2);
	}
public:

	HttpResponseStrContent(size_t statusCode, const std::wstring& s) : HttpResponse(statusCode), m_str(UTF8::GetUTF8(s)) {

		this->Set(u8"Content-Type", u8"text/html; charset=utf-8");
		this->SetContentLength(m_str.size());

	}
};




class HttpResponse404 : public HttpResponse{


public:

	HttpResponse404() : HttpResponse(404){
		this->SetContentLength(0);

	}

protected:
	void Send_(std::shared_ptr<TcpSocket> handle, char* header, DWORD size)  override {
		
		WSABUF buf ={};

		buf.buf = header;

		buf.len = size;

		handle->Write(&buf, 1);
	}

};



class HttpResponseFileContent : public HttpResponse {

	constexpr static size_t BAO_LIU_ZI_JIE_COUNT = 1024*1024*8;

	constexpr static size_t MAX_SEND_LENGTH = std::numeric_limits<int32_t>::max()-BAO_LIU_ZI_JIE_COUNT;
	//constexpr static size_t MAX_SEND_LENGTH = 5112660345;

	constexpr static size_t IF_USE_SEND_OR_SENDFILE_COUNT = 104857600;

	std::unique_ptr<CreateReadOnlyFile> m_file;


	size_t m_fileSize;

	size_t m_start_range;

	size_t m_end_range;

	size_t m_length;
	
	static std::wstring GetName(const std::wstring& path) {
		auto index = path.rfind(L'.');

		if (index == std::remove_reference_t< decltype(path)>::npos) {
			return std::wstring{};
		}
		else {
			return path.substr(index, path.size() - index);
		}
	}

	void Set() {
		this->SetContentLength(m_length);

		this->SetContentRange(m_start_range, m_end_range, m_fileSize);
	}

protected:
	void Send_(std::shared_ptr<TcpSocket> handle, char* header, DWORD size) override {

		auto length = ::Integer_cast<size_t, DWORD>(m_length);

		if (length > IF_USE_SEND_OR_SENDFILE_COUNT && Info::CanUseSendFile())
		{
			Print("use send file");
			TRANSMIT_PACKETS_ELEMENT pack[2]{};

			auto &v = pack[0];

			v.dwElFlags = TP_ELEMENT_MEMORY;

			v.pBuffer = header;
			v.cLength = size;

			auto &item = pack[1];

			item.dwElFlags = TP_ELEMENT_FILE;

			item.hFile = m_file->GetHandle();

			item.nFileOffset.QuadPart = m_start_range;

			item.cLength = length;

			handle->SendPack(pack, 2);
		}
		else
		{
			Print("use send buffer");
			handle->Write(header, size);

			handle->WriteFile(*m_file, m_start_range, length);

		}
	}


public:

	HttpResponseFileContent(size_t statusCode, const std::wstring& path)
		: HttpResponse(statusCode), m_file(std::make_unique<CreateReadOnlyFile>(path)) {
		
		m_fileSize = m_file->GetSize();

		this->SetContentType(HttpResponseFileContent::GetName(path));

	}

	
	void SetRange(size_t start, size_t end) {

		if(end >= m_fileSize){
			throw new ArgumentException{"request set renge end > fileSize"};
		}

		if(start> end){
			throw new ArgumentException{"request set renge start > end"};
		}

		auto length = (end - start) + 1;

		auto v = 0;

		if(length > MAX_SEND_LENGTH){
			auto v = length - MAX_SEND_LENGTH;
			end -= v;

			length -=v;
		}

	


		//Print("start:", start, "end:", end, "length:", length, "v:",v, "fileSize:", m_fileSize);
		m_start_range = start;

		m_end_range = end;
		
		
		

		m_length = length;

		this->Set();
	}

	void SetRange(size_t start) {

		this->SetRange(start, m_fileSize - 1);

	}

	void SetRange() {

		this->SetRange(0, m_fileSize - 1);
	}
};


class EnumFileFolder : Delete_Base {


public:

	class Data {
		WIN32_FIND_DATAW m_data;

	public:
		Data() : m_data() {

		}

		auto* Get() {
			return &m_data;
		}

		bool IsFolder() {
			return 0 != (m_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
		}

		const wchar_t* Path() const {
			return  m_data.cFileName;
		}

		size_t Size() {

			size_t n = MAXDWORD;

			n += 1;

			size_t high = m_data.nFileSizeHigh;

			size_t low = m_data.nFileSizeLow;

			return (high * n) + low;
		}
	};

private:
	EnumFileFolder::Data m_data;

	HANDLE m_handle;

	bool m_isFirst;

	static bool IsThrow(DWORD error) {
		if (error == ERROR_FILE_NOT_FOUND || error == ERROR_NO_MORE_FILES) {
			return false;
		}
		else {
			throw Win32SysteamException{ error };
		}

	}

public:

	EnumFileFolder(const std::wstring& path) {

		m_handle = ::FindFirstFileW(path.c_str(), m_data.Get());

		if (INVALID_HANDLE_VALUE == m_handle) {

			EnumFileFolder::IsThrow(GetLastError());

			m_isFirst = false;
		}
		else {
			m_isFirst = true;
		}
	}

	bool Get(EnumFileFolder::Data& out_data) {

		if (m_isFirst) {

			m_isFirst = false;

			out_data = m_data;

			return true;
		}
		else {

			if (FindNextFileW(m_handle, out_data.Get())) {
				return true;
			}
			else {
				return EnumFileFolder::IsThrow(GetLastError());
			}
		}
	}

	~EnumFileFolder()
	{
		::FindClose(m_handle);
	}

};



class File {
public:

	class IsFileIsFolder {
		bool m_isFolder;
		bool m_isFile;

	public:
		IsFileIsFolder(bool isFolder, bool isFile) : m_isFolder(isFolder), m_isFile(isFile) {}

		bool IsFile() {
			return m_isFile;
		}

		bool IsFolder() {
			return m_isFolder;
		}
	};


	static IsFileIsFolder IsFileOrFolder(const std::wstring& path) {
		auto value = GetFileAttributesW(path.c_str());

		if (value == INVALID_FILE_ATTRIBUTES) {
			auto e = GetLastError();

			if (e == ERROR_FILE_NOT_FOUND) {
				return IsFileIsFolder{ false, false };
			}
			else {
				throw Win32SysteamException{ e };
			}
		}
		else {
			if (0 == (value & FILE_ATTRIBUTE_DIRECTORY)) {
				return IsFileIsFolder{ false, true };
			}
			else {
				return IsFileIsFolder{ true, false };
			}
		}
	}

};



class Html {
public:

	template<bool ISFOLDER>
	static void Add(std::wstring& s, const wchar_t* path) {
		
		s.append(L"<li><a href=\"");
		std::wstring encodeUrl = ::UTF8::UrlEncode(path);
		s.append(encodeUrl.data());

		if constexpr (ISFOLDER) {

			s.append(L"/\">");

		}
		else {

			s.append(L"\">");

		}

		s.append(path);

		s.append(L"</a></li>");
	}

	static std::wstring GetHtml(const std::wstring& path) {

		std::wstring file{};

		std::wstring folder{};

		EnumFileFolder eff{ path };

		EnumFileFolder::Data data{};

		while (eff.Get(data))
		{
			
			if (data.IsFolder()) {

				Add<true>(folder, data.Path());

			}
			else {
				Add<false>(file, data.Path());
			}
		}

		std::wstring ret{};
		
		ret.append(L"<!DOCTYPE html><html lang=\"zh-cn\" xmlns=\"http://www.w3.org/1999/xhtml\"><head><meta charset=\"utf-8\" /><title>文件和文件</title></head><body><div><div><ul>");
		
		ret.append(folder);
		
		ret.append(L"</ul></div><div><ul>");
		
		ret.append(file);
		
		ret.append(L"</ul></div></div></body></html>");

		return ret;
	}

};

template<typename T>
class MyEventQuery{

private:
	std::deque<T> m_query;

	HANDLE m_wait_fiblr_handle;
	bool is_set_handle;
	bool is_close;

	auto PostMain(){
		if(is_set_handle){
			
			is_set_handle=false;
			
			
			::Fiber::PostMain(m_wait_fiblr_handle);

			
		}
		
	}

	auto OnClose_Throw(){
		if(is_close){
			throw ArgumentException{"MyEventQuery is close can not use"};
		}
	}

public:

	MyEventQuery(): m_wait_fiblr_handle(nullptr), is_set_handle(false), is_close(false){

	}

	auto Size(){
		this->OnClose_Throw();

		return m_query.size();
	}

	auto Wait(){
		this->OnClose_Throw();

		if(m_query.size() != 0){
			auto v = std::move(m_query.front());
			m_query.pop_front();
			return v;
		}

		if(is_set_handle){
			throw ArgumentException{"MyEventQuery handle is not post main"};
		}

		m_wait_fiblr_handle = ::GetCurrentFiber();
		is_set_handle = true;

		::Fiber::SwitchMain();

		if(is_close){
			throw ArgumentException{"MyEventQuery main switch call return but class is close"};
		}

		if(m_query.size() != 0){
			auto v = std::move(m_query.front());
			m_query.pop_front();
			return v;
		}

		throw ArgumentException{"MyEventQuery can not has item"};
	}


	auto Set(T v){
		this->OnClose_Throw();

		m_query.push_back(std::move(v));

		this->PostMain();
	}

	void Close(){
		is_close= true;

		this->PostMain();
	}

	~MyEventQuery(){


		this->Close();

		Print("close MyEventQuery");
	}

};

void Response(std::shared_ptr<TcpSocket> handle, std::unique_ptr<HttpReqest>& request, std::wstring& folderPath){
	
	auto path = UTF8::GetWideChar(request->GetPath());
	path =  folderPath + path;
	
	auto isff = File::IsFileOrFolder(path);

	if (isff.IsFile()) {

		
		
		std::pair<size_t, std::pair<bool, size_t>> range;

		if (request->GetRange(range)) {
			HttpResponseFileContent response{ 206, path };

			if (range.second.first) {
				response.SetRange(range.first, range.second.second);
			}
			else {
				response.SetRange(range.first);
			}

			response.Send(handle);

		}
		else {

			HttpResponseFileContent response{ 200, path };

			response.SetRange();

			response.Send(handle);

		}


	}
	else if (isff.IsFolder()) {
		
		if (path.ends_with(L'/')) {
			path += L'*';
		}
		else {
			path += L"/*";
		}
	
		HttpResponseStrContent response{ 200, Html::GetHtml(path) };

		response.Send(handle);
	}
	else {
		Print("path error   ", ::UTF8::GetMultiByte(path));
		
		HttpResponse404 response{};


		response.Send(handle);
	}
}


void RequestLoop(std::shared_ptr<TcpSocket> handle, std::wstring folderPath){

	
	try {
		int n = 0;

		while (true)
		{

			auto request = HttpReqest::Read(handle);
			
			Response(handle, request, folderPath);
			n++;

			Print(n, "re use link");
		}
	}
	catch (Win32SysteamException& e) {
		Print(e.what()); 
	}
	catch (HttpReqest::FormatException& e) {
		Print("request format error:", e.what());
	}
	catch (::SystemException& e) {
		Print("SystemException :", e.what());
	}
}


void Accpet() {
	
	TcpSocketListen lis{};
	
	lis.Bind(IPEndPoint(0, 0, 0, 0, 80));

	lis.Listen(16);

	while (true)
	{
		auto handle = lis.Accept();

		//handle->SetKeepAlive();
		Print("new connect");
		Fiber::Create(RequestLoop, handle, Info::GetFolderPath());
	}

}

int main(int argc, char *argv[]) {
	if(argc != 2){
		Exit("argce != 2");

		return 0;
	}

	std::string path{argv[1]};

	auto wpath = ::UTF8::GetWideChar(path);
	std::replace(wpath.begin(), wpath.end(), L'\\', L'/');
	
	Info::SetFolderPath(wpath);
	Start(Accpet);
}
