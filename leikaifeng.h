#pragma once
#ifndef _LEIKAIFENG
#define _LEIKAIFENG

#include <iostream>
#include <string>
#include <functional>
#define WIN32_LEAN_AND_MEAN   
#include <windows.h>
#include <shlwapi.h>
//#define WC_ERR_INVALID_CHARS 0x0080
//#define URL_ESCAPE_AS_UTF8              0x00040000
//#define URL_UNESCAPE_AS_UTF8            URL_ESCAPE_AS_UTF8
void Print() {
	std::cout << std::endl;
}


template<typename T, typename ...TS>
void Print(T value, TS ...values) {
	std::cout << value << "   ";
	Print(values...);
}


std::string GetWin32ErrorMessage(DWORD errorCode) {

	char buffer[4096];

	auto length = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, errorCode, 0, buffer, sizeof(buffer), nullptr);

	return std::string{ buffer, length };
}

void Exit(const std::string& message, DWORD errorCode) {
	std::cout << message << "	" << GetWin32ErrorMessage(errorCode) << std::endl;
	exit(errorCode);
}

void Exit(const std::string& message) {
	Exit(message, GetLastError());
}


class Win32SysteamException : public std::exception {

	std::string m_message;
public:

	Win32SysteamException() : Win32SysteamException(GetLastError()) {

	}

	Win32SysteamException(DWORD errorCode) : m_message(GetWin32ErrorMessage(errorCode)) {
		
	}

	Win32SysteamException(const std::string& message) : Win32SysteamException(message, GetLastError()) {
		
	}

	Win32SysteamException(const std::string& message, DWORD errorCode) : m_message(message + "__:__" + GetWin32ErrorMessage(errorCode)) {

	}

	const char* what() const noexcept override {
		return m_message.c_str();
	}
};

class Delete_Base {
public:
	
	Delete_Base() {}

	Delete_Base(const Delete_Base&) = delete;
	
	Delete_Base(Delete_Base&&) = delete;

	Delete_Base& operator=(const Delete_Base&) = delete;
	
	Delete_Base& operator=(Delete_Base&&) = delete;
};

class UTF8 {

public:

	static std::wstring GetWideChar(const std::string& s){

		return GetWideChar(s, CP_ACP);
	}

	static std::string GetMultiByteFromUTF8(const std::string& s){

		auto wp = GetWideCharFromUTF8(s);

		return GetMultiByte(wp);
	}


	static std::wstring GetWideCharFromUTF8(const std::string& s){

		return GetWideChar(s, CP_UTF8);
	}

	static std::wstring GetWideChar(const std::string& s, int codePage){

		auto buffer = reinterpret_cast<const char*>(s.data());

		auto size = static_cast<int>(s.size());

		return GetWideChar(buffer, size, codePage);
	}



	static std::wstring GetWideChar(const std::u8string& s){
		auto buffer = reinterpret_cast<const char*>(s.data());

		auto size = static_cast<int>(s.size());

		return GetWideChar(buffer, size, CP_UTF8);
	}

	static std::wstring GetWideChar(const char* buffer, const int size, int codePage) {

		
		constexpr auto FLAG = MB_ERR_INVALID_CHARS;

		
		if (size < 0) {
			throw Win32SysteamException{ "size overflow" };
		}
		else {

			auto length = MultiByteToWideChar(codePage, FLAG, buffer, size, nullptr, 0);

			if (0 == length) {
				throw Win32SysteamException{};
			}
			else {

				std::wstring ret_s{};

				ret_s.resize(static_cast<size_t>(length));

				if (length != MultiByteToWideChar(codePage, FLAG, buffer, size, ret_s.data(), length)) {

					throw Win32SysteamException{};
				}
				else {

					return ret_s;
				}


			}

		}
	}

	static std::u8string GetUTF8(const std::wstring& s) {
		std::u8string ret_s{};

		auto buffer = s.data();

		auto size = static_cast<int>(s.size());


		GetMultiByte(buffer, size, CP_UTF8, [&](int n)-> char*{

			ret_s.resize(static_cast<size_t>(n));
			return  reinterpret_cast<char*>(ret_s.data());
		});

		return ret_s;
	}

	static std::string GetMultiByte(const std::wstring& s){
		std::string ret_s{};

		auto buffer = s.data();

		auto size = static_cast<int>(s.size());

		GetMultiByte(buffer, size, CP_ACP, [&](int n)-> char*{

			ret_s.resize(static_cast<size_t>(n));
			return ret_s.data();
		});

		return ret_s;
	}

	
	static void GetMultiByte(const wchar_t* buffer, int size, int codePage, std::function<char*(int)> func) {

		
		auto flag = codePage != CP_UTF8 ? 0: WC_ERR_INVALID_CHARS;

		if (size < 0) {

			throw Win32SysteamException{ "size overflow" };
		}
		else {

			auto length = WideCharToMultiByte(codePage, flag, buffer, size, nullptr, 0, nullptr, nullptr);

			if (0 == length) {
				throw Win32SysteamException{};
			}
			else {
				
				auto res_s = func(length);
				
				if (length != WideCharToMultiByte(codePage, flag, buffer, size, res_s, length, nullptr, nullptr))
				{
					throw Win32SysteamException{};
				}
				

			}
		}
	}


	static std::wstring UrlEncode(const wchar_t* s){

		wchar_t buff[2048];
		DWORD length = 2048;
		auto isok =::UrlEscapeW(s, buff, &length, URL_ESCAPE_AS_UTF8);

		if(isok == S_OK)
		{
			return std::wstring {buff, length};
		}
		else if(isok == E_POINTER){
			throw new Win32SysteamException{"url encode buff low size"};
		}
		else{
			throw new Win32SysteamException{};
		}
	}

	static std::wstring UrlDecode(std::wstring& s){
		
		
		wchar_t buff[2048];
		DWORD length = 2048;
		auto isok =::UrlUnescapeW(s.data(), buff, &length, URL_UNESCAPE_AS_UTF8);

		if(isok == S_OK)
		{
			return std::wstring {buff, length};
		}
		else if(isok == E_POINTER){
			throw new Win32SysteamException{"url encode buff low size"};
		}
		else{
			throw new Win32SysteamException{};
		}
	}

	static std::string GetStdOut(std::u8string& v){
		return ::UTF8::GetMultiByte(::UTF8::GetWideChar(v));
	}
};


#endif // !_LEIKAIFENG
