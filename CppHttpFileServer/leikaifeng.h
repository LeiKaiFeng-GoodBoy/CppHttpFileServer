#pragma once
#ifndef _LEIKAIFENG
#define _LEIKAIFENG

#include <iostream>
#include <string>
#define WIN32_LEAN_AND_MEAN   
#include <windows.h>
//#define WC_ERR_INVALID_CHARS 0x0080
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

	Win32SysteamException(const std::string& message) : m_message(message) {

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
	static std::wstring GetWideChar(const std::u8string& s) {

		constexpr auto CODEPAGE = CP_UTF8;

		constexpr auto FLAG = MB_ERR_INVALID_CHARS;

		auto buffer = reinterpret_cast<const char*>(s.data());

		auto size = static_cast<int>(s.size());

		if (size < 0) {
			throw Win32SysteamException{ "size overflow" };
		}
		else {

			auto length = MultiByteToWideChar(CODEPAGE, FLAG, buffer, size, nullptr, 0);

			if (0 == length) {
				throw Win32SysteamException{};
			}
			else {

				std::wstring ret_s{};

				ret_s.resize(static_cast<size_t>(length));

				if (length != MultiByteToWideChar(CODEPAGE, FLAG, buffer, size, ret_s.data(), length)) {

					throw Win32SysteamException{};
				}
				else {

					return ret_s;
				}


			}

		}
	}

	static std::u8string GetUTF8(const std::wstring& s) {

		constexpr auto CODEPAGE = CP_UTF8;

		constexpr auto FLAG = WC_ERR_INVALID_CHARS;

		auto buffer = s.data();

		auto size = static_cast<int>(s.size());

		if (size < 0) {

			throw Win32SysteamException{ "size overflow" };
		}
		else {

			auto length = WideCharToMultiByte(CODEPAGE, FLAG, buffer, size, nullptr, 0, nullptr, nullptr);

			if (0 == length) {
				throw Win32SysteamException{};
			}
			else {
				std::u8string ret_s{};

				ret_s.resize(static_cast<size_t>(length));


				if (length != WideCharToMultiByte(CODEPAGE, FLAG, buffer, size, reinterpret_cast<char*>(ret_s.data()), length, nullptr, nullptr))
				{
					throw Win32SysteamException{};
				}
				else {
					return ret_s;
				}

			}
		}
	}

	static std::string GetMultiByte(const std::wstring& s) {

		constexpr auto CODEPAGE = CP_ACP;

		constexpr auto FLAG = 0;

		auto buffer = s.data();

		auto size = static_cast<int>(s.size());

		if (size < 0) {

			throw Win32SysteamException{ "size overflow" };
		}
		else {

			auto length = WideCharToMultiByte(CODEPAGE, FLAG, buffer, size, nullptr, 0, nullptr, nullptr);

			if (0 == length) {
				throw Win32SysteamException{};
			}
			else {
				std::string ret_s{};

				ret_s.resize(static_cast<size_t>(length));


				if (length != WideCharToMultiByte(CODEPAGE, FLAG, buffer, size, ret_s.data(), length, nullptr, nullptr))
				{
					throw Win32SysteamException{};
				}
				else {
					return ret_s;
				}

			}
		}
	}
};


#endif // !_LEIKAIFENG
