#define _WIN32_WINNT _WIN32_WINNT_WIN8
#include "leikaifeng.h"





int main2(int argc, char *argv[])
{

    std::wcout << argc << std::endl;
    for (int i = 0; i < argc; i++)
    {
        std::string v{argv[i]};
        int a = i;
        auto res = ::UTF8::GetWideChar(v);
        std::cout << ::UTF8::GetMultiByte(L"分割____") << std::endl;
        auto res2 = ::UTF8::GetMultiByte(res);
        std::cout << a << "  " << res2 << std::endl;
    }

    return 0;
}

void mytestpath(std::wstring& path){
    auto value = GetFileAttributesW(path.c_str());

		if (value == INVALID_FILE_ATTRIBUTES) {
			auto e = GetLastError();

			if (e == ERROR_FILE_NOT_FOUND) {
				Print("error");
			}
			else {
				Print("other error");
			}
		}
        else{
            Print("ok");
        }
}

int main(int argc, char *argv[])
{

    if (argc != 2)
    {
        Exit("argce != 2");

        return 0;
    }

    std::string path{argv[1]};

    auto wpath = ::UTF8::GetWideChar(path);
     std::cout  << ::UTF8::GetMultiByte(wpath)<< std::endl;
    auto v1 = ::UTF8::UrlEncode(wpath.data());
     std::cout  << ::UTF8::GetMultiByte(v1)<< std::endl;
    auto v2 = ::UTF8::UrlDecode(v1);
  
   
    std::cout  << ::UTF8::GetMultiByte(v2)<< std::endl;
}