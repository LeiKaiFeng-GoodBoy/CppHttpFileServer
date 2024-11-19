#define _WIN32_WINNT _WIN32_WINNT_WIN8
#define NTDDI_VERSION NTDDI_WIN8

#include <bitarchivereader.hpp>
#include "myio.h"


class MyZipReader2 : Delete_Base{

private:
    bit7z::Bit7zLibrary m_lib;
    bit7z::BitArchiveReader m_arc;
public:
    //初始化的顺序很重要
    MyZipReader2(const std::wstring& filePath, const std::wstring& dllPath):
     m_lib(bit7z::to_tstring(dllPath)),
     m_arc(m_lib, bit7z::to_tstring(filePath), bit7z::BitFormat::Zip)
    {
       
    }


    auto& Get(){
        return m_arc;
    }

    auto GetBytes(size_t index){
        
        try{
            std::vector<bit7z::byte_t> out{};
            m_arc.extractTo(out, ::Integer_cast<size_t, uint32_t>(index));
            return std::move(out);
        }
        catch (const bit7z::BitException &ex)
        {

            Print(ex.what());
        }

        return std::vector<bit7z::byte_t>{};
        
    }

    void GetFileNameAndIndex(std::function<void(uint32_t, std::wstring&)> func){

        try{
            auto arc_items = m_arc.items();
            for (auto &item : arc_items)
            {
                if(item.isDir()){

                }
                else{
                    
                    auto index = item.index();

                    auto path = item.path();

                    auto wpath = UTF8::GetWideCharFromUTF8(path);

                    func(index, wpath);
                }

            }
        }
        catch (const bit7z::BitException &ex)
        {

            Print(ex.what());
        }

        
    }

};



void Response(std::shared_ptr<TcpSocket> handle, std::unique_ptr<HttpReqest>& request, std::shared_ptr<MyZipReader2> reader){
	
	auto path = request->GetPath();
    Print(UTF8::GetStdOut(path));
   
    if(path == u8"/"){
        Html html {};

        reader->GetFileNameAndIndex([&html](uint32_t index, std::wstring& name){

            std::u8string path{};
            Number::ToString(path, index);
            auto wpath = UTF8::GetWideChar(path);

            html.Add(false, wpath, name);

        });


        HttpResponseStrContent strcont{200, html.GetHtml()};


        strcont.Send(handle);

        return;
    }
    
    std::u8string_view view {path};
    
    if(view.size() < 2){
        HttpResponse404 res404{};
        res404.Send(handle);

        return;
    }
    
    size_t index;
	
    if(!Number::Parse(view.substr(1, view.size()-1), index)){

        HttpResponse404 res404{};
        res404.Send(handle);

        return;
    }


    Print(index);

    auto buf = reader->GetBytes(index);

    
    HttpResponseBufferContent resbuf{200,L".png", std::move(buf)};

    resbuf.Send(handle);
}


void RequestLoop(std::shared_ptr<TcpSocket> handle, std::shared_ptr<MyZipReader2> reader){

	
	try {
		int n = 0;

		while (true)
		{

			auto request = HttpReqest::Read(handle);
			
			Response(handle, request, reader);
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


int main(int argc, char *argv[]) {
	if(argc != 2){
		Exit("argce != 2");

		return 0;
	}

	std::string path{argv[1]};

	auto wpath = ::UTF8::GetWideChar(path);
	std::wstring dllpath{L"7z.dll"};

    auto reader = std::make_shared<MyZipReader2>(wpath, dllpath);



	Info::Initialization();

    auto f = new Fiber{};

    f->Start([](std::shared_ptr<MyZipReader2> p){

        TcpSocketListen lis{};
        lis.Bind(IPEndPoint{0,0,0,0, 80});
        lis.Listen(6);

        while (true)
        {
            auto connect = lis.Accept();

            Fiber::GetThis().Create(RequestLoop, connect, p);
        }
        


    }, reader);
}
