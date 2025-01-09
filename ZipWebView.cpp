
#include <bitarchivereader.hpp>
#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <exception>
#include <memory>
#include "include/leikaifeng.h"
#include "myio.h"


class MyZipReader2 : Delete_Base{

private:

    class MyNeedData{
        public:
            uint32_t index;
            size_t size;
            std::string path;
            std::string exname;
        MyNeedData(uint32_t index,
            size_t size,
            std::string path,
            std::string exname):
            index(index), size(size),
            path(std::move(path)),
            exname(std::move(exname)){

            }
    };

    constexpr static size_t MAXINDEX =  std::numeric_limits<size_t>::max(); 

    bit7z::Bit7zLibrary m_lib;
    std::wstring m_path;
    std::unique_ptr<bit7z::BitArchiveReader> m_arc;

    std::unordered_map<uint32_t, MyNeedData> m_data; 
    std::shared_ptr<std::vector<byte>> m_fileData;
    size_t m_upIndex;
public:
    //初始化的顺序很重要
    MyZipReader2(const std::wstring& dllPath):
     m_lib(bit7z::to_tstring(dllPath)),
     m_path(),
     m_arc(),
     m_data(),
     m_fileData(),
     m_upIndex(MAXINDEX)
    {
       m_fileData = std::make_shared<std::vector<bit7z::byte_t>>();
    }

    const bit7z::BitInFormat &detectRAR(const std::string &in_file)
    {

        try
        {
            bit7z::BitArchiveReader info(m_lib, in_file, bit7z::BitFormat::Rar);
            // if BitArchiveInfo constructor did not throw an exception, the archive is RAR (< 5.0)!
            return bit7z::BitFormat::Rar;
        }
        catch (const bit7z::BitException &)
        {
            /* the archive is not a RAR and if it is not even a RAR5,
               the following line will throw an exception (not catched)! */
            bit7z::BitArchiveReader info(m_lib, in_file, bit7z::BitFormat::Rar5);
            return bit7z::BitFormat::Rar5;
        }
    }

    void OpenFile(const std::wstring& path, const bit7z::BitInFormat& format){
        auto fv = &format;
        auto u8path =  bit7z::to_tstring(path);
        if((*fv) == bit7z::BitFormat::Rar){
             fv = &detectRAR(u8path);
        }


        if(path == m_path){
            return;
        }

        m_path= path;

        m_arc = std::make_unique<bit7z::BitArchiveReader>(m_lib, 
        u8path, 
        *fv);
        
        m_data.clear();
        m_fileData = std::make_shared<std::vector<bit7z::byte_t>>();
        try{
            auto arc_items = m_arc->items();
            for (auto &item : arc_items)
            {
                if(item.isDir()){

                }
                else{
                    
                    auto index = item.index();

                    auto path = item.path();

                    auto size = item.size();

                    auto exname = item.extension();

                    m_data.emplace(index, MyNeedData{index, size, 
                        path,
                        exname,
                    });
                }

            }
        }
        catch (const bit7z::BitException &ex)
        {

            Exit(ex.what());
        }

        

    }

    bool GetBytes(uint32_t index, std::shared_ptr<std::vector<bit7z::byte_t>>& fileData, std::string& exname){
        
        auto v = m_data.find(index);

        if(v == m_data.end()){

            return false;
        }

        exname = v->second.exname;

        if(m_upIndex == index){
            fileData = m_fileData;

            return true;
        }

        m_upIndex=index;

        m_fileData = std::make_shared<std::vector<bit7z::byte_t>>();
        try{
            
            m_arc->extractTo(*m_fileData, ::Integer_cast<size_t, uint32_t>(index));
            
            fileData= m_fileData;
            return true;
        }
        catch (const bit7z::BitException &ex)
        {

            Print("extractTo error", ex.what());
        }

       
        return false;
    }

    void GetFileNameAndIndex(std::function<void(uint32_t, const std::string&)> func){

        for (const auto& item: m_data)
        {
           func(item.second.index, item.second.path);
        }
        
    }

};


bool GetBitInFormat(const std::wstring& filePath, bit7z::BitInFormat const * * v){
     std::filesystem::path path{filePath};

    if(!path.has_extension()){
        return false;
    }
    auto ex = path.extension();
    
    if(ex ==L".zip"){
        *v = &bit7z::BitFormat::Zip;
        return true;
    }
    else if(ex == L".rar"){
        *v = &bit7z::BitFormat::Rar;
        return true;
    }
    else if(ex == L".7z"){
        *v = &bit7z::BitFormat::SevenZip;
        return true;
    }
    else{

        return false;
    }
    
}

void Response2(std::shared_ptr<TcpSocket> handle, std::unique_ptr<HttpReqest>& request, std::shared_ptr<MyZipReader2> reader, std::wstring& filePath){
	
    const bit7z::BitInFormat* v;

    if(!GetBitInFormat(filePath, &v)){
        HttpResponse404 res404{};
        res404.Send(handle);

        return;
    }


    reader->OpenFile(filePath, *v);

    auto isjsonstr = request->GetQueryValue(u8"json");

    if(isjsonstr == u8"1"){
        boost::json::array vs{};

        reader->GetFileNameAndIndex([&vs](uint32_t index, const std::string& name){

            
            boost::json::object kv{};
            kv.emplace("index",index);
            
            kv.emplace("path", name);
            
            vs.emplace_back(kv);

        });
        auto cont = boost::json::serialize(vs);
        HttpResponseStrContent strcont{200, UTF8::GetUTF8(UTF8::GetWideCharFromUTF8(cont)), HttpResponseStrContent::JSON_TYPE};


        strcont.Send(handle);

        return;
    }


    auto indexstring = request->GetQueryValue(u8"Index");


    if(indexstring == u8""){
         Html html {};

        reader->GetFileNameAndIndex([&html](uint32_t index, const std::string& name){

            std::u8string path{};
            Number::ToString(path, index);
            auto wpath = UTF8::GetWideChar(path);
            wpath.insert(0, L"?Index=");
            html.Add(false, wpath, UTF8::GetWideCharFromUTF8( name));

        });


        HttpResponseStrContent strcont{200, html.GetHtml()};


        strcont.Send(handle);

        return;
    }

    size_t index;
    std::u8string view{indexstring};
    if(!Number::Parse(view, index)){

        HttpResponse404 res404{};
        res404.Send(handle);

        return;
    }


    Print(index);
    std::string exname{};
    std::shared_ptr<std::vector<bit7z::byte_t>> buf{};
    if(!reader->GetBytes(static_cast<uint32_t>(index), buf, exname)){
        HttpResponse404 res404{};
        res404.Send(handle);

        return;
    }
    exname.insert(0, ".");

   
    HttpResponseBufferContent resbuf{UTF8::GetWideCharFromUTF8(exname), buf};
    resbuf.SetRangeFromRequest(*request);
    resbuf.Send(handle);
}



void Response(std::shared_ptr<TcpSocket> handle, std::unique_ptr<HttpReqest>& request, std::shared_ptr<MyZipReader2> reader, std::wstring& folderPath, std::wstring& appPath){
	
	auto path = UTF8::GetWideChar(request->GetPath());

    
    if(path.starts_with(L"/app")){
        path = appPath +path.substr(4);

        if(File::IsFileOrFolder(path).IsFile()){
            
		    HttpResponseFileContent response{ path };
            
            response.SetRangeFromRequest(*request);

            response.Send(handle);

        }
        else{

            HttpResponse404 res404{};
            res404.Send(handle);

        }



        return;
    }
    

	path =  folderPath + path;
	
	auto isff = File::IsFileOrFolder(path);

	if (isff.IsFile()) {

        Response2(handle, request, reader, path);
		

	}
	else if (isff.IsFolder()) {
		
		if (path.ends_with(L'/')) {
			path += L'*';
		}
		else {
			path += L"/*";
		}
	
		EnumFileFolder eff{path};
		EnumFileFolder::Data data{};
		Html html{};
		while (eff.Get(data))
		{
			std::wstring name{data.Path()};

			html.Add(data.IsFolder(), name, name);
		}
		


		HttpResponseStrContent response{ 200,  html.GetHtml()};

		response.Send(handle);
	}
	else {
		Print("path error   ", ::UTF8::GetMultiByte(path));
		
		HttpResponse404 response{};


		response.Send(handle);
	}
}



void RequestLoop(std::shared_ptr<TcpSocket> handle, std::shared_ptr<MyZipReader2> reader, std::wstring path, std::wstring apppath){

	
	try {
		int n = 0;

		while (true)
		{

			auto request = HttpReqest::Read(handle);
			
			Response(handle, request, reader, path, apppath);
			n++;

			Print(n, "re use link");
		}
	}
    catch (const ArgumentException& e) {
		Print("request loop ArgumentException:", e.what());

	}
	catch (const Win32SysteamException& e) {
		Print("request loop Win32SysteamException", e.what()); 
	}
	catch (const HttpReqest::FormatException& e) {
		Print("request loop request format error:", e.what());
	}
	catch (const SystemException& e) {
		Print("request loop SystemException :", e.what());

    }
    catch (const std::exception& e) {
		Print("request loop std::exception :", e.what());
	}
    catch(...){
       
        Exit("request loop throw other error :");
    }
}


int main(int argc, char *argv[]) {
	if(argc != 3){
		Exit("argce != 3,  args  app path, file path");

		return 0;
	}

	
    std::string apppath{argv[1]};

    auto wapppath = ::UTF8::GetWideChar(apppath);
    std::replace(wapppath.begin(), wapppath.end(), L'\\', L'/');

    std::string path{argv[2]};

	auto wpath = ::UTF8::GetWideChar(path);
    std::replace(wpath.begin(), wpath.end(), L'\\', L'/');

	std::wstring dllpath{L"7z.dll"};

    auto reader = std::make_shared<MyZipReader2>(dllpath);


	Info::Initialization();

    auto f = new Fiber{};

    f->Start([](std::shared_ptr<MyZipReader2> p, std::wstring wpath, std::wstring wapppath){

        TcpSocketListen lis{};
        lis.Bind(IPEndPoint{0,0,0,0, 80});
        lis.Listen(6);

        while (true)
        {
            auto connect = lis.Accept();

            Fiber::GetThis().Create(RequestLoop, connect, p, wpath, wapppath);
        }
        


    }, reader, wpath, wapppath);
}
