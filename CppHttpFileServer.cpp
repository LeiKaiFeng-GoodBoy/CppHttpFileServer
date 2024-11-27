#define _WIN32_WINNT _WIN32_WINNT_WIN8
#define NTDDI_VERSION NTDDI_WIN8

#include "myio.h"


void Response(std::shared_ptr<TcpSocket> handle, std::unique_ptr<HttpReqest>& request, std::wstring& folderPath){
	
	auto path = UTF8::GetWideChar(request->GetPath());
	path =  folderPath + path;
	
	auto isff = File::IsFileOrFolder(path);

	if (isff.IsFile()) {

		HttpResponseFileContent response{path };
		
		response.SetRangeFromRequest(*request);

		response.Send(handle);


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

void NewAcceptAction(SOCKET s, std::wstring path){
	auto handle = std::make_shared<TcpSocket>(s);

	Fiber::GetThis().Create(RequestLoop, handle, path);

}

int main(int argc, char *argv[]) {
	if(argc != 2){
		Exit("argce != 2");

		return 0;
	}

	std::string path{argv[1]};

	auto wpath = ::UTF8::GetWideChar(path);
	std::replace(wpath.begin(), wpath.end(), L'\\', L'/');
	Info::Initialization();


	TcpSocketListenSync lis{};
	
	lis.Bind(IPEndPoint(0, 0, 0, 0, 80));

	lis.Listen(16);

	std::vector<Fiber*> f_v{};

	std::vector<std::thread> t_v{};

	size_t count = 3;

	for (size_t i = 0; i < count; i++)
	{
		auto f = new Fiber{};

		std::thread t{[](auto fiber){
			fiber->Start([](){});
			
		}, f};

		f_v.push_back(f);

		t_v.push_back(std::move(t));
	}
	

	size_t n=0;
	while (true)
	{
		n++;

		auto s = lis.Accept();

		auto index = n% count;

		f_v[index]->Create_ThreadSafe(NewAcceptAction, s, wpath);
	}
	
	
}
