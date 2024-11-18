#define _WIN32_WINNT _WIN32_WINNT_WIN8
#define NTDDI_VERSION NTDDI_WIN8

#include "myio.h"


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
	
		EnumFileFolder eff{path};
		EnumFileFolder::Data data{};

		std::wstring html_string = Html::GetHtml([&eff, &data](Html::Data& v){
			
			auto res = eff.Get(data);
			if(res){
				v.IsFolder = data.IsFolder();

				v.Path = data.Path();

				return true;
			}
			else{
				return false;
			}
			
		});

		HttpResponseStrContent response{ 200,  html_string};

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
