#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

HANDLE GetProcessHandle(DWORD pid) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL), handle = NULL;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);	
	
	if( Process32First(snap, &pe32) ){
		do{
			if( pid == pe32.th32ProcessID ){
				handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			}
		}while( Process32Next(snap, &pe32) );
	}
	
	return handle;
}

 bool levelup_privileges(HANDLE handle)
{
 HANDLE hProc = NULL;
 HANDLE hToken = NULL;
 LUID luid;
 TOKEN_PRIVILEGES tp;

 if (OpenProcessToken(handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))

 {

   if (LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid)) 

   {  

       tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

       tp.Privileges[0].Luid = luid;

       tp.PrivilegeCount = 1;  

       AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL); 

       return true; 

     } 

   }

 return false;

 }

int main() {
	DWORD pid;
	printf("[*] Process PID : ");
	scanf("%ld", &pid);
	
	HANDLE handle = GetProcessHandle(pid);
	
	printf("[*] Handle : 0x%x\n", handle);
	printf("[+] Elevating privileges...\n");
	if( levelup_privileges(handle) )
		printf("[+] Privilege Elevation Successfully!!!\n");
	else
		printf("[-] Privilege elevation failed...\n");
	return 0;
}
