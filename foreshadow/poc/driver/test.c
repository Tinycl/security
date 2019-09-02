#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>

#define ALLOCPAGE (0x100)
#define DEVNAME "/dev/poc"

struct POC_ARG
{
	unsigned long  va;
	unsigned long  pa;
	unsigned long  va_pte_va;
	unsigned long  va_pte_value;
};

struct POC_ARG pocarg;
int dfd;
static char* g_pbuf;
int main(int argc, char **argv)
{
	dfd = open(DEVNAME, O_RDWR);
	if(dfd < 0)
	{
		printf("poc driver is no load\n");
		return -1;
	}
	ioctl(dfd, ALLOCPAGE, &pocarg);
	printf("pte entry value is 0x%lx\n", pocarg.va_pte_value);
	close(dfd);
	return 0;
} 
