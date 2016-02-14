
#include <stdio.h>
#include <signal.h>
#include <execinfo.h>

void *buf[100];

void signalHandler(int signo)
{
	backtrace((void **)&buf, sizeof(buf));
	signal(SIGSEGV, SIG_DFL);
}

int mandrake()
{
	int *p = NULL;

	*p = 0;
}

int phantom()
{
	mandrake();
}

int phoenix()
{
	phantom();
}

int foo()
{
	phoenix();
}

int bar()
{
	foo();
}

int main()
{
	printf("Trace me bitches!!!!!\n");
	signal(SIGSEGV, signalHandler);
	bar();
}

