
#include <stdio.h>
#include <string.h> //memset
#include <stdlib.h> //exit
#include <stdint.h> //types defintion

#include <unistd.h> //fork()
#include <poll.h>
#include <sys/ptrace.h> //ptrace()
#include <sys/types.h>
#include <sys/wait.h> //waitpid
#include <errno.h> //erno
#include <sys/procfs.h> //elf_regset

#include "ptrace.h"
#include "elf_utils.h"

#ifdef DBG_PRINTF
#undef DBG_PRINTF
#define DBG_PRINTF(fmt,...)             \
	 fprintf(stderr, fmt, ##__VA_ARGS__);
#else
#define DBG_PRINTF
#endif

#define LOG_PRINTF(fmt, ...) \
	fprintf(stderr, fmt, ##__VA_ARGS__)

typedef enum inf_state_t {
	INF_STATE_INVALID = -1,
	INF_STATE_STARTED,
	INF_STATE_RUNNING,
	INF_STATE_STOPPED,

	INF_STATE_MAX = 256
} inf_state_t;

typedef struct inf_handle {
	char *progname;
	pid_t pid;
	inf_state_t state;
  Elf_Ehdr *ehdr;
  off_t e_sz;
} inf_handle_t;

static inf_handle_t inferior;
static inf_handle_t *inf;

static const char *GetSinfo(int signo)
{
  switch (signo) {
	 case SIGSEGV: return "SIGSEGV"; break;
	 case SIGABRT: return "SIGABRT"; break;
	 case SIGBUS:  return "SIGBUS"; break;
	 case SIGKILL: return "SIGKILL"; break;
	 case SIGINT:  return "SIGINT"; break;
	 default:  return "Unknown signal number"; break;
	}
}

static void print_reg_info(elf_gregset_t regs)
{
	int i = 0;
  struct rorder {
		int idx;
		const char *reg_name;
	};
	static struct rorder reg_print_order[] = { \
		{RAX, "rax"},
		{RBX, "rbx"},
		{RCX, "rcx"},
		{RDX, "rdx"},
		{RSI, "rsi"},
		{RDI, "rdi"},
		{RBP, "rbp"},
		{RSP, "rsp"},
		{R8,  "r8"},
		{R9,  "r9"},
		{R10, "r10"},
		{R11, "r11"},
		{R12, "r12"},
		{R13, "r13"},
		{R14, "r14"},
		{R15, "r15"},
		{RIP, "rip"},
	  {EFLAGS, "eflags"},
		{CS, "cs"},
		{SS, "ss"},
		{DS, "ds"},
		{ES, "es"},
		{FS, "fs"},
		{GS, "gs"},
	 };

	for (i = 0; i < (sizeof(reg_print_order)/sizeof(reg_print_order[0])); ++i) {
		uint64_t idx = reg_print_order[i].idx;
		if (EFLAGS == idx) {
			fprintf(stderr, "%s\t\t0x%x%10s[ PF ZF IF RF ]\n",
					reg_print_order[i].reg_name,
					regs[idx], " ");
			continue;
		}
		fprintf(stderr, "%s\t\t0x%llx%20lld\n",
				reg_print_order[i].reg_name,
				regs[idx], regs[idx]);
	}
}

Elf_Addr ReadWordInInferior(Elf_Addr offset)
{
	Elf_Addr address = ptrace(PT_READ_I, inf->pid, offset, 0);
	return address;
}

static void PrintBacktrace(Elf_Addr pc, Elf_Addr bp)
{
	char *name;
	Elf_Addr value;
	Elf_Addr ra = pc;
	Elf_Addr fp = bp;
	fprintf(stderr, "Backtrace\n");
#define FRAME_NEXT(fp) ReadWordInInferior(fp)
#define FRAME_RA(fp) ReadWordInInferior(fp+8)

	do {
		ra = FRAME_RA(fp);
	  elf_search_symbol(inf->ehdr, (Elf_Addr)pc, &value, &name);
		if (!name)
			break;
	  fprintf(stderr, "%p %s+0x%x() \n", pc, name, pc-value);
		pc = ra;
	} while (fp = FRAME_NEXT(fp));
}

void handle_inf_event(void)
{
	int status = 0;
	if (inf->state == INF_STATE_STARTED) {
		wait(&status);
		if (WIFSTOPPED(status)) {
			DBG_PRINTF( "The first process SIGTRAP after execve()\n"); //lets continue;
		  long retval = ptrace(PTRACE_CONT, inf->pid, NULL, 0);
	    DBG_PRINTF("ptrace cont returned %ld\n", retval);
			inf->state = INF_STATE_RUNNING;
		}
	} else if (inf->state == INF_STATE_RUNNING) {
		if (inf->pid != waitpid(inf->pid, &status, 0)) {
			LOG_PRINTF("waitpid() error\n");
			exit(0); // ???? kill the tracee ?
		}
		if (WIFSTOPPED(status)) {
			int si = WSTOPSIG(status);
			elf_gregset_t regs;
			Elf_Sym *sym = NULL;
      Elf_Addr value;
      char *name;

			LOG_PRINTF( "Program received signal %s\n", GetSinfo(si));

			if (ptrace (PTRACE_GETREGS, inf->pid, 0, (long) &regs) < 0)
				perror("couldn't get registers\n");

			DBG_PRINTF("successfully read registers\n");
			print_reg_info(regs);
			PrintBacktrace(regs[RIP], regs[RBP]);
			exit(0);
		}
	}
}

void do_sigchld(int signo)
{
	DBG_PRINTF("sigchld received by %d task\n", getpid());
	handle_inf_event();
}

int main()
{
	char *program = "/home/vijay/ptrace/cdump";
	pid_t pid;

	inf = &inferior;
	inf->progname = program;

  inf->ehdr = elf_map_file(program, &inf->e_sz);
	if (NULL == inf->ehdr) {
		LOG_PRINTF("Cannot map the elf file\n");
		exit(0);
	}
	signal(SIGCHLD, do_sigchld);

	if (!(pid= fork())) {
		int *ptr = NULL;
		char *argv[10];
		memset(argv, 0, sizeof(argv));
    long retval = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		DBG_PRINTF("ptrace returned %ld\n", retval);
		if (0 > retval) {
			DBG_PRINTF("ptrace failed with errno(%d:%s)\n", errno, strerror(errno));
			exit(0);
		}
		DBG_PRINTF( "Now exec'ing the child\n");
		int rval = execv(program, argv);
		if (0 > rval) {
			DBG_PRINTF( "execv returned error\n");
			exit(0);
		}
		DBG_PRINTF("Error if you are here!!!!\n");
	} else {
		int rval = 0;
		inf->pid = pid;
poll_forever:
	  rval = poll(0, 0, -1);
		goto poll_forever;
	}
}

