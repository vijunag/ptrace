# ptrace

My expirements with ptrace.
==============================
A simple asynchronous ptracer for Linux systems based on SIGCHLD signal. Every noticeable program state change is noticed through a SIGCHLD handler. Program attempts to print the stack trace if frame pointers exists and prints the symbol for the obtained return addresses.

Example Trace:
--------------
```
localhost:~/ptrace]$ ./ptrace -e cdump
Trace me bitches!!!!!
Program received signal SIGSEGV
rax0x0                   0
rbx0x0                   0
rcx0x7fb80b308238     140428438438456
rdx0x0                   0
rsi0x0                   0
rdi0xb                  11
rbp0x7ffea28b6ad0     140731625466576
rsp0x7ffea28b6ad0     140731625466576
r80x7ffea28b6a70     140731625466480
r90x0                   0
r100x8                   8
r110x202                 514
r120x4004e0             4195552
r130x7ffea28b6c00     140731625466880
r140x0                   0
r150x0                   0
rip0x400612             4195858
eflags0x10206          [ PF ZF IF RF ]
cs0x33                  51
ss0x2b                  43
ds0x0                   0
es0x0                   0
fs0x0                   0
gs0x0                   0
Backtrace
0x400612 mandrake+0x10()
	0x400629 phantom+0xe()
	0x40063a phoenix+0xe()
	0x40064b foo+0xe()
	0x40065c bar+0xe()
	0x400686 main+0x27()
```

