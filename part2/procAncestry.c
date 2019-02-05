#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define __NR_cs3013_syscall2 378

/*
	Define our ancestry struct which we pass into our program.
*/
struct ancestry {
	pid_t ancestors[10];
	pid_t siblings[100];
	pid_t children[100];
};

int main(int argc, char *argv[])
{
	// If the user put the wrong number of arguments in, tell them
	if(argc != 2)
	{
		printf("Wrong number of arguments\n");
		exit(1);
	}
	int pid = atoi(argv[1]);
	struct ancestry *ourAncestry = malloc(sizeof(struct ancestry));
	
	// Do the syscall
	syscall(__NR_cs3013_syscall2, pid, ourAncestry);
	return 0;


}
