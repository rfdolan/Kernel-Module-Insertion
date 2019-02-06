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

	// Incrementers for the arrays
	int childInc = 0;
	int sibInc = 0;
	int ancInc = 0;
	int pid = atoi(argv[1]);
	struct ancestry *ourAncestry = malloc(sizeof(struct ancestry));
	
	// Do the syscall
	syscall(__NR_cs3013_syscall2, &pid, ourAncestry);

	// Loop through an print the child processes as long as we haven't reached the end
	printf("Child Processes:\n");
	while((ourAncestry->children[childInc] != 0) && (childInc < 100)){
		printf("%d\n", ourAncestry->children[childInc]);
		childInc++;
		
	}
	
	// Loop through an print the sibling processes as long as we haven't reached the end
	printf("\nSibling Processes: \n");
	while((ourAncestry->siblings[sibInc] != 0) && (sibInc < 100)){
		printf("%d\n", ourAncestry->siblings[sibInc]);
		sibInc++;
		
	}

	printf("\nAncestry path:\n");
	
	// Loop through an print the ancestry path as long as we haven't reached the end
	while((ourAncestry->ancestors[ancInc] != 0) && (ancInc < 10)){
		printf("%d\n", ourAncestry->ancestors[ancInc]);
		ancInc++;	
	}
	if(ancInc >= 10){
		printf("We couldn't store the whole ancestry, but  we assume that it eventually gets to 1.\n");
	}
	free(ourAncestry);
	return 0;


}
