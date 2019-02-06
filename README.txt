Written by Raymond Dolan

Part 1 intercepts the open, read, and close syscalls, and gives custom messages with each
The read functino looks for the string "VIRUS" in any read files, and returns a message if it finds it

Part 2 intercepts our previously made syscall and makes it return the geneology of the passed in pid
The file testPart2.sh runs the necessary commands to test the program
	-It takes the pid of the process that you wish to analyze

