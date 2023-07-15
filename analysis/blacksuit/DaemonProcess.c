////////////////////////////////////////////////////////////
// Blacksuit Encryptor
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////

// Check if the argument for the daemon process is not set to 1
if (demonoff != 1)
{
    pidID = fork(); // Create a sub process
    if (pidID < 0)
        return 1; // Error occured forking the process
    if (pidID)    // Parent process ID is not an error
        exit(0);
    setsid(); // Create a session and sets the process group ID.  A new session can control the terminal
    pidID = fork();
    if (pidID < 0)
        return 2; // Error occured forking the process
    if (pidID)    // Parent process ID is not an error
        exit(0);
    // Child process successfully created
    *(_QWORD *)&argc = "\nThe process is running, you can close...";
    puts("\nThe process is running, you can close...");
}
