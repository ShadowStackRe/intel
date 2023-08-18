////////////////////////////////////////////////////////////
// AbyssLocker
// https://www.shadowstackre.com/analysis/AbyssLocker
//
// Technique: Mitre Command and Scripting Interpreter
// URL: https://attack.mitre.org/techniques/T1059/
//
// Analysis: ShadowStackRE
////////////////////////////////////////////////////////////
v9 = getopt(argc, argv, "m:vdekc:"); // Get program arguments
if (v9 == -1)
    break;
if (v9 == 101)
    goto LABEL_23;
if (v9 > 101)
{
    switch (v9)
    {
    case 'm': // Mode
        progArgMode = atoi(optarg);
        break;
    case 'v': // Verbose
        progArgVerbose = 1;
        break;
    case 'k':
        progArgVMKill = 1; // Kill thbe VM infrastructure
    LABEL_23:
        progArgVMDK = 1; // Encrypt VMDisks
        break;
    }
}
else if (v9 == 99)
{
    progArgCountFiles = atoi(optarg);
}
else if (v9 == 100)
{
    progArgDeamon = 1; // Daemon Mode
}
