// H03: harmless, auditable Windows process-create test artifact.
// No network, filesystem writes, persistence, registry, elevation or child processes.
using System;

internal static class H03BenignProbe
{
    private static int Main(string[] args)
    {
#if H03_V2
        Console.WriteLine("H03_BENIGN_PROBE_VERSION_2");
#else
        Console.WriteLine("H03_BENIGN_PROBE_VERSION_1");
#endif
        return 0;
    }
}
