using System;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Utils;

namespace I2PCore.TransportLayer;

/// <summary>
///     AEAD error handling with probing resistance
///     Per NTCP2/SSU2 spec: On AEAD failure, implement random delays to resist probing attacks
/// </summary>
public static class AEADErrorHandler
{
    private static readonly Random random = new();
    private static readonly int MinDelayMs = 100;
    private static readonly int MaxDelayMs = 3000;

    /// <summary>
    ///     Handle AEAD authentication failure with probing resistance
    ///     Per spec: "For probing resistance, Bob should set a random timeout and read random bytes before closing"
    /// </summary>
    /// <param name="protocolName">Protocol name for logging (NTCP2 or SSU2)</param>
    /// <param name="sessionId">Session identifier for logging</param>
    /// <param name="closeAction">Action to close the connection (e.g., TCP RST or drop UDP)</param>
    public static async Task HandleAEADFailure(string protocolName, string sessionId, Action closeAction)
    {
        // Log the failure
        Logging.LogWarning($"{protocolName} {sessionId}: AEAD authentication failed");

        // Random delay for probing resistance
        var delayMs = random.Next(MinDelayMs, MaxDelayMs);
        Logging.LogDebug($"{protocolName} {sessionId}: Delaying {delayMs}ms before closing connection");

        await Task.Delay(delayMs);

        // Close the connection
        closeAction?.Invoke();

        Logging.LogDebug($"{protocolName} {sessionId}: Connection closed after AEAD failure");
    }

    /// <summary>
    ///     Handle AEAD failure synchronously (for contexts where async is not possible)
    /// </summary>
    public static void HandleAEADFailureSync(string protocolName, string sessionId, Action closeAction)
    {
        // Log the failure
        Logging.LogWarning($"{protocolName} {sessionId}: AEAD authentication failed");

        // Random delay for probing resistance
        var delayMs = random.Next(MinDelayMs, MaxDelayMs);
        Logging.LogDebug($"{protocolName} {sessionId}: Delaying {delayMs}ms before closing connection");

        Thread.Sleep(delayMs);

        // Close the connection
        closeAction?.Invoke();

        Logging.LogDebug($"{protocolName} {sessionId}: Connection closed after AEAD failure");
    }

    /// <summary>
    ///     Validate AEAD decryption result
    ///     Returns true if valid, false if failed
    /// </summary>
    public static bool ValidateAEADResult(byte[] decryptedData, string protocolName, string sessionId)
    {
        if (decryptedData == null)
        {
            Logging.LogWarning($"{protocolName} {sessionId}: AEAD decryption returned null (authentication failed)");
            return false;
        }

        return true;
    }

    /// <summary>
    ///     Generate termination message for AEAD failure
    /// </summary>
    public static Block CreateAEADFailureTermination(ulong timestamp)
    {
        return Block.CreateTerminationBlock(TerminationReason.DataPhaseAEADFailure, timestamp);
    }
}