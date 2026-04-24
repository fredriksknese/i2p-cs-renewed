using System;
using I2PCore.TransportLayer.Crypto;

class Program
{
    static void Main()
    {
        // Test vector from Python
        var key = Convert.FromHexString("53C06D6344D8424C15BE93C05C67908F96E01A51B31B85A55E6AB39A4436F016");
        var nonce = Convert.FromHexString("000000000000000000000000");
        var plaintext = Convert.FromHexString("0202000003D3000069898DBD00000000");
        var ad = Convert.FromHexString("CC38CEFA86487C300EBEC7D6A28ECD4745C1B0DB082DDB8F4444A06A7504A237");

        Console.WriteLine("Testing ChaCha20-Poly1305:");
        Console.WriteLine($"Key:       {Convert.ToHexString(key)}");
        Console.WriteLine($"Nonce:     {Convert.ToHexString(nonce)}");
        Console.WriteLine($"AD:        {Convert.ToHexString(ad)}");
        Console.WriteLine($"Plaintext: {Convert.ToHexString(plaintext)}");

        var result = ChaCha20Poly1305.Encrypt(key, nonce, plaintext, ad);

        Console.WriteLine($"Result:    {Convert.ToHexString(result)}");
        Console.WriteLine($"Expected:  4CFE82D9F3681E43433E15C7E3DC2B133A5D42C88E7CAD2E470492B58E325707");

        if (Convert.ToHexString(result) == "4CFE82D9F3681E43433E15C7E3DC2B133A5D42C88E7CAD2E470492B58E325707")
        {
            Console.WriteLine("✓ CORRECT!");
        }
        else
        {
            Console.WriteLine("✗ MISMATCH!");
        }
    }
}
