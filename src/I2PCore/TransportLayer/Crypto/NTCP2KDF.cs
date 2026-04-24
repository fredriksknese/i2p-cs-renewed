using System;
using System.Security.Cryptography;

namespace I2PCore.TransportLayer.Crypto
{
    /// <summary>
    /// NTCP2-specific Key Derivation Functions
    /// Implements the SipHash key derivation as specified in NTCP2 spec
    /// </summary>
    public static class NTCP2KDF
    {
        /// <summary>
        /// Derive SipHash keys for frame length obfuscation (NTCP2 spec lines 1094-1160)
        ///
        /// Per spec:
        ///   ask_master = HMAC-SHA256(temp_key, "ask" || byte(0x01))
        ///   temp_key = HMAC-SHA256(ask_master, h || "siphash")
        ///   sip_master = HMAC-SHA256(temp_key, byte(0x01))
        ///
        ///   Alice to Bob:
        ///   temp_key = HMAC-SHA256(sip_master, zerolen)
        ///   sipkeys_ab = HMAC-SHA256(temp_key, byte(0x01))
        ///   sipk1_ab = sipkeys_ab[0:7], little endian
        ///   sipk2_ab = sipkeys_ab[8:15], little endian
        ///   sipiv_ab = sipkeys_ab[16:23]
        ///
        ///   Bob to Alice:
        ///   sipkeys_ba = HMAC-SHA256(temp_key, sipkeys_ab || byte(0x02))
        ///   sipk1_ba = sipkeys_ba[0:7], little endian
        ///   sipk2_ba = sipkeys_ba[8:15], little endian
        ///   sipiv_ba = sipkeys_ba[16:23]
        /// </summary>
        public static SipHashKeys DeriveSipHashKeys(byte[] chainingKey, byte[] handshakeHash)
        {
            if (chainingKey == null || chainingKey.Length != 32)
                throw new ArgumentException("Chaining key must be 32 bytes", nameof(chainingKey));
            if (handshakeHash == null || handshakeHash.Length != 32)
                throw new ArgumentException("Handshake hash must be 32 bytes", nameof(handshakeHash));

            // Step 1: ask_master = HKDF(ck, zerolen, "ask", 32)
            // i2pd: HKDF(salt=ck, ikm=empty, info="ask")
            var askMaster = NoiseKDF.HKDF(chainingKey, null, System.Text.Encoding.ASCII.GetBytes("ask"), 32);

            // Step 2: sip_master = HKDF(ask_master, h || "siphash", "", 32)
            // i2pd: HKDF(salt=ask_master, ikm=h || "siphash", info="")
            var ikm2 = new byte[32 + 7];
            Array.Copy(handshakeHash, 0, ikm2, 0, 32);
            Array.Copy(System.Text.Encoding.ASCII.GetBytes("siphash"), 0, ikm2, 32, 7);
            var sipMaster = NoiseKDF.HKDF(askMaster, ikm2, null, 32);

            // Step 3: sipkeys_ab, sipkeys_ba = HKDF(sip_master, zerolen, "", 64)
            // i2pd: HKDF(salt=sip_master, ikm=empty, info="")
            var sipkeys = NoiseKDF.HKDF(sipMaster, null, null, 64);

            // Extract k1, k2, IV for Alice to Bob (first 32 bytes)
            var sipk1Ab = BitConverter.ToUInt64(sipkeys, 0);
            var sipk2Ab = BitConverter.ToUInt64(sipkeys, 8);
            var sipivAb = new byte[8];
            Array.Copy(sipkeys, 16, sipivAb, 0, 8);

            // Extract k1, k2, IV for Bob to Alice (next 32 bytes)
            var sipk1Ba = BitConverter.ToUInt64(sipkeys, 32);
            var sipk2Ba = BitConverter.ToUInt64(sipkeys, 40);
            var sipivBa = new byte[8];
            Array.Copy(sipkeys, 48, sipivBa, 0, 8);

            // Clear sensitive data
            Array.Clear(askMaster, 0, askMaster.Length);
            Array.Clear(sipMaster, 0, sipMaster.Length);
            Array.Clear(sipkeys, 0, sipkeys.Length);

            return new SipHashKeys
            {
                AliceToBobK1 = sipk1Ab,
                AliceToBobK2 = sipk2Ab,
                AliceToBobIV = sipivAb,
                BobToAliceK1 = sipk1Ba,
                BobToAliceK2 = sipk2Ba,
                BobToAliceIV = sipivBa
            };
        }

        private static byte[] HMACSHA256(byte[] key, byte[] data)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }
    }

    /// <summary>
    /// Container for SipHash keys derived for NTCP2 frame obfuscation
    /// </summary>
    public class SipHashKeys
    {
        public ulong AliceToBobK1 { get; set; }
        public ulong AliceToBobK2 { get; set; }
        public byte[] AliceToBobIV { get; set; }

        public ulong BobToAliceK1 { get; set; }
        public ulong BobToAliceK2 { get; set; }
        public byte[] BobToAliceIV { get; set; }
    }
}
