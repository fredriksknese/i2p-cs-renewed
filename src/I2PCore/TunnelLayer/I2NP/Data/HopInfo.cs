using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;

namespace I2PCore.TunnelLayer.I2NP.Data
{
    public class HopInfo
    {
        public readonly I2PKeysAndCert Peer;
        public readonly I2PTunnelId TunnelId;

        public I2PSessionKey IvKey;
        public I2PSessionKey LayerKey;

        // ECIES reply decryption keys (derived from Noise handshake for short tunnel builds)
        public byte[] ReplyKey;
        public byte[] ReplyIV;

        // Garlic key and tag for decrypting build replies from endpoint hops
        // Derived from sequential HKDF chain on Noise CK (i2pd "RGarlicKeyAndTag")
        public byte[] GarlicKey;
        public ulong GarlicTag;

        // Handshake hash from Noise N (used as AD for AEAD reply record decryption)
        public byte[] HandshakeHash;

        public VariableTunnelBuildMessage.ReplyProcessingInfo ReplyProcessing;

        /// <summary>
        /// Index of this hop's record in the shuffled ShortTunnelBuild message.
        /// Used for reply decryption (nonce = recordIndex).
        /// </summary>
        public int RecordIndex;

        public HopInfo( I2PKeysAndCert dest, I2PTunnelId id )
        {
            Peer = dest;
            TunnelId = id;
        }
    }
}
