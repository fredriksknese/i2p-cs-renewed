using System;
using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Data;
using System.Linq;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;

namespace I2PCore.TunnelLayer
{
    public class TunnelBuildRequestDecrypt
    {
        private readonly IEnumerable<AesEgBuildRequestRecord> RecordsField;
        private readonly I2PIdentHash Me;
        private readonly I2PPrivateKey Key;
        private readonly AesEgBuildRequestRecord ToMeField;
        private readonly EgBuildRequestRecord MyRecord;
        private readonly BuildRequestRecord DecryptedRecord;

        public TunnelBuildRequestDecrypt(
            IEnumerable<AesEgBuildRequestRecord> records,
            I2PIdentHash me,
            I2PPrivateKey key )
        {
            RecordsField = records;
            Me = me;
            Key = key;

            ToMeField = RecordsField.FirstOrDefault( rec => Me.Hash16 == rec.ToPeer16 );

            if ( ToMeField != null )
            {
                MyRecord = new EgBuildRequestRecord( ToMeField );
                try
                {
                    DecryptedRecord = MyRecord.Decrypt( key );
                }
                catch ( Exception ex )
                {
                    Logging.LogDebug( $"TunnelBuildRequestDecrypt: Decryption failed for {Me.Id32Short}: {ex.Message}" );
                }
            }
        }

        public TunnelBuildRequestDecrypt Clone()
        {
            return new TunnelBuildRequestDecrypt(
                Records.Select( r => r.Clone() ),
                Me,
                Key );
        }

        public AesEgBuildRequestRecord ToMe()
        {
            return ToMeField;
        }

        public BuildRequestRecord Decrypted => DecryptedRecord;
        public IEnumerable<AesEgBuildRequestRecord> Records => RecordsField;

        public IEnumerable<AesEgBuildRequestRecord> CreateTunnelBuildReplyRecords( 
            BuildResponseRecord.RequestResponse response )
        {
            var newrecords = new List<AesEgBuildRequestRecord>(
                Records.Select( r => r.Clone() )
            );

            var tmp = new TunnelBuildRequestDecrypt( newrecords, Me, Key );

            tmp.ToMeField.Data.Randomize();
            var responserec = new BuildResponseRecord( tmp.ToMeField.Data )
            {
                Reply = response
            };
            responserec.UpdateHash();

            var cipher = new CbcBlockCipher( new AesEngine() );
            cipher.Init( true, Decrypted.ReplyKeyBuf.ToParametersWithIv( Decrypted.ReplyIv ) );

            foreach ( var one in newrecords )
            {
                cipher.Reset();
                one.Process( cipher );
            }

            return newrecords;
        }


        public override string ToString()
        {
            return $"{GetType().Name} {Decrypted}";
        }
    }
}
