using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using I2PCore.Utils;
using System.Threading;
using I2PCore.SessionLayer;
using I2PCore.Crypto.MLKEM;

namespace I2PCore.Data
{
    public class I2PPrivateKey : I2PKeyType
    {
        public I2PPrivateKey( I2PCertificate cert ) : base( cert )
        {
            switch ( Certificate.PublicKeyType )
            {
                case KeyTypes.MLKEM512_X25519:
                    {
                        var (_, mlkemPriv) = MLKEM512.GenerateKeyPair();
                        var x25519Priv = BufUtils.RandomBytes( 32 );
                        x25519Priv[0] &= 248;
                        x25519Priv[31] &= 127;
                        x25519Priv[31] |= 64;

                        var combined = new byte[mlkemPriv.Length + x25519Priv.Length];
                        Array.Copy( mlkemPriv, 0, combined, 0, mlkemPriv.Length );
                        Array.Copy( x25519Priv, 0, combined, mlkemPriv.Length, x25519Priv.Length );
                        Key = new BufLen( combined );
                    }
                    break;

                case KeyTypes.MLKEM768_X25519:
                    {
                        var (_, mlkemPriv) = MLKEM768.GenerateKeyPair();
                        var x25519Priv = BufUtils.RandomBytes( 32 );
                        x25519Priv[0] &= 248;
                        x25519Priv[31] &= 127;
                        x25519Priv[31] |= 64;

                        var combined = new byte[mlkemPriv.Length + x25519Priv.Length];
                        Array.Copy( mlkemPriv, 0, combined, 0, mlkemPriv.Length );
                        Array.Copy( x25519Priv, 0, combined, mlkemPriv.Length, x25519Priv.Length );
                        Key = new BufLen( combined );
                    }
                    break;

                case KeyTypes.MLKEM1024_X25519:
                    {
                        var (_, mlkemPriv) = MLKEM1024.GenerateKeyPair();
                        var x25519Priv = BufUtils.RandomBytes( 32 );
                        x25519Priv[0] &= 248;
                        x25519Priv[31] &= 127;
                        x25519Priv[31] |= 64;

                        var combined = new byte[mlkemPriv.Length + x25519Priv.Length];
                        Array.Copy( mlkemPriv, 0, combined, 0, mlkemPriv.Length );
                        Array.Copy( x25519Priv, 0, combined, mlkemPriv.Length, x25519Priv.Length );
                        Key = new BufLen( combined );
                    }
                    break;

                default:
                    Key = new BufLen( BufUtils.RandomBytes( KeySizeBytes ) );

                    switch ( Certificate.PublicKeyType )
                    {
                        case KeyTypes.X25519:
                            // X25519 key clamping per RFC 7748
                            Key[0] &= 248;
                            Key[Key.Length - 1] &= 127;
                            Key[Key.Length - 1] |= 64;
                            break;

                        default:
                            // ElGamal / EC keys: ensure high bit set and odd
                            Key[0] |= 0x80;
                            Key[Key.Length - 1] |= 0x01;
                            break;
                    }
                    break;
            }
        }

        public I2PPrivateKey( BufRef reader, I2PCertificate cert ) : base( reader, cert ) { }

        public override int KeySizeBytes { get { return Certificate.PrivateKeyLength; } }

        #region Precalculated keys

        protected static Thread Worker;
        private static LinkedList<I2PdhKeyPair> _precalculatedKeys;
        private static AutoResetEvent _keyConsumed = new( true );

        public static I2PdhKeyPair GetNewKeyPair()
        {
            if ( Worker == null )
            {
                _precalculatedKeys = new LinkedList<I2PdhKeyPair>();

                Worker = new Thread( () => Run() )
                {
                    Name = "DH Key pair generator",
                    Priority = ThreadPriority.Lowest,
                    IsBackground = true
                };
                Worker.Start();
            }

            I2PdhKeyPair result;

            lock ( _precalculatedKeys )
            {
                if ( _precalculatedKeys.Count > 0 )
                {
                    result = _precalculatedKeys.Last.Value;
                    _precalculatedKeys.RemoveLast();
                    _keyConsumed.Set();
                    return result;
                }
            }

            result.PrivateKey = new I2PPrivateKey( DefaultAsymetricKeyCert );
            result.PublicKey = new I2PPublicKey( result.PrivateKey );
            return result;
        }

        private static void Run()
        {
            try
            {
                try
                {
                    while ( true )
                    {
                        _keyConsumed.WaitOne( 5000 );

                        while ( _precalculatedKeys.Count < 10 )
                        {
                            I2PdhKeyPair keys;
                            keys.PrivateKey = new I2PPrivateKey( DefaultAsymetricKeyCert );
                            keys.PublicKey = new I2PPublicKey( keys.PrivateKey );
                            lock ( _precalculatedKeys )
                            {
                                _precalculatedKeys.AddFirst( keys );
                            }
                        }
                    }
                }
                catch ( ThreadAbortException )
                {
                }
                catch ( Exception ex )
                {
                    Logging.Log( ex );
                }
            }
            finally
            {
                Worker = null;
            }
        }

        #endregion
    }

    public struct I2PdhKeyPair
    {
        public I2PPrivateKey PrivateKey;
        public I2PPublicKey PublicKey;
    }
}
