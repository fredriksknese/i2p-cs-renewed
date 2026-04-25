using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace I2PCore.Data;

public class I2PSignature : I2PType
{
    public I2PCertificate Certificate;
    public I2PByteBlock Sig;

    public I2PSignature()
    {
        Certificate = I2PSigningKey.DefaultSigningKeyCert;
        Sig = new I2PByteBlock(new byte[Certificate.SignatureLength]);
    }

    public I2PSignature(I2PBufferCursor buf, I2PCertificate cert)
    {
        Certificate = cert;

        Sig = buf.ReadBlock(cert.SignatureLength);
    }

    public void Write(IBufferWriter<byte> dest)
    {
        dest.WriteBlock(Sig);
    }

    public static bool SupportedSignatureType(I2PSigningKey.SigningKeyTypes stype)
    {
        return stype == I2PSigningKey.SigningKeyTypes.DsaSha1
               || stype == I2PSigningKey.SigningKeyTypes.EcdsaSha256P256
               || stype == I2PSigningKey.SigningKeyTypes.EcdsaSha384P384
               || stype == I2PSigningKey.SigningKeyTypes.EcdsaSha512P521
               || stype == I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519
               || stype == I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519ph
               || stype == I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519
               || stype == I2PSigningKey.SigningKeyTypes.RsaSha2562048
               || stype == I2PSigningKey.SigningKeyTypes.RsaSha3843072
               || stype == I2PSigningKey.SigningKeyTypes.RsaSha5124096
               || stype == I2PSigningKey.SigningKeyTypes.GostR34102012_256
               || stype == I2PSigningKey.SigningKeyTypes.GostR34102012_512
               || stype == I2PSigningKey.SigningKeyTypes.MlDsa44;
    }

    public static byte[] DoSign(I2PSigningPrivateKey key, params I2PByteBlock[] bufs)
    {
        //Logging.LogDebug( "DoSign: " + key.Certificate.SignatureType.ToString() );

        switch (key.Certificate.SignatureType)
        {
            case I2PSigningKey.SigningKeyTypes.DsaSha1:
                return DoSignDsaSha1(bufs, key);

            case I2PSigningKey.SigningKeyTypes.EcdsaSha256P256:
                return DoSignEcDsa(bufs, key, new Sha256Digest(), NistNamedCurves.GetByName("P-256"), 64);

            case I2PSigningKey.SigningKeyTypes.EcdsaSha384P384:
                return DoSignEcDsa(bufs, key, new Sha384Digest(), NistNamedCurves.GetByName("P-384"), 96);

            case I2PSigningKey.SigningKeyTypes.EcdsaSha512P521:
                return DoSignEcDsa(bufs, key, new Sha512Digest(), NistNamedCurves.GetByName("P-521"), 132);

            case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519:
            case I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519:
                return DoSignEdDsasha512Ed25519(bufs, key);

            case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519ph:
                return DoSignEdDsasha512Ed25519ph(bufs, key);

            case I2PSigningKey.SigningKeyTypes.RsaSha2562048:
                return DoSignRsa(bufs, key, new Sha256Digest());

            case I2PSigningKey.SigningKeyTypes.RsaSha3843072:
                return DoSignRsa(bufs, key, new Sha384Digest());

            case I2PSigningKey.SigningKeyTypes.RsaSha5124096:
                return DoSignRsa(bufs, key, new Sha512Digest());

            case I2PSigningKey.SigningKeyTypes.GostR34102012_256:
                return DoSignGost(bufs, key, 256);

            case I2PSigningKey.SigningKeyTypes.GostR34102012_512:
                return DoSignGost(bufs, key, 512);

            case I2PSigningKey.SigningKeyTypes.MlDsa44:
                return DoSignMlDsa44(bufs, key);

            default:
                Logging.LogWarning($"I2PSignature: Signing not implemented for {key.Certificate.SignatureType}");
                return null;
        }
    }

    public static byte[] DoSignEdDsasha512Ed25519(IEnumerable<I2PByteBlock> bufs, I2PSigningPrivateKey key)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(key.Key.ToByteArray(), 0));
        var ar = bufs.SelectMany(b => b.ToByteArray()).ToArray();
        signer.BlockUpdate(ar, 0, ar.Length);
        return signer.GenerateSignature();
    }

    public static byte[] DoSignDsaSha1(IEnumerable<I2PByteBlock> bufs, I2PSigningPrivateKey key)
    {
        var sha = new Sha1Digest();
        foreach (var buf in bufs) sha.BlockUpdate(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
        var hash = new byte[sha.GetDigestSize()];
        sha.DoFinal(hash, 0);

        var s = new DsaSigner();

        var dsaparams = new ParametersWithRandom(
            new DsaPrivateKeyParameters(
                key.ToBigInteger(),
                new DsaParameters(
                    I2PConstants.DsaP,
                    I2PConstants.DsaQ,
                    I2PConstants.DsaG)));

        s.Init(true, dsaparams);
        var sig = s.GenerateSignature(hash);
        var result = new byte[40];

        var b1 = sig[0].ToByteArrayUnsigned();
        var b2 = sig[1].ToByteArrayUnsigned();

        // https://geti2p.net/en/docs/spec/common-structures#type_Signature
        // When a signature is composed of two elements (for example values R,S), 
        // it is serialized by padding each element to length/2 with leading zeros if necessary.
        // All types are Big Endian, except for EdDSA, which is stored and transmitted in a Little Endian format.

        // Pad msb. Big endian.
        Array.Copy(b1, 0, result, 0 + 20 - b1.Length, b1.Length);
        Array.Copy(b2, 0, result, 20 + 20 - b2.Length, b2.Length);

        return result;
    }

    public static byte[] DoSignEcDsaSha256P256_old(IEnumerable<I2PByteBlock> bufs, I2PSigningPrivateKey key)
    {
        var sha = new Sha256Digest();
        foreach (var buf in bufs) sha.BlockUpdate(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
        var hash = new byte[sha.GetDigestSize()];
        sha.DoFinal(hash, 0);

        var p = NistNamedCurves.GetByName("P-256");
        var param = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
        var pk = new ECPrivateKeyParameters(key.ToBigInteger(), param);

        var s = new ECDsaSigner();
        s.Init(true, new ParametersWithRandom(pk));

        var sig = s.GenerateSignature(hash);
        var result = new byte[64];

        var b1 = sig[0].ToByteArrayUnsigned();
        var b2 = sig[1].ToByteArrayUnsigned();

        // https://geti2p.net/en/docs/spec/common-structures#type_Signature
        // When a signature is composed of two elements (for example values R,S), 
        // it is serialized by padding each element to length/2 with leading zeros if necessary.
        // All types are Big Endian, except for EdDSA, which is stored and transmitted in a Little Endian format.

        // Pad msb. Big endian.
        Array.Copy(b1, 0, result, 0 + 20 - b1.Length, b1.Length);
        Array.Copy(b2, 0, result, 20 + 20 - b2.Length, b2.Length);

        Logging.LogDebug("DoSignEcDsaSha256P256: Used.");

        return result;
    }

    public static byte[] DoSignEcDsa(
        IEnumerable<I2PByteBlock> bufs,
        I2PSigningPrivateKey key,
        IDigest digest,
        X9ECParameters ecparam,
        int sigsize)
    {
        foreach (var buf in bufs) digest.BlockUpdate(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
        var hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);

        var param = new ECDomainParameters(ecparam.Curve, ecparam.G, ecparam.N, ecparam.H);
        var pk = new ECPrivateKeyParameters(key.ToBigInteger(), param);

        var s = new ECDsaSigner();
        s.Init(true, new ParametersWithRandom(pk));

        var sig = s.GenerateSignature(hash);
        var result = new byte[sigsize];

        var b1 = sig[0].ToByteArrayUnsigned();
        var b2 = sig[1].ToByteArrayUnsigned();

        // https://geti2p.net/en/docs/spec/common-structures#type_Signature
        // When a signature is composed of two elements (for example values R,S), 
        // it is serialized by padding each element to length/2 with leading zeros if necessary.
        // All types are Big Endian, except for EdDSA, which is stored and transmitted in a Little Endian format.

        // Pad msb. Big endian.
        Array.Copy(b1, 0, result, sigsize / 2 - b1.Length, b1.Length);
        Array.Copy(b2, 0, result, sigsize - b2.Length, b2.Length);

        Logging.LogDebug($"DoSignEcDsa: {digest}: Used.");

        return result;
    }

    public static bool DoVerify(I2PSigningPublicKey key, I2PSignature signed, params I2PByteBlock[] bufs)
    {
        //Logging.LogDebug( $"DoVerify: {key.Certificate.SignatureType}" );

        switch (key.Certificate.SignatureType)
        {
            case I2PSigningKey.SigningKeyTypes.DsaSha1:
                return DoVerifyDsaSha1(bufs, key, signed);

            case I2PSigningKey.SigningKeyTypes.EcdsaSha256P256:
                return DoVerifyEcDsa(bufs, key, signed, new Sha256Digest(), NistNamedCurves.GetByName("P-256"));

            case I2PSigningKey.SigningKeyTypes.EcdsaSha384P384:
                return DoVerifyEcDsa(bufs, key, signed, new Sha384Digest(), NistNamedCurves.GetByName("P-384"));

            case I2PSigningKey.SigningKeyTypes.EcdsaSha512P521:
                return DoVerifyEcDsa(bufs, key, signed, new Sha512Digest(), NistNamedCurves.GetByName("P-521"));

            case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519:
            case I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519:
                return DoVerifyEdDsasha512Ed25519(bufs, key, signed);

            case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519ph:
                return DoVerifyEdDsasha512Ed25519ph(bufs, key, signed);

            case I2PSigningKey.SigningKeyTypes.RsaSha2562048:
                return DoVerifyRsa(bufs, key, signed, new Sha256Digest());

            case I2PSigningKey.SigningKeyTypes.RsaSha3843072:
                return DoVerifyRsa(bufs, key, signed, new Sha384Digest());

            case I2PSigningKey.SigningKeyTypes.RsaSha5124096:
                return DoVerifyRsa(bufs, key, signed, new Sha512Digest());

            case I2PSigningKey.SigningKeyTypes.GostR34102012_256:
                return DoVerifyGost(bufs, key, signed, 256);

            case I2PSigningKey.SigningKeyTypes.GostR34102012_512:
                return DoVerifyGost(bufs, key, signed, 512);

            case I2PSigningKey.SigningKeyTypes.MlDsa44:
                return DoVerifyMlDsa44(bufs, key, signed);

            default:
                Logging.LogWarning($"I2PSignature: Verification not implemented for {key.Certificate.SignatureType}");
                return false;
        }
    }

    public static bool DoVerifyEdDsasha512Ed25519(IEnumerable<I2PByteBlock> bufs, I2PSigningPublicKey key,
        I2PSignature signed)
    {
        var signer = new Ed25519Signer();
        signer.Init(false, new Ed25519PublicKeyParameters(key.Key.BaseArray, key.Key.BaseArrayOffset));
        var ar = bufs.SelectMany(b => b.ToByteArray()).ToArray();
        signer.BlockUpdate(ar, 0, ar.Length);
        return signer.VerifySignature(signed.Sig.ToByteArray());
    }

    public static bool DoVerifyDsaSha1(IEnumerable<I2PByteBlock> bufs, I2PSigningPublicKey key, I2PSignature signed)
    {
        if (!SupportedSignatureType(signed.Certificate.SignatureType))
        {
            Logging.LogWarning(
                $"I2PSignature: Unsupported signature type {signed.Certificate.SignatureType} in DSA verify");
            return false;
        }

        var sha = new Sha1Digest();
        foreach (var buf in bufs) sha.BlockUpdate(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
        var hash = new byte[sha.GetDigestSize()];
        sha.DoFinal(hash, 0);

        var dsa = new DsaSigner();

        var sigsize = signed.Certificate.SignatureLength;
        var r = new BigInteger(1, signed.Sig.BaseArray, signed.Sig.BaseArrayOffset + 0, sigsize / 2);
        var s = new BigInteger(1, signed.Sig.BaseArray, signed.Sig.BaseArrayOffset + sigsize / 2, sigsize / 2);

        var dsaparams =
            new DsaPublicKeyParameters(
                key.ToBigInteger(),
                new DsaParameters(
                    I2PConstants.DsaP,
                    I2PConstants.DsaQ,
                    I2PConstants.DsaG));

        dsa.Init(false, dsaparams);
        return dsa.VerifySignature(hash, r, s);
    }

    public static bool DoVerifyEcDsa(
        IEnumerable<I2PByteBlock> bufs,
        I2PSigningPublicKey key,
        I2PSignature signed,
        IDigest digest,
        X9ECParameters ecparam)
    {
        if (!SupportedSignatureType(signed.Certificate.SignatureType))
        {
            Logging.LogWarning(
                $"I2PSignature: Unsupported signature type {signed.Certificate.SignatureType} in ECDSA verify");
            return false;
        }

        foreach (var buf in bufs) digest.BlockUpdate(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
        var hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);

        var param = new ECDomainParameters(ecparam.Curve, ecparam.G, ecparam.N, ecparam.H);
        var pk = new ECPublicKeyParameters(ecparam.Curve.DecodePoint(key.ToByteArray()), param);

        var dsa = new ECDsaSigner();

        var sigsize = signed.Certificate.SignatureLength;
        var r = new BigInteger(1, signed.Sig.BaseArray, signed.Sig.BaseArrayOffset, sigsize / 2);
        var s = new BigInteger(1, signed.Sig.BaseArray, signed.Sig.BaseArrayOffset + sigsize / 2, sigsize / 2);

        dsa.Init(false, pk);
        var result = dsa.VerifySignature(hash, r, s);
        Logging.LogDebug($"DoVerifyEcDsa: {result}: {digest}");
        return result;
    }

    /// <summary>
    ///     EdDSA-SHA512-Ed25519ph (prehash mode - SHA512 the data first, then sign the hash)
    /// </summary>
    public static byte[] DoSignEdDsasha512Ed25519ph(IEnumerable<I2PByteBlock> bufs, I2PSigningPrivateKey key)
    {
        // Prehash: SHA-512 of the data
        var sha = new Sha512Digest();
        foreach (var buf in bufs) sha.BlockUpdate(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
        var hash = new byte[sha.GetDigestSize()];
        sha.DoFinal(hash, 0);

        // Sign the hash with Ed25519
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(key.Key.ToByteArray(), 0));
        signer.BlockUpdate(hash, 0, hash.Length);
        return signer.GenerateSignature();
    }

    public static bool DoVerifyEdDsasha512Ed25519ph(IEnumerable<I2PByteBlock> bufs, I2PSigningPublicKey key,
        I2PSignature signed)
    {
        // Prehash: SHA-512 of the data
        var sha = new Sha512Digest();
        foreach (var buf in bufs) sha.BlockUpdate(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
        var hash = new byte[sha.GetDigestSize()];
        sha.DoFinal(hash, 0);

        // Verify the hash with Ed25519
        var signer = new Ed25519Signer();
        signer.Init(false, new Ed25519PublicKeyParameters(key.Key.BaseArray, key.Key.BaseArrayOffset));
        signer.BlockUpdate(hash, 0, hash.Length);
        return signer.VerifySignature(signed.Sig.ToByteArray());
    }

    /// <summary>
    ///     RSA signature with specified hash
    /// </summary>
    public static byte[] DoSignRsa(IEnumerable<I2PByteBlock> bufs, I2PSigningPrivateKey key, IDigest digest)
    {
        // Hash the data
        foreach (var buf in bufs) digest.BlockUpdate(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
        var hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);

        // Create RSA private key parameters from I2P format
        var keyBytes = key.Key.ToByteArray();
        var modulus = new BigInteger(1, keyBytes);

        var signer = new RsaDigestSigner(digest);
        var privKeyParams = new RsaKeyParameters(true, modulus, BigInteger.ValueOf(65537));
        signer.Init(true, privKeyParams);
        var ar = bufs.SelectMany(b => b.ToByteArray()).ToArray();
        signer.BlockUpdate(ar, 0, ar.Length);
        return signer.GenerateSignature();
    }

    public static bool DoVerifyRsa(IEnumerable<I2PByteBlock> bufs, I2PSigningPublicKey key, I2PSignature signed,
        IDigest digest)
    {
        var keyBytes = key.Key.ToByteArray();
        var modulus = new BigInteger(1, keyBytes);

        var signer = new RsaDigestSigner(digest);
        var pubKeyParams = new RsaKeyParameters(false, modulus, BigInteger.ValueOf(65537));
        signer.Init(false, pubKeyParams);
        var ar = bufs.SelectMany(b => b.ToByteArray()).ToArray();
        signer.BlockUpdate(ar, 0, ar.Length);
        return signer.VerifySignature(signed.Sig.ToByteArray());
    }

    /// <summary>
    ///     Verify a GOST R 34.10-2012 signature (256-bit or 512-bit).
    ///     Uses BouncyCastle's ECGOST3410-2012 signer with Streebog hash.
    /// </summary>
    public static bool DoVerifyGost(IEnumerable<I2PByteBlock> bufs, I2PSigningPublicKey key, I2PSignature signed,
        int bits)
    {
        try
        {
            var keyBytes = key.Key.ToByteArray();
            var sigBytes = signed.Sig.ToByteArray();
            var data = bufs.SelectMany(b => b.ToByteArray()).ToArray();

            // Select curve and hash based on key size
            DerObjectIdentifier curveOid;
            IDigest digest;

            if (bits == 256)
            {
                curveOid = ECGost3410NamedCurves.GetOid("Tc26-Gost-3410-12-256-paramSetA");
                digest = new Gost3411_2012_256Digest();
            }
            else
            {
                curveOid = ECGost3410NamedCurves.GetOid("Tc26-Gost-3410-12-512-paramSetA");
                digest = new Gost3411_2012_512Digest();
            }

            var ecParams = ECGost3410NamedCurves.GetByOid(curveOid);
            var curve = ecParams.Curve;
            var halfLen = keyBytes.Length / 2;

            // GOST public key: x || y in little-endian
            var xBytes = new byte[halfLen];
            var yBytes = new byte[halfLen];
            Array.Copy(keyBytes, 0, xBytes, 0, halfLen);
            Array.Copy(keyBytes, halfLen, yBytes, 0, halfLen);
            // Reverse to big-endian for BouncyCastle
            Array.Reverse(xBytes);
            Array.Reverse(yBytes);

            var x = new BigInteger(1, xBytes);
            var y = new BigInteger(1, yBytes);
            var point = curve.CreatePoint(x, y);
            var domainParams = new ECDomainParameters(
                ecParams.Curve, ecParams.G, ecParams.N, ecParams.H);
            var pubKeyParams = new ECPublicKeyParameters(
                "ECGOST3410-2012",
                point,
                domainParams);

            var signer = new ECGost3410Signer();
            signer.Init(false, pubKeyParams);

            // Hash the data
            digest.BlockUpdate(data, 0, data.Length);
            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            // GOST signature: r || s in little-endian, each halfLen bytes
            var sigHalf = sigBytes.Length / 2;
            var sBytes = new byte[sigHalf];
            var rBytes = new byte[sigHalf];
            Array.Copy(sigBytes, 0, sBytes, 0, sigHalf);
            Array.Copy(sigBytes, sigHalf, rBytes, 0, sigHalf);
            Array.Reverse(sBytes);
            Array.Reverse(rBytes);

            var r = new BigInteger(1, rBytes);
            var s = new BigInteger(1, sBytes);

            return signer.VerifySignature(hash, r, s);
        }
        catch (Exception ex)
        {
            Logging.LogDebug($"I2PSignature: GOST verification failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    ///     Sign with GOST R 34.10-2012 (256-bit or 512-bit).
    ///     Uses BouncyCastle's ECGOST3410 signer with Streebog hash.
    /// </summary>
    public static byte[] DoSignGost(IEnumerable<I2PByteBlock> bufs, I2PSigningPrivateKey key, int bits)
    {
        var keyBytes = key.Key.ToByteArray();
        var data = bufs.SelectMany(b => b.ToByteArray()).ToArray();

        DerObjectIdentifier curveOid;
        IDigest digest;
        int sigSize;

        if (bits == 256)
        {
            curveOid = ECGost3410NamedCurves.GetOid("Tc26-Gost-3410-12-256-paramSetA");
            digest = new Gost3411_2012_256Digest();
            sigSize = 64;
        }
        else
        {
            curveOid = ECGost3410NamedCurves.GetOid("Tc26-Gost-3410-12-512-paramSetA");
            digest = new Gost3411_2012_512Digest();
            sigSize = 128;
        }

        var ecParams = ECGost3410NamedCurves.GetByOid(curveOid);
        var domainParams = new ECDomainParameters(
            ecParams.Curve, ecParams.G, ecParams.N, ecParams.H);

        // GOST private key is stored in little-endian
        var dBytes = new byte[keyBytes.Length];
        Array.Copy(keyBytes, dBytes, keyBytes.Length);
        Array.Reverse(dBytes); // Convert to big-endian for BouncyCastle
        var d = new BigInteger(1, dBytes);

        var privKeyParams = new ECPrivateKeyParameters(
            "ECGOST3410-2012", d, domainParams);

        // Hash the data
        digest.BlockUpdate(data, 0, data.Length);
        var hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);

        var signer = new ECGost3410Signer();
        signer.Init(true, new ParametersWithRandom(privKeyParams));

        var sig = signer.GenerateSignature(hash);
        var result = new byte[sigSize];

        // GOST signature: s || r in little-endian, each sigSize/2 bytes
        var halfLen = sigSize / 2;
        var rBytes = sig[0].ToByteArrayUnsigned();
        var sBytes = sig[1].ToByteArrayUnsigned();

        // Pad and reverse to little-endian
        var rPadded = new byte[halfLen];
        var sPadded = new byte[halfLen];
        Array.Copy(rBytes, 0, rPadded, halfLen - rBytes.Length, rBytes.Length);
        Array.Copy(sBytes, 0, sPadded, halfLen - sBytes.Length, sBytes.Length);
        Array.Reverse(rPadded);
        Array.Reverse(sPadded);

        // Format: s || r (little-endian)
        Array.Copy(sPadded, 0, result, 0, halfLen);
        Array.Copy(rPadded, 0, result, halfLen, halfLen);

        return result;
    }

    /// <summary>
    ///     ML-DSA-44 (FIPS 204) signing using BouncyCastle.
    ///     Public key: 1312 bytes, Signature: 2420 bytes, Private key: 2560 bytes.
    /// </summary>
    public static byte[] DoSignMlDsa44(IEnumerable<I2PByteBlock> bufs, I2PSigningPrivateKey key)
    {
        var keyBytes = key.Key.ToByteArray();
        var privKeyParams = MLDsaPrivateKeyParameters.FromEncoding(
            MLDsaParameters.ml_dsa_44, keyBytes);

        var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_44, false);
        signer.Init(true, privKeyParams);

        var data = bufs.SelectMany(b => b.ToByteArray()).ToArray();
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    /// <summary>
    ///     ML-DSA-44 (FIPS 204) verification using BouncyCastle.
    /// </summary>
    public static bool DoVerifyMlDsa44(IEnumerable<I2PByteBlock> bufs, I2PSigningPublicKey key, I2PSignature signed)
    {
        try
        {
            var keyBytes = key.Key.ToByteArray();
            var pubKeyParams = MLDsaPublicKeyParameters.FromEncoding(
                MLDsaParameters.ml_dsa_44, keyBytes);

            var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_44, false);
            signer.Init(false, pubKeyParams);

            var data = bufs.SelectMany(b => b.ToByteArray()).ToArray();
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signed.Sig.ToByteArray());
        }
        catch (Exception ex)
        {
            Logging.LogDebug($"I2PSignature: ML-DSA-44 verification failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    ///     Generate ML-DSA-44 random key pair.
    /// </summary>
    public static (byte[] publicKey, byte[] privateKey) CreateMlDsa44RandomKeys()
    {
        var random = new SecureRandom();
        var keyGenParams = new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_44);
        var keyPairGenerator = new MLDsaKeyPairGenerator();
        keyPairGenerator.Init(keyGenParams);

        var keyPair = keyPairGenerator.GenerateKeyPair();

        var pubKeyParams = (MLDsaPublicKeyParameters)keyPair.Public;
        var privKeyParams = (MLDsaPrivateKeyParameters)keyPair.Private;

        return (pubKeyParams.GetEncoded(), privKeyParams.GetEncoded());
    }

    public override string ToString()
    {
        return $"I2PSignature: {FreenetBase64.Encode(new I2PByteBlock(Sig.ToByteArray()))}";
    }
}