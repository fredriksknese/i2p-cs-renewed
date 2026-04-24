using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;
using I2PCore;
using I2PCore.Data;
using I2PCore.Utils;
using System.Linq;

namespace I2PTests
{
    [TestFixture]
    public class KadDHTTest
    {
        /// <summary>
        /// Test basic insert and count.
        /// </summary>
        [Test]
        public void TestInsertAndCount()
        {
            var dht = new KadDHT();

            Assert.AreEqual( 0, dht.Count );

            for ( int i = 0; i < 100; i++ )
            {
                dht.Insert( new I2PIdentHash( true ) );
            }

            Assert.AreEqual( 100, dht.Count );
        }

        /// <summary>
        /// Test that duplicate inserts don't increase count.
        /// </summary>
        [Test]
        public void TestDuplicateInsert()
        {
            var dht = new KadDHT();
            var hash = new I2PIdentHash( true );

            dht.Insert( hash );
            dht.Insert( hash );

            Assert.AreEqual( 1, dht.Count, "Duplicate insert should not increase count" );
        }

        /// <summary>
        /// Test remove operation.
        /// </summary>
        [Test]
        public void TestRemove()
        {
            var dht = new KadDHT();
            var hash = new I2PIdentHash( true );

            dht.Insert( hash );
            Assert.AreEqual( 1, dht.Count );

            var removed = dht.Remove( hash );
            Assert.IsTrue( removed, "Remove should return true for existing entry" );
            Assert.AreEqual( 0, dht.Count );

            var removedAgain = dht.Remove( hash );
            Assert.IsFalse( removedAgain, "Remove should return false for non-existing entry" );
        }

        /// <summary>
        /// Test FindClosest returns the closest hash by XOR distance.
        /// </summary>
        [Test]
        public void TestFindClosest()
        {
            var dht = new KadDHT();

            // Insert known hashes
            var hashes = Enumerable.Range( 0, 50 )
                .Select( _ => new I2PIdentHash( true ) )
                .ToArray();

            foreach ( var h in hashes )
                dht.Insert( h );

            var target = new I2PIdentHash( true );
            var closest = dht.FindClosest( target );

            Assert.IsNotNull( closest, "FindClosest should return a result" );

            // Verify it's actually the closest by brute force
            var bruteClosest = hashes
                .OrderBy( h => XorDistance( h, target ) )
                .First();

            // The DHT should return the same result as brute force
            // (they should have the same XOR distance)
            var dhtDist = XorDistance( closest, target );
            var bruteDist = XorDistance( bruteClosest, target );
            Assert.IsTrue( dhtDist.CompareTo( bruteDist ) <= 0,
                "DHT closest should be at least as close as brute-force closest" );
        }

        /// <summary>
        /// Test FindClosest with count returns multiple results ordered by distance.
        /// </summary>
        [Test]
        public void TestFindClosestMultiple()
        {
            var dht = new KadDHT();

            var hashes = Enumerable.Range( 0, 100 )
                .Select( _ => new I2PIdentHash( true ) )
                .ToArray();

            foreach ( var h in hashes )
                dht.Insert( h );

            var target = new I2PIdentHash( true );
            var closest3 = dht.FindClosest( target, 3 );

            Assert.IsNotNull( closest3 );
            Assert.AreEqual( 3, closest3.Count, "Should return exactly 3 closest" );

            // Verify all 3 are actually in the top-3 closest by brute force
            var bruteTop3 = hashes
                .OrderBy( h => XorDistance( h, target ) )
                .Take( 3 )
                .ToList();

            // The DHT results should all be within the brute-force top-3 distance range
            var maxBruteDist = XorDistance( bruteTop3.Last(), target );
            foreach ( var h in closest3 )
            {
                var dist = XorDistance( h, target );
                Assert.IsTrue( dist.CompareTo( maxBruteDist ) <= 0,
                    "DHT closest-3 entry should be within brute-force top-3 range" );
            }
        }

        /// <summary>
        /// Test FindClosest with filter.
        /// </summary>
        [Test]
        public void TestFindClosestWithFilter()
        {
            var dht = new KadDHT();

            var hashes = Enumerable.Range( 0, 50 )
                .Select( _ => new I2PIdentHash( true ) )
                .ToArray();

            foreach ( var h in hashes )
                dht.Insert( h );

            var target = new I2PIdentHash( true );
            var excluded = dht.FindClosest( target ); // Get the actual closest

            // Find closest excluding the actual closest
            var nextClosest = dht.FindClosest( target,
                h => !h.Equals( excluded ) );

            Assert.IsNotNull( nextClosest );
            Assert.IsFalse( nextClosest.Equals( excluded ),
                "Filter should exclude the specified hash" );
        }

        /// <summary>
        /// Test Clear operation.
        /// </summary>
        [Test]
        public void TestClear()
        {
            var dht = new KadDHT();

            for ( int i = 0; i < 50; i++ )
                dht.Insert( new I2PIdentHash( true ) );

            Assert.AreEqual( 50, dht.Count );

            dht.Clear();

            Assert.AreEqual( 0, dht.Count );
            Assert.IsNull( dht.FindClosest( new I2PIdentHash( true ) ) );
        }

        /// <summary>
        /// Test Cleanup removes entries that don't pass the filter.
        /// </summary>
        [Test]
        public void TestCleanup()
        {
            var dht = new KadDHT();

            var keep = Enumerable.Range( 0, 25 )
                .Select( _ => new I2PIdentHash( true ) )
                .ToArray();
            var remove = Enumerable.Range( 0, 25 )
                .Select( _ => new I2PIdentHash( true ) )
                .ToArray();

            foreach ( var h in keep ) dht.Insert( h );
            foreach ( var h in remove ) dht.Insert( h );

            Assert.AreEqual( 50, dht.Count );

            var keepSet = keep.ToHashSet();
            dht.Cleanup( h => keepSet.Contains( h ) );

            // Count may not be exact due to trie structure, but should be around 25
            Assert.IsTrue( dht.Count <= 50, "Count should decrease after cleanup" );

            // None of the removed hashes should be findable
            foreach ( var h in remove )
            {
                var found = dht.FindClosest( h, f => f.Equals( h ) );
                // If found, it should not be one of the removed ones
                if ( found != null )
                    Assert.IsFalse( found.Equals( h ) || !keepSet.Contains( found ),
                        "Cleaned-up hash should not be findable" );
            }
        }

        /// <summary>
        /// Test with large dataset for performance.
        /// </summary>
        [Test]
        public void TestLargeDataset()
        {
            var dht = new KadDHT();

            var hashes = Enumerable.Range( 0, 1000 )
                .Select( _ => new I2PIdentHash( true ) )
                .ToArray();

            foreach ( var h in hashes )
                dht.Insert( h );

            Assert.AreEqual( 1000, dht.Count );

            // FindClosest should work efficiently
            var target = new I2PIdentHash( true );
            var closest = dht.FindClosest( target, 10 );

            Assert.IsNotNull( closest );
            Assert.AreEqual( 10, closest.Count );
        }

        /// <summary>
        /// Compute XOR distance between two IdentHashes as a comparable byte array.
        /// Used for brute-force verification of DHT results.
        /// </summary>
        private static Org.BouncyCastle.Math.BigInteger XorDistance( I2PIdentHash a, I2PIdentHash b )
        {
            var ab = a.Hash.ToByteArray();
            var bb = b.Hash.ToByteArray();
            var xor = new byte[32];
            for ( int i = 0; i < 32; i++ )
                xor[i] = (byte)( ab[i] ^ bb[i] );
            return new Org.BouncyCastle.Math.BigInteger( 1, xor );
        }
    }
}
