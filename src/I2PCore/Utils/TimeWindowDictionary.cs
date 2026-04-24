using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace I2PCore.Utils
{
    public class TimeWindowDictionary<T, TV> : IDisposable, IEnumerable<KeyValuePair<T, TV>> where TV : class
    {
        private TickSpan MemorySpan;

        private ConcurrentDictionary<T, KeyValuePair<TV, TickCounter>> Memory = new();

        private TickCounter LastCleanup = TickCounter.Now;

        public int SecondsBetweenCleanup { get; set; } = 240;

        public TimeWindowDictionary( TickSpan span )
        {
            MemorySpan = span;
        }

        public TV this[T key]
        {
            get { return Get( key ); }
            set { Set( key, value ); }
        }

        internal void Clear()
        {
            Memory.Clear();
        }

        public bool IsEmpty
        {
            get
            {
                Cleanup();
                return Memory.IsEmpty;
            }
        }

        public int Count
        {
            get
            {
                Cleanup();
                return Memory.Count;
            }
        }

        private void CheckCleanupTimeout()
        {
            if ( LastCleanup.DeltaToNowSeconds > SecondsBetweenCleanup )
            {
                Cleanup();
            }
        }

        public void Set( T ident, TV value )
        {
            CheckCleanupTimeout();

            RemoveAndDispose( ident );
            Memory[ident] = new KeyValuePair<TV, TickCounter>( value, TickCounter.Now );
        }

        public void Touch( T ident )
        {
            CheckCleanupTimeout();

            if ( Memory.TryGetValue( ident, out var pair ) )
            {
                pair.Value.SetNow();
            }
        }

        public bool TryGetValue( T ident, out TV value )
        {
            CheckCleanupTimeout();

            if ( Memory.TryGetValue( ident, out var pair ) )
            {
                if ( pair.Value.DeltaToNow > MemorySpan )
                {
                    RemoveAndDispose( ident );
                    value = null;
                    return false;
                }

                value = pair.Key;
                return true;
            }

            value = null;
            return false;
        }

        /// <summary>
        /// Returns null if item have not been stored or is too old.
        /// </summary>
        public TV Get( T ident )
        {
            CheckCleanupTimeout();

            if ( Memory.TryGetValue( ident, out var pair ) )
            {
                if ( pair.Value.DeltaToNow > MemorySpan )
                {
                    RemoveAndDispose( ident );
                    return null;
                }
                return pair.Key;
            }

            return null;
        }

        public bool Remove( T ident )
        {
            CheckCleanupTimeout();
            return RemoveAndDispose( ident );
        }

        protected bool RemoveAndDispose( T ident )
        {
            var result = Memory.TryRemove( ident, out var removed );

            if ( result )
            {
                if ( removed.Key is IDisposable )
                {
                    ( (IDisposable)removed.Key ).Dispose();
                }
                if ( removed.Value is IDisposable )
                {
                    ( (IDisposable)removed.Value ).Dispose();
                }
            } 

            return result;
        }

        public bool TryRemove( T ident, out TV value )
        {
            CheckCleanupTimeout();

            var result = Memory.TryRemove( ident, out var removed );

            if ( result )
            {
                if ( removed.Key is IDisposable )
                {
                    ( (IDisposable)removed.Key ).Dispose();
                }
            } 

            value = result ? removed.Key : default( TV );
            return result;
        }

        public TV Get( T ident, Func<TV> generator )
        {
            var result = Get( ident );
            if ( result != null ) return result;
            result = generator();
            Set( ident, result );
            return result;
        }

        public void ProcessItem( T key, Action<T,TV> action )
        {
            if ( Memory.TryGetValue( key, out var pair ) )
            {
                action( key, pair.Key );
            }
        }

        private void Cleanup()
        {
            LastCleanup.SetNow();

            foreach ( var identpair in Memory.ToArray() )
            {
                if ( identpair.Value.Value.DeltaToNow > MemorySpan )
                {
                    RemoveAndDispose( identpair.Key );
                }
            }
        }

        public class ItemWithCreationTime<TK,TW>
        {
            public TK Key { get; protected set; }
            public TW Value { get; protected set; }
            public TickCounter Created { get; protected set; }

            public ItemWithCreationTime( TK key, TW value, TickCounter created )
            {
                Key = key;
                Value = value;
                Created = created;
            }
        }

        public IEnumerable<ItemWithCreationTime<T,TV>> ItemsWithCreationTime()
        {
            Cleanup();
            foreach( var one in Memory.ToArray() )
            {
                yield return new ItemWithCreationTime<T,TV>( one.Key, one.Value.Key, one.Value.Value );
            }
        }

        #region IEnumerable<KeyValuePair<T,V>> Members
        public IEnumerator<KeyValuePair<T, TV>> GetEnumerator()
        {
            Cleanup();
            return Memory
                .AsEnumerable()
                .Select( p => new KeyValuePair<T, TV>( p.Key, p.Value.Key ) )
                .GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            Cleanup();
            return Memory
                    .AsEnumerable()
                    .Select( p => new KeyValuePair<T, TV>( p.Key, p.Value.Key ) )
                    .GetEnumerator();
        }

        void IDisposable.Dispose()
        {
            foreach ( var identpair in Memory.ToArray() )
            {
                RemoveAndDispose( identpair.Key );
            }
        }
        #endregion
    }
}
