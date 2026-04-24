using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;

namespace I2PCore
{
    /// <summary>
    /// The type of NetDb lookup request.
    /// </summary>
    public enum NetDbRequestType
    {
        RouterInfo,
        LeaseSet,
        Exploratory
    }

    /// <summary>
    /// Tracks the state of an individual NetDb lookup request,
    /// modeled after i2pd's RequestedDestination.
    /// </summary>
    public class NetDbRequest
    {
        public I2PIdentHash Key { get; }
        public DateTime CreationTime { get; }
        public DateTime LastRequestTime { get; set; }
        public int NumAttempts { get; set; }
        public NetDbRequestType RequestType { get; }
        public HashSet<I2PIdentHash> ExcludedPeers { get; } = new();
        public bool IsComplete { get; set; }

        public NetDbRequest( I2PIdentHash key, NetDbRequestType requestType )
        {
            Key = key ?? throw new ArgumentNullException( nameof( key ) );
            RequestType = requestType;
            CreationTime = DateTime.UtcNow;
            LastRequestTime = DateTime.MinValue;
            NumAttempts = 0;
            IsComplete = false;
        }

        /// <summary>
        /// Returns true if the request has exceeded MAX_NUM_REQUEST_ATTEMPTS.
        /// </summary>
        public bool IsExhausted =>
            NumAttempts >= NetDbRequests.MAX_NUM_REQUEST_ATTEMPTS;

        /// <summary>
        /// Returns true if the request has lived longer than
        /// REQUEST_RECORD_EXPIRATION_TIMEOUT seconds.
        /// </summary>
        public bool IsExpired =>
            ( DateTime.UtcNow - CreationTime ).TotalSeconds
                >= NetDbRequests.REQUEST_RECORD_EXPIRATION_TIMEOUT;

        /// <summary>
        /// Returns true if enough time has passed since the last attempt
        /// to allow a retry (MIN_REQUEST_TIME seconds).
        /// </summary>
        public bool IsRetryAllowed =>
            LastRequestTime == DateTime.MinValue
            || ( DateTime.UtcNow - LastRequestTime ).TotalSeconds
                >= NetDbRequests.MIN_REQUEST_TIME;

        /// <summary>
        /// Record that an attempt was made right now, and add the queried
        /// peer to the excluded set.
        /// </summary>
        public void RecordAttempt( I2PIdentHash queriedPeer )
        {
            LastRequestTime = DateTime.UtcNow;
            NumAttempts++;
            if ( queriedPeer != null )
                ExcludedPeers.Add( queriedPeer );
        }
    }

    /// <summary>
    /// Manages outstanding NetDb lookup requests, modeled after
    /// i2pd's NetDbRequests / RequestedDestination classes.
    /// </summary>
    public class NetDbRequests
    {
        /// <summary>
        /// Maximum number of retry attempts per request before giving up.
        /// Matches i2pd MAX_NUM_REQUEST_ATTEMPTS (raised to 7 for the
        /// tunnel-based retry strategy used in this implementation).
        /// </summary>
        public const int MAX_NUM_REQUEST_ATTEMPTS = 7;

        /// <summary>
        /// Seconds after creation before a request record is considered
        /// expired and removed.
        /// </summary>
        public const int REQUEST_RECORD_EXPIRATION_TIMEOUT = 60;

        /// <summary>
        /// Minimum seconds between retry attempts for a single request.
        /// </summary>
        public const int MIN_REQUEST_TIME = 5;

        /// <summary>
        /// Retry timeout in seconds: if no response within this window
        /// the request is eligible for retry.
        /// </summary>
        public const int RETRY_TIMEOUT = 7;

        /// <summary>
        /// Upper bound on concurrently active requests.
        /// </summary>
        public const int MAX_ACTIVE_REQUESTS = 64;

        private readonly ConcurrentDictionary<I2PIdentHash, NetDbRequest> ActiveRequests = new();

        /// <summary>
        /// Number of currently tracked requests.
        /// </summary>
        public int Count => ActiveRequests.Count;

        /// <summary>
        /// Create and register a new lookup request for <paramref name="key"/>.
        /// Returns the new request, or null if a request for that key already
        /// exists or the maximum number of active requests has been reached.
        /// </summary>
        public NetDbRequest CreateRequest( I2PIdentHash key, NetDbRequestType type )
        {
            if ( key == null ) throw new ArgumentNullException( nameof( key ) );

            if ( ActiveRequests.Count >= MAX_ACTIVE_REQUESTS )
                return null;

            var request = new NetDbRequest( key, type );
            return ActiveRequests.TryAdd( key, request ) ? request : null;
        }

        /// <summary>
        /// Mark the request for <paramref name="key"/> as complete and
        /// remove it from the active set.
        /// </summary>
        public bool RequestComplete( I2PIdentHash key )
        {
            if ( key == null ) return false;

            if ( ActiveRequests.TryRemove( key, out var request ) )
            {
                request.IsComplete = true;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Returns true if there is an active (non-complete) request
        /// for the given key.
        /// </summary>
        public bool HasRequest( I2PIdentHash key )
        {
            return key != null && ActiveRequests.ContainsKey( key );
        }

        /// <summary>
        /// Gets the set of peers already queried for <paramref name="key"/>,
        /// or an empty set if no such request exists.
        /// </summary>
        public HashSet<I2PIdentHash> GetExcludedPeers( I2PIdentHash key )
        {
            if ( key != null && ActiveRequests.TryGetValue( key, out var request ) )
                return request.ExcludedPeers;

            return new HashSet<I2PIdentHash>();
        }

        /// <summary>
        /// Try to retrieve the active request for the given key.
        /// </summary>
        public bool TryGetRequest( I2PIdentHash key, out NetDbRequest request )
        {
            request = null;
            return key != null && ActiveRequests.TryGetValue( key, out request );
        }

        /// <summary>
        /// Periodic maintenance: retries requests whose last attempt
        /// was more than RETRY_TIMEOUT seconds ago (if retry is allowed),
        /// removes expired or exhausted requests, and respects the
        /// MAX_ACTIVE_REQUESTS cap.
        ///
        /// Returns the list of requests that are eligible for a new
        /// send attempt so the caller can dispatch them.
        /// </summary>
        public IList<NetDbRequest> ManageRequests()
        {
            var now = DateTime.UtcNow;
            var retryList = new List<NetDbRequest>();

            foreach ( var kvp in ActiveRequests )
            {
                var request = kvp.Value;

                // Remove completed, expired, or exhausted requests
                if ( request.IsComplete || request.IsExpired || request.IsExhausted )
                {
                    ActiveRequests.TryRemove( kvp.Key, out _ );
                    continue;
                }

                // Check if enough time has passed since last attempt for a retry
                bool needsRetry = request.LastRequestTime == DateTime.MinValue
                    || ( now - request.LastRequestTime ).TotalSeconds >= RETRY_TIMEOUT;

                if ( needsRetry && request.IsRetryAllowed )
                {
                    retryList.Add( request );
                }
            }

            return retryList;
        }
    }
}
