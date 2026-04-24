using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.ECIES
{
    /// <summary>
    /// ECIES ACK Handler
    /// Manages acknowledgments for reliable message delivery
    ///
    /// Tracks sent messages and processes ACKs
    /// Handles retransmission of unacknowledged messages
    /// </summary>
    public class ECIESAckHandler
    {
        private readonly ConcurrentDictionary<uint, PendingMessage> _pendingMessages;
        private readonly ConcurrentDictionary<I2PIdentHash, DestinationAckState> _destinationStates;

        // Configuration
        private const int MaxRetransmissions = 3;
        private const int RetransmissionTimeoutSeconds = 30;
        private const int AckTimeoutSeconds = 60;

        public ECIESAckHandler()
        {
            _pendingMessages = new ConcurrentDictionary<uint, PendingMessage>();
            _destinationStates = new ConcurrentDictionary<I2PIdentHash, DestinationAckState>();
        }

        /// <summary>
        /// Track a sent message that requires acknowledgment
        /// </summary>
        public void TrackMessage(
            uint messageId,
            I2PIdentHash destination,
            byte[] messageData)
        {
            if (destination == null)
                throw new ArgumentNullException(nameof(destination));

            if (messageData == null)
                throw new ArgumentNullException(nameof(messageData));

            var pending = new PendingMessage
            {
                MessageId = messageId,
                Destination = destination,
                MessageData = messageData,
                SentTime = DateTime.UtcNow,
                RetransmissionCount = 0
            };

            _pendingMessages.TryAdd(messageId, pending);

            // Update destination state
            var state = _destinationStates.GetOrAdd(destination, _ => new DestinationAckState());
            state.LastMessageId = messageId;
        }

        /// <summary>
        /// Process an ACK for messages
        /// </summary>
        public AckProcessingResult ProcessAck(I2PIdentHash destination, uint ackThrough)
        {
            if (destination == null)
                throw new ArgumentNullException(nameof(destination));

            var result = new AckProcessingResult
            {
                AckedMessages = new List<uint>()
            };

            // Get destination state
            if (_destinationStates.TryGetValue(destination, out var state))
            {
                state.LastAckReceived = DateTime.UtcNow;
                state.LastAckThrough = ackThrough;
            }

            // Find all messages up to and including ackThrough
            var toRemove = _pendingMessages
                .Where(kvp => kvp.Value.Destination.Equals(destination) && kvp.Key <= ackThrough)
                .Select(kvp => kvp.Key)
                .ToList();

            // Remove acknowledged messages
            foreach (var messageId in toRemove)
            {
                if (_pendingMessages.TryRemove(messageId, out _))
                {
                    result.AckedMessages.Add(messageId);
                }
            }

            result.Success = true;
            return result;
        }

        /// <summary>
        /// Get messages that need retransmission
        /// </summary>
        public List<PendingMessage> GetMessagesForRetransmission()
        {
            var now = DateTime.UtcNow;
            var toRetransmit = new List<PendingMessage>();

            foreach (var kvp in _pendingMessages)
            {
                var pending = kvp.Value;

                // Check if message has timed out
                if ((now - pending.SentTime).TotalSeconds > RetransmissionTimeoutSeconds)
                {
                    // Check if we haven't exceeded max retransmissions
                    if (pending.RetransmissionCount < MaxRetransmissions)
                    {
                        pending.RetransmissionCount++;
                        pending.SentTime = now;
                        toRetransmit.Add(pending);
                    }
                    else
                    {
                        // Give up on this message
                        _pendingMessages.TryRemove(kvp.Key, out _);
                    }
                }
            }

            return toRetransmit;
        }

        /// <summary>
        /// Create an ACK block for a destination
        /// </summary>
        public AckBlock CreateAckBlock(I2PIdentHash destination)
        {
            if (destination == null)
                throw new ArgumentNullException(nameof(destination));

            if (_destinationStates.TryGetValue(destination, out var state))
            {
                var block = new AckBlock();
                block.Acks.Add((0, (ushort)(state.LastMessageId & 0xFFFF)));
                return block;
            }

            return null;
        }

        /// <summary>
        /// Check if a message is pending acknowledgment
        /// </summary>
        public bool IsPending(uint messageId)
        {
            return _pendingMessages.ContainsKey(messageId);
        }

        /// <summary>
        /// Get count of pending messages for a destination
        /// </summary>
        public int GetPendingCount(I2PIdentHash destination)
        {
            if (destination == null)
                return 0;

            return _pendingMessages
                .Count(kvp => kvp.Value.Destination.Equals(destination));
        }

        /// <summary>
        /// Clean up expired messages
        /// </summary>
        public void CleanupExpired()
        {
            var now = DateTime.UtcNow;

            // Remove messages that have exceeded ACK timeout
            var expired = _pendingMessages
                .Where(kvp => (now - kvp.Value.SentTime).TotalSeconds > AckTimeoutSeconds)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var messageId in expired)
            {
                _pendingMessages.TryRemove(messageId, out _);
            }

            // Clean up old destination states
            var expiredStates = _destinationStates
                .Where(kvp => (now - kvp.Value.LastAckReceived).TotalMinutes > 30)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var dest in expiredStates)
            {
                _destinationStates.TryRemove(dest, out _);
            }
        }

        /// <summary>
        /// Get statistics
        /// </summary>
        public AckStatistics GetStatistics()
        {
            return new AckStatistics
            {
                PendingMessages = _pendingMessages.Count,
                TrackedDestinations = _destinationStates.Count,
                TotalRetransmissions = _pendingMessages.Values.Sum(p => p.RetransmissionCount)
            };
        }
    }

    /// <summary>
    /// Pending message awaiting acknowledgment
    /// </summary>
    public class PendingMessage
    {
        public uint MessageId { get; set; }
        public I2PIdentHash Destination { get; set; }
        public byte[] MessageData { get; set; }
        public DateTime SentTime { get; set; }
        public int RetransmissionCount { get; set; }
    }

    /// <summary>
    /// ACK state for a destination
    /// </summary>
    internal class DestinationAckState
    {
        public uint LastMessageId { get; set; }
        public uint LastAckThrough { get; set; }
        public DateTime LastAckReceived { get; set; }

        public DestinationAckState()
        {
            LastAckReceived = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Result of processing an ACK
    /// </summary>
    public class AckProcessingResult
    {
        public bool Success { get; set; }
        public List<uint> AckedMessages { get; set; }
        public string Error { get; set; }
    }

    /// <summary>
    /// ACK statistics
    /// </summary>
    public class AckStatistics
    {
        public int PendingMessages { get; set; }
        public int TrackedDestinations { get; set; }
        public int TotalRetransmissions { get; set; }

        public override string ToString()
        {
            return $"ACK Stats: Pending={PendingMessages}, Destinations={TrackedDestinations}, Retrans={TotalRetransmissions}";
        }
    }
}
