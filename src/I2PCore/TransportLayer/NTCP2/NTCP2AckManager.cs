using System;
using System.Collections.Generic;

namespace I2PCore.TransportLayer.NTCP2
{
    /// <summary>
    /// Manages message tracking and reliability for NTCP2
    /// NTCP2 is TCP-based so retransmission is handled by TCP,
    /// but we still need message sequencing and flow control
    /// </summary>
    public class NTCP2AckManager
    {
        /// <summary>
        /// Next message ID to assign for outgoing messages
        /// </summary>
        private uint NextMessageId = 1;

        /// <summary>
        /// Tracks received message IDs to detect duplicates
        /// </summary>
        private HashSet<uint> ReceivedMessageIds = new HashSet<uint>();

        /// <summary>
        /// Tracks sent messages awaiting acknowledgment (if needed)
        /// </summary>
        private Dictionary<uint, PendingMessage> PendingMessages = new Dictionary<uint, PendingMessage>();

        /// <summary>
        /// Maximum number of pending messages before applying backpressure
        /// </summary>
        private const int MAX_PENDING_MESSAGES = 100;

        public class PendingMessage
        {
            public uint MessageId;
            public DateTime SentTime;
            public byte[] MessageData;
        }

        /// <summary>
        /// Get next message ID for outgoing message
        /// </summary>
        public uint GetNextMessageId()
        {
            var id = NextMessageId;
            NextMessageId++;
            return id;
        }

        /// <summary>
        /// Record a sent message
        /// </summary>
        public void RecordSent(uint messageId, byte[] messageData)
        {
            PendingMessages[messageId] = new PendingMessage
            {
                MessageId = messageId,
                SentTime = DateTime.UtcNow,
                MessageData = (byte[])messageData.Clone()
            };

            // Clean up old pending messages (older than 60 seconds)
            CleanupOldPending();
        }

        /// <summary>
        /// Check if a received message ID is a duplicate
        /// </summary>
        public bool IsDuplicate(uint messageId)
        {
            return ReceivedMessageIds.Contains(messageId);
        }

        /// <summary>
        /// Record a received message
        /// </summary>
        public void RecordReceived(uint messageId)
        {
            ReceivedMessageIds.Add(messageId);

            // Limit size of received set
            if (ReceivedMessageIds.Count > 10000)
            {
                // Remove oldest half (approximate)
                var toRemove = new List<uint>();
                int count = 0;
                foreach (var id in ReceivedMessageIds)
                {
                    if (count++ > 5000)
                        break;
                    toRemove.Add(id);
                }
                foreach (var id in toRemove)
                {
                    ReceivedMessageIds.Remove(id);
                }
            }
        }

        /// <summary>
        /// Remove acknowledged message
        /// </summary>
        public void RemovePending(uint messageId)
        {
            PendingMessages.Remove(messageId);
        }

        /// <summary>
        /// Check if we should apply backpressure
        /// </summary>
        public bool ShouldApplyBackpressure()
        {
            return PendingMessages.Count >= MAX_PENDING_MESSAGES;
        }

        /// <summary>
        /// Clean up old pending messages
        /// </summary>
        private void CleanupOldPending()
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-60);
            var toRemove = new List<uint>();

            foreach (var kvp in PendingMessages)
            {
                if (kvp.Value.SentTime < cutoff)
                {
                    toRemove.Add(kvp.Key);
                }
            }

            foreach (var id in toRemove)
            {
                PendingMessages.Remove(id);
            }
        }

        /// <summary>
        /// Get count of pending messages
        /// </summary>
        public int PendingCount => PendingMessages.Count;
    }
}
