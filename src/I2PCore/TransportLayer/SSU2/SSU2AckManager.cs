using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     Manages ACK generation and retransmission for SSU2 packets
///     Per spec lines 1458-1650: ACK blocks contain packet number ranges
/// </summary>
public class SSU2AckManager
{
    // Maximum delay before sending ACK (spec line 1508)
    private const int MAX_ACK_DELAY_MS = 500;

    // Maximum retransmission attempts (spec line 1588)
    private const int MAX_RETRANSMIT_ATTEMPTS = 3;

    // RTO (Retransmission Timeout) initial value (spec line 1591)
    private const int INITIAL_RTO_MS = 1000;

    // Maximum RTO value
    private const int MAX_RTO_MS = 60000;

    /// <summary>
    ///     Tracks received packet numbers for ACK generation
    /// </summary>
    private readonly SortedSet<uint> ReceivedPackets = new();

    /// <summary>
    ///     Tracks packets sent but not yet acknowledged
    /// </summary>
    private readonly Dictionary<uint, PendingPacket> UnackedPackets = new();

    /// <summary>
    ///     Current RTO value (adaptive)
    /// </summary>
    private int CurrentRTO = INITIAL_RTO_MS;

    /// <summary>
    ///     Highest packet number we've sent ACK for
    /// </summary>
    private uint HighestAckedReceive;

    /// <summary>
    ///     Time of last ACK sent
    /// </summary>
    private DateTime LastAckSent = DateTime.MinValue;

    /// <summary>
    ///     RTT variance for RTO calculation
    /// </summary>
    private double RTTVariance = INITIAL_RTO_MS / 2;

    /// <summary>
    ///     Smoothed RTT for RTO calculation
    /// </summary>
    private double SmoothedRTT = INITIAL_RTO_MS;

    /// <summary>
    ///     Check if there are unacknowledged packets
    /// </summary>
    public bool HasUnackedPackets => UnackedPackets.Count > 0;

    /// <summary>
    ///     Get count of unacknowledged packets
    /// </summary>
    public int UnackedCount => UnackedPackets.Count;

    /// <summary>
    ///     Record a received packet for ACK generation
    /// </summary>
    public void RecordReceived(uint packetNumber)
    {
        ReceivedPackets.Add(packetNumber);
    }

    /// <summary>
    ///     Record a sent packet for retransmission tracking
    /// </summary>
    public void RecordSent(uint packetNumber, byte[] packetData)
    {
        var now = DateTime.UtcNow;
        UnackedPackets[packetNumber] = new PendingPacket
        {
            PacketNumber = packetNumber,
            PacketData = (byte[])packetData.Clone(),
            SentTime = now,
            RetransmitCount = 0,
            NextRetransmitTime = now.AddMilliseconds(CurrentRTO)
        };
    }

    /// <summary>
    ///     Process received ACK block and remove acknowledged packets
    ///     Spec lines 1458-1507: ACK block format
    /// </summary>
    public void ProcessAck(SSU2AckBlock ackBlock)
    {
        var ackedPackets = new List<uint>();

        // Process ACK ranges
        foreach (var range in ackBlock.AckRanges)
            for (var pn = range.Start; pn <= range.End; pn++)
                if (UnackedPackets.TryGetValue(pn, out var pending))
                {
                    // Calculate RTT for this packet
                    var rtt = (DateTime.UtcNow - pending.SentTime).TotalMilliseconds;
                    UpdateRTO(rtt);

                    ackedPackets.Add(pn);
                }

        // Remove acknowledged packets
        foreach (var pn in ackedPackets) UnackedPackets.Remove(pn);
    }

    /// <summary>
    ///     Update RTO using exponential weighted moving average (spec line 1593-1596)
    /// </summary>
    private void UpdateRTO(double measuredRTT)
    {
        // SRTT = 7/8 * SRTT + 1/8 * RTT
        SmoothedRTT = 0.875 * SmoothedRTT + 0.125 * measuredRTT;

        // RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - RTT|
        RTTVariance = 0.75 * RTTVariance + 0.25 * Math.Abs(SmoothedRTT - measuredRTT);

        // RTO = SRTT + 4 * RTTVAR
        CurrentRTO = (int)Math.Min(SmoothedRTT + 4 * RTTVariance, MAX_RTO_MS);
        CurrentRTO = Math.Max(CurrentRTO, INITIAL_RTO_MS);
    }

    /// <summary>
    ///     Check if we need to send an ACK
    /// </summary>
    public bool NeedsSendAck()
    {
        if (ReceivedPackets.Count == 0)
            return false;

        // Send ACK if we have new packets and enough time has passed
        var timeSinceLastAck = DateTime.UtcNow - LastAckSent;
        return timeSinceLastAck.TotalMilliseconds >= MAX_ACK_DELAY_MS;
    }

    /// <summary>
    ///     Generate ACK block from received packets (spec lines 1458-1507)
    ///     ACK format: 1-byte ACK count, then for each ACK:
    ///     4-byte packet number through (big endian)
    ///     1-byte ACK count (number of additional contiguous packets)
    /// </summary>
    public SSU2AckBlock GenerateAck()
    {
        if (ReceivedPackets.Count == 0)
            return null;

        var ranges = new List<AckRange>();
        uint rangeStart = 0;
        uint rangeEnd = 0;
        var inRange = false;

        foreach (var pn in ReceivedPackets)
            if (!inRange)
            {
                // Start new range
                rangeStart = pn;
                rangeEnd = pn;
                inRange = true;
            }
            else if (pn == rangeEnd + 1)
            {
                // Extend current range
                rangeEnd = pn;
            }
            else
            {
                // Gap found, save current range and start new one
                ranges.Add(new AckRange { Start = rangeStart, End = rangeEnd });
                rangeStart = pn;
                rangeEnd = pn;
            }

        // Add last range
        if (inRange) ranges.Add(new AckRange { Start = rangeStart, End = rangeEnd });

        HighestAckedReceive = ReceivedPackets.Max();
        LastAckSent = DateTime.UtcNow;

        return new SSU2AckBlock { AckRanges = ranges };
    }

    /// <summary>
    ///     Get packets that need retransmission
    /// </summary>
    public List<PendingPacket> GetPacketsNeedingRetransmit()
    {
        var now = DateTime.UtcNow;
        var toRetransmit = new List<PendingPacket>();

        foreach (var pending in UnackedPackets.Values)
            if (now >= pending.NextRetransmitTime)
            {
                if (pending.RetransmitCount < MAX_RETRANSMIT_ATTEMPTS)
                {
                    pending.RetransmitCount++;
                    pending.SentTime = now;
                    pending.NextRetransmitTime = now.AddMilliseconds(CurrentRTO * (1 << pending.RetransmitCount));
                    toRetransmit.Add(pending);
                }
                else
                {
                    // Max retransmits exceeded - this will be cleaned up by caller
                    toRetransmit.Add(pending);
                }
            }

        return toRetransmit;
    }

    /// <summary>
    ///     Remove packet from tracking (failed permanently)
    /// </summary>
    public void RemovePacket(uint packetNumber)
    {
        UnackedPackets.Remove(packetNumber);
    }

    public class PendingPacket
    {
        public DateTime NextRetransmitTime;
        public byte[] PacketData;
        public uint PacketNumber;
        public int RetransmitCount;
        public DateTime SentTime;
    }
}

/// <summary>
///     Represents a range of acknowledged packet numbers
/// </summary>
public class AckRange
{
    public uint End;
    public uint Start;

    public int Count => (int)(End - Start + 1);
}

/// <summary>
///     ACK block for inclusion in Data packets (spec lines 1458-1507)
/// </summary>
public class SSU2AckBlock
{
    public List<AckRange> AckRanges = new();

    /// <summary>
    ///     Serialize ACK block to bytes
    ///     Format: 1-byte count, then for each range:
    ///     4-byte "through" (end of range, big endian)
    ///     1-byte "ACKs" (additional packets in range, 0 = 1 packet)
    /// </summary>
    public byte[] Serialize()
    {
        if (AckRanges.Count == 0)
            return new byte[1]; // Just the count byte = 0

        var result = new List<byte>();
        result.Add((byte)Math.Min(AckRanges.Count, 255));

        foreach (var range in AckRanges.Take(255))
        {
            // 4-byte "through" (packet number at end of range)
            var throughBytes = BufUtils.Flip32B(range.End);
            result.AddRange(throughBytes);

            // 1-byte "ACKs" (additional packets: count - 1)
            result.Add((byte)Math.Min(range.Count - 1, 255));
        }

        return result.ToArray();
    }

    /// <summary>
    ///     Parse ACK block from bytes
    /// </summary>
    public static SSU2AckBlock Parse(I2PBufferCursor data)
    {
        var ackCount = data.ReadByte();
        var ranges = new List<AckRange>();

        for (var i = 0; i < ackCount; i++)
        {
            var through = data.ReadUInt32BigEndian();
            var acks = data.ReadByte();

            // "through" is the end, "acks" is count-1
            var end = through;
            var start = end - acks;

            ranges.Add(new AckRange { Start = start, End = end });
        }

        return new SSU2AckBlock { AckRanges = ranges };
    }
}