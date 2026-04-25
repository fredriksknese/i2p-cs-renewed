using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PCore.TunnelLayer.I2NP
{
    public static class I2NpUtil
    {
        public static I2NpMessage GetMessage(
                I2NpMessage.MessageTypes messagetype,
                I2PBufferCursor reader,
                uint? msgid = null )
        {
            I2NpMessage result = null;

            try
            {
                switch ( messagetype )
                {
                    case I2NpMessage.MessageTypes.Garlic:
                        result = new GarlicMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.Data:
                        result = new DataMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.DatabaseSearchReply:
                        result = new DatabaseSearchReplyMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.DatabaseStore:
                        result = new DatabaseStoreMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.DeliveryStatus:
                        result = new DeliveryStatusMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.TunnelData:
                        result = new TunnelDataMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.TunnelGateway:
                        result = new TunnelGatewayMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.DatabaseLookup:
                        result = new DatabaseLookupMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.VariableTunnelBuild:
                        result = new VariableTunnelBuildMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.TunnelBuild:
                        result = new TunnelBuildMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.TunnelBuildReply:
                        result = new TunnelBuildReplyMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.VariableTunnelBuildReply:
                        result = new VariableTunnelBuildReplyMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.ShortTunnelBuild:
                        result = new ShortTunnelBuildMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.ShortTunnelBuildReply:
                        result = new ShortTunnelBuildReplyMessage( reader );
                        break;

                    case I2NpMessage.MessageTypes.TunnelTest:
                        result = new TunnelTestMessage( reader );
                        break;

                    default:
                        Logging.LogWarning( $"GetMessage: '{messagetype}' is not a known message type, skipping." );
                        return null;
                }
            }
            catch ( Exception ex )
            {
                Logging.Log( "GetMessage", ex );
                return null;
            }

            if ( result != null && msgid.HasValue )
            {
                result.MessageId = msgid.Value;
            }

            return result;
        }
    }
}
