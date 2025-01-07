using System;
using System.Threading.Tasks;
using AltitudeAngelWings.Model;

namespace AltitudeAngelWings.Service.Messaging
{
    public class MessagesService : IMessagesService
    {
        private readonly IMessageDisplay _messageDisplay;

        public MessagesService(IMessageDisplay messageDisplay)
        {
            _messageDisplay = messageDisplay;
        }

        public Task AddMessageAsync(Message message) => Task.Factory.StartNew(async () =>
        {

            try
            {
                _messageDisplay.AddMessage(message);
                if(message.Content.Contains("POI:"))
                {
                    if(!message.Content.Contains("POI: vehicle pos unavailable") && !message.Content.Contains("POI: failed to get terrain al") && !message.Content.Contains("POI: vehicle pos unavailable"))
                    {
                        message.Content = message.Content + "My :";
                        _messageDisplay.AddMessage(message);
                    }
                    else
                    {
                        message.Content = message.Content + "Wrong :";
                        _messageDisplay.AddMessage(message);
                    }
                }
                do
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(200)).ConfigureAwait(false);
                } while (!message.HasExpired());
            }
            finally
            {
                _messageDisplay.RemoveMessage(message);
            }
        });
    }
}
