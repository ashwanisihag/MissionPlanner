namespace MissionPlanner.GCSViews.ConfigurationView
{
    /// <summary>
    /// Full Parameter List — same as ConfigRawParams but with the tree panel hidden.
    /// </summary>
    public class ConfigRawParamsList : ConfigRawParams
    {
        public ConfigRawParamsList()
        {
            HideTree = true;
        }
    }
}
