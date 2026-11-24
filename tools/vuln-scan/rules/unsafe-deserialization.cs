// Semgrep rule test fixture (run: semgrep --test tools/vuln-scan/rules). Not compiled.
public class Importer
{
    public object Load(Stream input)
    {
        // ruleid: insecure-formatter-deserialization
        var formatter = new BinaryFormatter();

        // ruleid: insecure-formatter-deserialization
        var other = new System.Runtime.Serialization.NetDataContractSerializer();

        var settings = new JsonSerializerSettings
        {
            // ruleid: newtonsoft-typenamehandling
            TypeNameHandling = TypeNameHandling.Auto
        };

        // ruleid: newtonsoft-typenamehandling
        settings.TypeNameHandling = TypeNameHandling.All;

        // ok: newtonsoft-typenamehandling
        settings.TypeNameHandling = TypeNameHandling.None;

        // ruleid: javascriptserializer-type-resolver
        var js = new JavaScriptSerializer(new SimpleTypeResolver());

        // ok: insecure-formatter-deserialization
        var safe = new XmlSerializer(typeof(Order));

        return null;
    }
}
