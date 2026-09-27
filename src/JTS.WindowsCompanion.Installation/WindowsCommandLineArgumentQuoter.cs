using System.Text;

namespace JTS.WindowsCompanion.Setup;

internal static class WindowsCommandLineArgumentQuoter
{
    public static string Quote(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var result = new StringBuilder(value.Length + 2);
        result.Append('"');
        var pendingBackslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                pendingBackslashes += 1;
                continue;
            }

            if (character == '"')
            {
                result.Append('\\', (pendingBackslashes * 2) + 1);
                result.Append('"');
                pendingBackslashes = 0;
                continue;
            }

            result.Append('\\', pendingBackslashes);
            pendingBackslashes = 0;
            result.Append(character);
        }

        result.Append('\\', pendingBackslashes * 2);
        result.Append('"');
        return result.ToString();
    }
}
