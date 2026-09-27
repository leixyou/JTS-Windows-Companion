using System.IO;
using System.Text;

namespace JTS.WindowsCompanion.UnattendedSetup;

internal static class EnrollmentCodeInput
{
    internal const int MaximumCharacters = 4096;
    internal static async Task<string> ReadAsync(TextReader reader, CancellationToken token)
    {
        var text = new StringBuilder(); var buffer = new char[1];
        while (await reader.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false) != 0)
        {
            if (buffer[0] == '\n') break;
            if (text.Length == MaximumCharacters || buffer[0] == '\0') throw new ArgumentException("ENROLLMENT_CODE_INVALID");
            text.Append(buffer[0]);
        }
        var code = text.ToString().Trim();
        if (code.Length == 0) throw new ArgumentException("ENROLLMENT_CODE_INVALID");
        return code;
    }
}
