namespace JTS.WindowsCompanion.UnattendedSetup;

internal static class RelayOriginInput
{
    internal static bool TryNormalize(string? input, out string origin)
    {
        origin = string.Empty;
        var text = input?.Trim();
        if (text is not { Length: >= 1 and <= 2048 } || text.Any(c => char.IsControl(c) || c == '\\')
            || !Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme != "https"
            || uri.UserInfo.Length != 0 || uri.AbsolutePath != "/" || uri.Query.Length != 0 || uri.Fragment.Length != 0)
            return false;
        origin = uri.AbsoluteUri;
        return true;
    }
}
