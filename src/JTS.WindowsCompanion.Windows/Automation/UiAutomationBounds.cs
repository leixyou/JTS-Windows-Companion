using JTS.WindowsCompanion.Automation;

namespace JTS.WindowsCompanion.Windows.Automation;

internal static class UiAutomationBounds
{
    public static UiaBounds FromProvider(double x, double y, double width, double height)
    {
        // UIA returns Rect.Empty for elements without a displayed rectangle.
        // WPF encodes it with infinities, which JSON cannot represent. A zero
        // area conveys unavailable geometry without inventing a clickable box.
        if (!double.IsFinite(x) || !double.IsFinite(y)
            || !double.IsFinite(width) || !double.IsFinite(height)
            || width < 0 || height < 0)
        {
            return new UiaBounds(0, 0, 0, 0);
        }

        return new UiaBounds(x, y, width, height);
    }
}
