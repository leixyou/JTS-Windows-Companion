using System.Runtime.InteropServices;
using Xunit;

namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

public sealed class AccountContractTests
{
    private static readonly Guid Enrollment = Guid.Parse("aabbccdd-eeff-4012-8123-123456789abc");
    private const string Sid = "S-1-5-21-123-456-789-1100";

    [Fact]
    public void PasswordIsBoundedTerminatedAndHasAllFourComplexityClasses()
    {
        using var password = AccountPassword.Create();
        Assert.Equal(48, AccountPassword.CharacterCount);
        Assert.True(password.Pointer != IntPtr.Zero);
        var upper = false; var lower = false; var digit = false; var symbol = false;
        for (var i = 0; i < AccountPassword.CharacterCount; i++)
        {
            var character = (char)Marshal.ReadInt16(password.Pointer, i * sizeof(char));
            // Assertions carry only booleans, never password characters or a copied secret string.
            Assert.True(character is >= '!' and <= '~');
            Assert.True("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+-.:;<=>?@[]^_{|}~".Contains(character));
            upper |= char.IsAsciiLetterUpper(character); lower |= char.IsAsciiLetterLower(character);
            digit |= char.IsAsciiDigit(character); symbol |= !char.IsAsciiLetterOrDigit(character);
        }
        Assert.True(upper && lower && digit && symbol);
        Assert.True(Marshal.ReadInt16(password.Pointer, AccountPassword.CharacterCount * sizeof(char)) == 0);
    }

    [Fact]
    public void PasswordBuffersAndValuesAreIndependent()
    {
        using var first = AccountPassword.Create(); using var second = AccountPassword.Create();
        Assert.True(first.Pointer != second.Pointer);
        var different = false;
        for (var i = 0; i < AccountPassword.CharacterCount; i++)
            different |= Marshal.ReadInt16(first.Pointer, i * sizeof(char)) != Marshal.ReadInt16(second.Pointer, i * sizeof(char));
        Assert.True(different);
        first.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { _ = first.Pointer; });
        Assert.True(second.Pointer != IntPtr.Zero);
    }

    [Fact]
    public void DisposalIsIdempotentAndNeverReexposesTheReleasedBuffer()
    {
        var password = AccountPassword.Create(); password.Dispose(); password.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { _ = password.Pointer; });
        // Reading freed memory to "prove" zeroization would itself be unsafe. This checks lifetime only.
    }

    [Theory]
    [InlineData("authority", "JTS25A_aabbccddeeff")]
    [InlineData("worker", "JTS25W_aabbccddeeff")]
    public void AccountNamesAreDistinctDedicatedLocalSamNames(string role, string name)
    {
        Assert.Equal(name, LocalAccountIdentity.AccountName(Enrollment, role));
        Assert.Equal(19, name.Length);
        var identity = new LocalAccountIdentity(name, Sid, Enrollment, role);
        identity.Validate();
        Assert.Equal($"JTS.Companion25/v1/{Enrollment:D}/{role}", identity.Marker);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Authority")]
    [InlineData("worker ")]
    [InlineData("admin")]
    public void UnknownNoncanonicalOrMissingRolesAreRejected(string? role)
    {
        Invalid(() => LocalAccountIdentity.AccountName(Enrollment, role!));
        Invalid(() => new LocalAccountIdentity("JTS25A_aabbccddeeff", Sid, Enrollment, role!).Validate());
    }

    [Fact]
    public void EmptyEnrollmentAndCrossRoleOrCrossEnrollmentNameAreRejected()
    {
        Invalid(() => LocalAccountIdentity.AccountName(Guid.Empty, "authority"));
        Invalid(() => (Identity() with { EnrollmentId = Guid.Empty }).Validate());
        Invalid(() => (Identity() with { EnrollmentId = Guid.Parse("11223344-5566-4012-8123-123456789abc") }).Validate());
        Invalid(() => (Identity() with { Role = "worker" }).Validate());
    }

    [Theory]
    [InlineData(null)]
    [InlineData(".\\JTS25A_aabbccddeeff")]
    [InlineData("JTS25A_AABBCCDDEEFF")]
    [InlineData("jts25a_aabbccddeeff")]
    [InlineData("JTS25A_aabbccddeeff ")]
    [InlineData("Administrator")]
    public void AccountNameMustMatchCanonicalEnrollmentDerivedValue(string? name)
        => Invalid(() => (Identity() with { Name = name! }).Validate());

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-21-123-456-789-500")]
    [InlineData("S-1-5-21-123-456-789-999")]
    [InlineData("S-1-5-21-0123-456-789-1100")]
    [InlineData("S-1-5-21-123-456-789-01100")]
    [InlineData("S-1-5-21-123-456-789-4294967296")]
    [InlineData("S-1-5-21-123-456-789-1100-1")]
    [InlineData("S-1-5-21-123-456-789-1100 ")]
    [InlineData("s-1-5-21-123-456-789-1100")]
    public void SidMustBeCanonicalAndNotWellKnownOrBuiltIn(string? sid)
        => Invalid(() => (Identity() with { Sid = sid! }).Validate());

    [Fact]
    public void MarkerBindsFullEnrollmentEvenWhenTruncatedNamesCollide()
    {
        var first = Identity();
        var second = first with { EnrollmentId = Guid.Parse("aabbccdd-eeff-4012-8123-123456789abd") };
        first.Validate(); second.Validate();
        Assert.Equal(first.Name, LocalAccountIdentity.AccountName(second.EnrollmentId, second.Role));
        Assert.NotEqual(first.Marker, second.Marker);
        // Native ownership also checks the recorded SID; this portable test does not prove local SAM membership.
    }

    private static LocalAccountIdentity Identity() => new(LocalAccountIdentity.AccountName(Enrollment, "authority"), Sid, Enrollment, "authority");
    private static void Invalid(Action action) => Assert.Equal("INSTALL_ACCOUNT_IDENTITY_INVALID",
        Assert.Throws<UnattendedInstallationException>(action).Code);
}
