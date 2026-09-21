// This file is part of Keepass2Android, Copyright 2025 Philipp Crocoll.
//
//   Keepass2Android is free software: you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.
//
//   Keepass2Android is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with Keepass2Android.  If not, see <http://www.gnu.org/licenses/>.

using Kp2aAutofillParser;

namespace Kp2aAutofillParserTest
{
  /// <summary>
  /// Tests for the host matching used by the autofill code path: the host of a web page
  /// is passed in punycode notation by the autofill framework, while the entry usually
  /// contains the Unicode notation (and vice versa).
  /// </summary>
  public class UrlHostMatchingTest
  {
    // The host of https://tinyauth.oracle-noddy.爱来自世界.top:18081 as the
    // autofill framework reports it (punycode, no scheme/port/path).
    private const string PunycodeHost = "tinyauth.oracle-noddy.xn--rhqv03d5th68cnuv.top";
    private const string UnicodeHost = "tinyauth.oracle-noddy.爱来自世界.top";

    [Theory]
    [InlineData(PunycodeHost, UnicodeHost)]
    [InlineData(UnicodeHost, PunycodeHost)]
    [InlineData(PunycodeHost, PunycodeHost)]
    [InlineData(UnicodeHost, UnicodeHost)]
    public void HostsMatchIgnoresTheIdnNotation(string queryHost, string entryHost)
    {
      Assert.True(UrlHostMatching.HostsMatch(queryHost, entryHost, false));
      Assert.True(UrlHostMatching.HostsMatch(queryHost, entryHost, true));
    }

    [Theory]
    [InlineData("tinyauth.oracle-noddy.xn--rhqv03d5th68cnuv.top", "爱来自世界.top")]
    [InlineData("tinyauth.oracle-noddy.爱来自世界.top", "xn--rhqv03d5th68cnuv.top")]
    public void HostsMatchAcceptsAParentDomainInAnotherIdnNotation(string queryHost, string entryHost)
    {
      Assert.True(UrlHostMatching.HostsMatch(queryHost, entryHost, false));
    }

    [Fact]
    public void HostsMatchAcceptsTheParentDomainOfTheSearchedHost()
    {
      Assert.True(UrlHostMatching.HostsMatch("accounts.google.com", "google.com", false));
      Assert.True(UrlHostMatching.HostsMatch("sub.example.com", "example.com", false));
    }

    [Fact]
    public void HostsMatchDoesNotAcceptAChildDomainOfTheSearchedHost()
    {
      Assert.False(UrlHostMatching.HostsMatch("example.com", "sub.example.com", false));
    }

    [Fact]
    public void HostsMatchDoesNotAcceptAHostWithTheSameSuffix()
    {
      // regression guard for the phishing issue #1926 ("x.com" must not match "examplex.com")
      Assert.False(UrlHostMatching.HostsMatch("example.com", "examplex.com", false));
      Assert.False(UrlHostMatching.HostsMatch("x.com", "examplex.com", false));
    }

    [Fact]
    public void HostsMatchTreatsHostsCaseInsensitively()
    {
      Assert.True(UrlHostMatching.HostsMatch("EXAMPLE.com", "example.COM", false));
      Assert.True(UrlHostMatching.HostsMatch("Www.Example.COM", "www.example.com", false));
    }

    [Fact]
    public void HostsMatchRemovesWwwFromAnIdnHostAsWell()
    {
      // the "www." is removed after normalizing, so both notations behave the same
      Assert.True(UrlHostMatching.HostsMatch("xn--rhqv03d5th68cnuv.top", "www.爱来自世界.top", true));
      Assert.True(UrlHostMatching.HostsMatch("爱来自世界.top", "www.xn--rhqv03d5th68cnuv.top", true));
      Assert.False(UrlHostMatching.HostsMatch("xn--rhqv03d5th68cnuv.top", "www.爱来自世界.top", false));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void HostsMatchOnlyRemovesWwwWhenSubdomainsAreAllowed(bool allowSubdomains, bool expected)
    {
      Assert.Equal(expected, UrlHostMatching.HostsMatch("example.com", "www.example.com", allowSubdomains));
    }

    [Fact]
    public void HostsMatchHandlesIpAddresses()
    {
      Assert.True(UrlHostMatching.HostsMatch("192.168.188.2", "192.168.188.2", false));
      Assert.False(UrlHostMatching.HostsMatch("192.168.188.2", "192.168.188.3", false));
    }

    [Fact]
    public void HostsMatchKeepsHostsWithInvalidDomainCharactersComparable()
    {
      // IdnMapping throws for these; they must still match themselves
      Assert.True(UrlHostMatching.HostsMatch("_dmarc.example.com", "_dmarc.example.com", false));
      Assert.True(UrlHostMatching.HostsMatch("some_host", "some_host", false));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void HostsMatchRejectsAnEmptyEntryHost(string entryHost)
    {
      Assert.False(UrlHostMatching.HostsMatch("example.com", entryHost, true));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void HostsMatchRejectsAnEmptySearchedHost(string queryHost)
    {
      Assert.False(UrlHostMatching.HostsMatch(queryHost, "example.com", true));
    }

    [Fact]
    public void NormalizeHostReturnsThePunycodeNotation()
    {
      Assert.Equal("xn--rhqv03d5th68cnuv.top", UrlHostMatching.NormalizeHost("爱来自世界.top"));
      Assert.Equal("xn--rhqv03d5th68cnuv.top", UrlHostMatching.NormalizeHost("xn--rhqv03d5th68cnuv.top"));
      Assert.Equal("example.com", UrlHostMatching.NormalizeHost("example.com"));
      Assert.Equal("192.168.188.2", UrlHostMatching.NormalizeHost("192.168.188.2"));
      Assert.Equal("_dmarc.example.com", UrlHostMatching.NormalizeHost("_dmarc.example.com"));
      Assert.Equal("", UrlHostMatching.NormalizeHost(""));
    }
  }
}
