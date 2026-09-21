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

using System;
using System.Globalization;

namespace Kp2aAutofillParser
{
  /// <summary>
  /// Pure host matching, free of Android and KeePassLib references so that it can be unit
  /// tested (see Kp2aAutofillParser.Tests/UrlHostMatchingTest.cs).
  /// </summary>
  public static class UrlHostMatching
  {
    private static readonly IdnMapping s_idnMapping = new IdnMapping();

    /// <summary>
    /// Returns the host in ASCII (punycode) notation.
    /// </summary>
    /// Browsers and the autofill framework pass hosts in punycode notation
    /// (e.g. "xn--rhqv03d5th68cnuv.top") while entries often contain the Unicode
    /// notation (e.g. "爱来自世界.top"). Both notations denote the same host and
    /// must be treated as equal when matching URLs.
    public static string NormalizeHost(string host)
    {
      if (String.IsNullOrEmpty(host))
        return host;

      try
      {
        return s_idnMapping.GetAscii(host);
      }
      catch (ArgumentException)
      {
        // Not a valid domain name (invalid characters, labels longer than 63
        // characters, ...): compare it as it is.
        return host;
      }
    }

    /// <summary>
    /// Returns whether the host of an entry's URL refers to the host that was searched
    /// for, either exactly or as one of its parent domains.
    /// </summary>
    public static bool HostsMatch(string queryHost, string entryHost, bool allowSubdomains)
    {
      if (String.IsNullOrWhiteSpace(queryHost))
        return false;

      string normalizedEntryHost = NormalizeHost(entryHost);
      if (String.IsNullOrEmpty(normalizedEntryHost))
        return false;

      if (allowSubdomains && normalizedEntryHost.StartsWith("www.", StringComparison.Ordinal))
        normalizedEntryHost = normalizedEntryHost.Substring(4); //remove "www."
      if (String.IsNullOrWhiteSpace(normalizedEntryHost))
        return false;

      string normalizedQueryHost = NormalizeHost(queryHost);
      return String.Equals(normalizedQueryHost, normalizedEntryHost, StringComparison.OrdinalIgnoreCase)
        || normalizedQueryHost.EndsWith("." + normalizedEntryHost, StringComparison.OrdinalIgnoreCase);
    }
  }
}
