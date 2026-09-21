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
using System.Collections.Generic;

namespace Kp2aAutofillParser
{
  /// <summary>
  /// Prototype: how precisely the URL of an entry matches the searched host.
  /// </summary>
  /// <remarks>
  /// The shipped implementation answers only yes/no per search phase (see the phase
  /// chain in keepass2android.ShareUrlResults.GetSearchResultsForUrl), so the caller
  /// cannot tell an exact host match from a match on a parent domain, and the first
  /// phase that returns anything hides the more precise phases. Ranks make that
  /// information explicit and would allow the caller to decide which ranks to return
  /// (and in which order) instead of relying on the phase order.
  ///
  /// This branch is an exploration, not a change of the search behavior.
  /// </remarks>
  public enum UrlMatchRank
  {
    None = 0,
    /// <summary>Any field of the entry contains the searched text (last resort).</summary>
    TextAnyField = 1,
    /// <summary>A URL value contains the searched text without a host relation.</summary>
    TextInUrlValue = 2,
    /// <summary>The hosts are parent and child of each other.</summary>
    DomainRelation = 3,
    /// <summary>The hosts are equal (after IDN normalization).</summary>
    Host = 4,
    /// <summary>A URL value contains the complete searched URL.</summary>
    Url = 5
  }

  /// <summary>
  /// Prototype of the rank based decisions, see UrlMatchRank.
  /// </summary>
  public static class UrlMatchRankPolicy
  {
    /// <summary>
    /// Returns the rank of an entry whose URL host refers to the searched host.
    /// </summary>
    public static UrlMatchRank RankHostMatch(string queryHost, string entryHost, bool allowSubdomains)
    {
      if (String.IsNullOrWhiteSpace(queryHost))
        return UrlMatchRank.None;

      string normalizedEntryHost = UrlHostMatching.NormalizeHost(entryHost);
      if (String.IsNullOrEmpty(normalizedEntryHost))
        return UrlMatchRank.None;
      if (allowSubdomains && normalizedEntryHost.StartsWith("www.", StringComparison.Ordinal))
        normalizedEntryHost = normalizedEntryHost.Substring(4);

      string normalizedQueryHost = UrlHostMatching.NormalizeHost(queryHost);
      if (String.Equals(normalizedQueryHost, normalizedEntryHost, StringComparison.OrdinalIgnoreCase))
        return UrlMatchRank.Host;
      if (normalizedQueryHost.EndsWith("." + normalizedEntryHost, StringComparison.OrdinalIgnoreCase))
        return UrlMatchRank.DomainRelation;
      return UrlMatchRank.None;
    }

    /// <summary>
    /// Returns the highest rank of the given candidates, None if there is none.
    /// </summary>
    public static UrlMatchRank Best(IEnumerable<UrlMatchRank> ranks)
    {
      UrlMatchRank best = UrlMatchRank.None;
      foreach (UrlMatchRank rank in ranks)
      {
        if (rank > best)
          best = rank;
      }
      return best;
    }

    /// <summary>
    /// Returns whether an entry with the given rank should be returned when the best
    /// rank of the search is <paramref name="bestRank"/>.
    /// </summary>
    /// <param name="includeDomainRelation">
    /// true: return exact host matches together with matches on a parent domain (the
    /// currently shipped phases 2/3 behavior). false: return only the most precise
    /// rank, which hides the parent domain entries as soon as a host match exists.
    /// </param>
    public static bool IsIncluded(UrlMatchRank rank, UrlMatchRank bestRank, bool includeDomainRelation)
    {
      if (bestRank == UrlMatchRank.None)
        return false;
      if (rank == bestRank)
        return true;
      return includeDomainRelation
        && bestRank == UrlMatchRank.Host
        && rank == UrlMatchRank.DomainRelation;
    }
  }
}
