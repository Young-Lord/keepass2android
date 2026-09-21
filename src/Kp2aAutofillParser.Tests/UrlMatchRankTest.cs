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
  /// Tests for the rank prototype: what the search would return if the caller could
  /// distinguish the precision of a match instead of taking the first non-empty phase.
  /// </summary>
  public class UrlMatchRankTest
  {
    // The scenario from the bug report: the page host is passed in punycode, the entry
    // "tiny" stores the Unicode notation (plus the punycode host in KP2A_URL_1) and the
    // entry "sub1" is about the parent domain.
    private const string PageHost = "tinyauth.oracle-noddy.xn--rhqv03d5th68cnuv.top";
    private const string TinyHost = "tinyauth.oracle-noddy.爱来自世界.top";
    private const string Sub1Host = "oracle-noddy.xn--rhqv03d5th68cnuv.top";

    [Fact]
    public void RankOfAnExactHostMatchIsHost()
    {
      Assert.Equal(UrlMatchRank.Host, UrlMatchRankPolicy.RankHostMatch(PageHost, TinyHost, false));
      Assert.Equal(UrlMatchRank.Host, UrlMatchRankPolicy.RankHostMatch(PageHost, PageHost, false));
    }

    [Fact]
    public void RankOfAParentDomainMatchIsDomainRelation()
    {
      Assert.Equal(UrlMatchRank.DomainRelation, UrlMatchRankPolicy.RankHostMatch(PageHost, Sub1Host, false));
      Assert.Equal(UrlMatchRank.DomainRelation, UrlMatchRankPolicy.RankHostMatch("sub.example.com", "example.com", false));
    }

    [Fact]
    public void UnrelatedHostsHaveNoRank()
    {
      Assert.Equal(UrlMatchRank.None, UrlMatchRankPolicy.RankHostMatch("example.com", "examplex.com", false));
      Assert.Equal(UrlMatchRank.None, UrlMatchRankPolicy.RankHostMatch("example.com", "", false));
      Assert.Equal(UrlMatchRank.None, UrlMatchRankPolicy.RankHostMatch("", "example.com", false));
    }

    [Fact]
    public void BestRankIsTheMostPreciseOne()
    {
      Assert.Equal(UrlMatchRank.Host,
        UrlMatchRankPolicy.Best(new[]
        {
          UrlMatchRankPolicy.RankHostMatch(PageHost, Sub1Host, false),
          UrlMatchRankPolicy.RankHostMatch(PageHost, TinyHost, false)
        }));
      Assert.Equal(UrlMatchRank.DomainRelation, UrlMatchRankPolicy.Best(new[] { UrlMatchRank.None, UrlMatchRank.DomainRelation }));
      Assert.Equal(UrlMatchRank.None, UrlMatchRankPolicy.Best(new[] { UrlMatchRank.None }));
    }

    [Fact]
    public void StrictPolicyReturnsOnlyTheMostPreciseRank()
    {
      const bool strict = false;
      UrlMatchRank best = UrlMatchRank.Host;

      Assert.True(UrlMatchRankPolicy.IsIncluded(UrlMatchRank.Host, best, strict));
      Assert.False(UrlMatchRankPolicy.IsIncluded(UrlMatchRank.DomainRelation, best, strict));
      Assert.False(UrlMatchRankPolicy.IsIncluded(UrlMatchRank.TextInUrlValue, best, strict));
      Assert.False(UrlMatchRankPolicy.IsIncluded(UrlMatchRank.None, best, strict));
    }

    [Fact]
    public void RelaxedPolicyAddsTheParentDomainMatches()
    {
      const bool withDomainRelation = true;
      UrlMatchRank best = UrlMatchRank.Host;

      Assert.True(UrlMatchRankPolicy.IsIncluded(UrlMatchRank.Host, best, withDomainRelation));
      Assert.True(UrlMatchRankPolicy.IsIncluded(UrlMatchRank.DomainRelation, best, withDomainRelation));
      Assert.False(UrlMatchRankPolicy.IsIncluded(UrlMatchRank.TextInUrlValue, best, withDomainRelation));
    }

    [Fact]
    public void TheReportedScenarioWouldReturnOnlyTheHostMatchWhenStrict()
    {
      var entries = new (string title, string host)[]
      {
        ("sub1", Sub1Host),
        ("tiny", TinyHost),
      };

      var ranks = new System.Collections.Generic.Dictionary<string, UrlMatchRank>();
      foreach (var entry in entries)
        ranks[entry.title] = UrlMatchRankPolicy.RankHostMatch(PageHost, entry.host, false);

      UrlMatchRank best = UrlMatchRankPolicy.Best(ranks.Values);

      Assert.Equal(UrlMatchRank.Host, best);
      Assert.Equal(UrlMatchRank.DomainRelation, ranks["sub1"]);  // parent domain: phase 2
      Assert.Equal(UrlMatchRank.Host, ranks["tiny"]);            // same host: phase 2
      // the entry the user wants is the precise one and would be listed first
      Assert.True(ranks["tiny"] > ranks["sub1"]);
    }
  }
}
