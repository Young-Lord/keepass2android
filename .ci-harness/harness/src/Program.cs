using System;
using System.Collections.Generic;
using System.Linq;
using KeePassLib;
using KeePassLib.Security;
using KeePassLib.Utility;
using keepass2android;

namespace harness
{
  /// <summary>
  /// Compiles the real src/Kp2aBusinessLogic/SearchDbHelper.cs and drives it the way
  /// ShareUrlResults.GetSearchResultsForUrl does (five phases, first non-empty wins,
  /// per database), so the autofill candidate list can be inspected branch by branch.
  /// </summary>
  static class Program
  {
    static readonly SearchDbHelper Helper = new SearchDbHelper(new StubApp());

    /// <summary>Mirror of ShareUrlResults.GetSearchResultsForUrl for a single database.</summary>
    static PwGroup GetSearchResultsForUrl(Database db, string url)
    {
      PwGroup resultsForThisDb = db.SearchForExactUrl(url);

      if (!url.StartsWith(AndroidAppConstants.Scheme, StringComparison.OrdinalIgnoreCase))
      {
        if (!resultsForThisDb.Entries.Any())
          resultsForThisDb = db.SearchForHost(url, false);
        if (!resultsForThisDb.Entries.Any())
          resultsForThisDb = db.SearchForHost(url, true);
      }

      if (!resultsForThisDb.Entries.Any())
        resultsForThisDb = db.SearchForText(url);
      if (!resultsForThisDb.Entries.Any())
        resultsForThisDb = db.SearchForText(UrlUtil.GetHost(url.Trim()));

      return resultsForThisDb;
    }

    static PwGroup Results(Database db, string url)
    {
      return GetSearchResultsForUrl(db, url);
    }

    static Database MakeDb()
    {
      var db = new Database();
      db.KpDatabase = new PwDatabase();
      db.Root = new PwGroup(true, true, "root", PwIcon.Folder);
      return db;
    }

    static PwEntry Add(Database db, string title, params (string field, string value)[] fields)
    {
      var e = new PwEntry(true, true);
      e.Strings.Set(PwDefs.TitleField, new ProtectedString(false, title));
      foreach (var (field, value) in fields)
        e.Strings.Set(field, new ProtectedString(field.StartsWith("KP2A") || field.StartsWith("AndroidApp"), value));
      db.Root.AddEntry(e, true);
      db.EntriesById[e.Uuid] = e;
      return e;
    }

    static string Titles(PwGroup g)
    {
      if (g == null) return "<null>";
      string titles = string.Join(", ", g.Entries.Select(e => e.Strings.ReadSafe(PwDefs.TitleField)));
      return titles.Length == 0 ? "<none>" : titles;
    }

    // ---- the user's scenario -------------------------------------------------

    const string PageHost = "tinyauth.oracle-noddy.xn--rhqv03d5th68cnuv.top";
    const string Query = PageHost;

    static Database ScenarioDb()
    {
      var db = MakeDb();
      Add(db, "sub1", (PwDefs.UrlField, "https://oracle-noddy.xn--rhqv03d5th68cnuv.top:18081/sub"));
      Add(db, "tiny",
          (PwDefs.UrlField, "tinyauth.oracle-noddy.爱来自世界.top"),
          ("KP2A_URL_1", PageHost));
      return db;
    }

    // ---- regression matrix ---------------------------------------------------

    static void Matrix()
    {
      // branchDependent: true for the rows the IDN fix changes (they mismatch on
      // branches without it), false for the rows that must hold on every branch.
      var rows = new (string query, string urlValue, bool expectHost, bool expectHostNoSub, bool branchDependent)[]
      {
        // query, entry URL value, SearchForHost(false) hits, SearchForHost(true) hits
        (PageHost, "tinyauth.oracle-noddy.爱来自世界.top", true, true, true),           // IDN
        (PageHost, "爱来自世界.top", true, true, true),                                  // IDN parent
        ("xn--rhqv03d5th68cnuv.top", "爱来自世界.top", true, true, true),                 // IDN other direction
        ("sub.example.com", "example.com", true, true, false),
        ("sub.example.com", "https://examplex.com", false, false, false),
        ("192.168.188.2", "192.168.188.2", true, true, false),
        ("192.168.188.2", "https://192.168.188.3", false, false, false),
        ("example.com", "https://www.example.com", false, true, false),                   // www. stripped only when allowSubdomains
        ("accounts.google.com", "https://google.com:443/x", true, true, false),
        ("accounts.google.com", "https://accounts.google.com", true, true, false),
        ("example.com", "https://example.com:8443", true, true, false),                  // port ignored
        ("_dmarc.example.com", "_dmarc.example.com", true, true, false),                 // underscore host
        ("example.com", "", false, false, false),                                        // empty URL
        ("example.com", "kdbx://c:/data/abc.kdbx", false, false, false),                 // file path
      };

      Console.WriteLine("query | entry URL | expect(false/true) | actual(false/true) | ok");
      int stableBad = 0;
      int idnBad = 0;
      foreach (var row in rows)
      {
        var db = MakeDb();
        Add(db, "e", (PwDefs.UrlField, row.urlValue));
        bool actFalse = Helper.SearchForHost(db, row.query, false).Entries.Any();
        bool actTrue = Helper.SearchForHost(db, row.query, true).Entries.Any();
        bool ok = actFalse == row.expectHost && actTrue == row.expectHostNoSub;
        if (!ok)
        {
          if (row.branchDependent) idnBad++;
          else stableBad++;
        }
        Console.WriteLine($"{row.query} | {row.urlValue} | {row.expectHost}/{row.expectHostNoSub} | {actFalse}/{actTrue} | {(ok ? "ok" : "MISMATCH")}");
      }
      Console.WriteLine($"matrix mismatches: {stableBad + idnBad} (stable rows: {stableBad}, idn rows: {idnBad})");
      StableMatrixMismatches = stableBad;
    }

    /// <summary>Mismatches of the matrix rows that must hold on every branch.</summary>
    static int StableMatrixMismatches;

    // ---- androidapp:// scenario ---------------------------------------------

    static void AppScenario()
    {
      var db = MakeDb();
      Add(db, "A", ("KP2A_URL_1", "androidapp://com.example.a"));
      Add(db, "B", ("AndroidApp1", "androidapp://com.example.a"));
      var g = Results(db, "androidapp://com.example.a");
      Console.WriteLine("androidapp://com.example.a -> " + Titles(g));
    }

    /// <summary>
    /// Scenarios around the additional URL fields (the fields written by "Remember
    /// search text", by KeePassXC's "Additional URLs" and by SetNextFreeUrlField).
    /// </summary>
    static void AdditionalFieldScenarios()
    {
      // URL field empty, the site is only remembered in an additional field (#1037)
      var emptyUrl = MakeDb();
      Add(emptyUrl, "emptyurl", (PwDefs.UrlField, ""), ("KP2A_URL_1", "https://example.com"));
      Console.WriteLine("empty URL field + KP2A_URL_1, web query   -> " + Titles(Results(emptyUrl, "example.com")));

      // an app identifier in an additional field must not match a web host
      var appOnly = MakeDb();
      Add(appOnly, "apponly", ("AndroidApp1", "androidapp://com.example.a"));
      Console.WriteLine("AndroidApp1 only, web query              -> " + Titles(Results(appOnly, "example.com")));
      Console.WriteLine("AndroidApp1 only, app query              -> " + Titles(Results(appOnly, "androidapp://com.example.a")));

      // the host is in the URL field, the punycode spelling in KP2A_URL_1
      var idnInAdditional = MakeDb();
      Add(idnInAdditional, "tiny", (PwDefs.UrlField, "tinyauth.oracle-noddy.爱来自世界.top"), ("KP2A_URL_1", PageHost));
      Console.WriteLine("punycode in KP2A_URL_1, web query        -> " + Titles(Results(idnInAdditional, PageHost)));

      // parent domain entry next to the entry with the searched host
      var parentAndExact = MakeDb();
      Add(parentAndExact, "parent", (PwDefs.UrlField, "https://oracle-noddy.xn--rhqv03d5th68cnuv.top"));
      Add(parentAndExact, "exact", (PwDefs.UrlField, "https://" + PageHost));
      Console.WriteLine("parent + exact entry, web query          -> " + Titles(Results(parentAndExact, PageHost)));
    }

    static void PhaseDump()
    {
      var db = ScenarioDb();
      Console.WriteLine($"exact        : {Titles(Helper.SearchForExactUrl(db, Query))}");
      Console.WriteLine($"host(false)  : {Titles(Helper.SearchForHost(db, Query, false))}");
      Console.WriteLine($"host(true)   : {Titles(Helper.SearchForHost(db, Query, true))}");
      Console.WriteLine($"text(url)    : {Titles(Helper.SearchForText(db, Query))}");
      Console.WriteLine($"text(host)   : {Titles(Helper.SearchForText(db, UrlUtil.GetHost(Query.Trim())))}");
      Console.WriteLine($"FINAL        : {Titles(Results(db, Query))}");
    }

    static int Main(string[] args)
    {
      Console.WriteLine("== user scenario ==");
      Console.WriteLine($"page url: https://{PageHost}:18081");
      PhaseDump();

      Console.WriteLine();
      Console.WriteLine("== androidapp:// ==");
      AppScenario();

      Console.WriteLine();
      Console.WriteLine("== additional URL fields ==");
      AdditionalFieldScenarios();

      Console.WriteLine();
      Console.WriteLine("== regression matrix ==");
      Matrix();

#if HAS_RANK
      Console.WriteLine();
      RankDump();
#endif

      return Invariants();
    }

    /// <summary>
    /// Returns the number of broken invariants: zero means the branch behaves correctly.
    /// The invariants cover what the fixes claim and what must not regress; the candidate
    /// order (the first entry is the one the autofill dropdown offers) is only reported,
    /// because ordering by precision is not part of these fixes.
    /// </summary>
    static int Invariants()
    {
      int broken = 0;

      void Check(bool ok, string what)
      {
        Console.WriteLine($"invariant: {(ok ? "ok" : "BROKEN")} - {what}");
        if (!ok) broken++;
      }

      string scenarioFinal = Titles(Results(ScenarioDb(), Query));
      Check(scenarioFinal.Contains("tiny"),
        $"the reported scenario lists the entry 'tiny' (got '{scenarioFinal}')");
      Check(StableMatrixMismatches == 0,
        $"no regression in the matrix rows that must hold on every branch (got {StableMatrixMismatches} mismatches)");

      var appDb = MakeDb();
      Add(appDb, "A", ("KP2A_URL_1", "androidapp://com.example.a"));
      Add(appDb, "B", ("AndroidApp1", "androidapp://com.example.a"));
      Check(Titles(Results(appDb, "androidapp://com.example.a")) == "A, B",
        "an androidapp:// URL remembered in KP2A_URL_1 or AndroidApp1 finds both entries");

      var appOnly = MakeDb();
      Add(appOnly, "apponly", ("AndroidApp1", "androidapp://com.example.a"));
      Check(Titles(Results(appOnly, "example.com")) == "<none>",
        "an app identifier does not match a web host");

      Console.WriteLine($"invariants broken: {broken}");
      Console.WriteLine($"observation: candidate order '{scenarioFinal}' - Kp2aAutofillService keeps only " +
        "Take(2 - numDisableDatasets) = 1 candidate by default, so the first entry is the one offered");
      return broken;
    }

#if HAS_RANK
    /// <summary>
    /// Prints what a rank based caller would return for the reported scenario, for
    /// comparison with the phase based candidate list of the shipped code.
    /// </summary>
    static void RankDump()
    {
      var candidates = new (string title, string urlValue)[]
      {
        ("sub1", "https://oracle-noddy.xn--rhqv03d5th68cnuv.top:18081/sub"),
        ("tiny", "tinyauth.oracle-noddy.爱来自世界.top"),
        ("tiny", PageHost),
      };

      var ranked = new List<(string title, Kp2aAutofillParser.UrlMatchRank rank)>();
      foreach (var (title, urlValue) in candidates)
        ranked.Add((title, Kp2aAutofillParser.UrlMatchRankPolicy.RankHostMatch(Query, UrlUtil.GetHost(urlValue.Trim()), false)));

      var best = Kp2aAutofillParser.UrlMatchRankPolicy.Best(ranked.ConvertAll(r => r.rank));
      Console.WriteLine("== rank prototype ==");
      Console.WriteLine("entry | rank");
      foreach (var (title, rank) in ranked)
        Console.WriteLine($"{title} | {rank}");
      Console.WriteLine($"best: {best}");

      foreach (bool includeDomainRelation in new[] { false, true })
      {
        var included = ranked.FindAll(r => Kp2aAutofillParser.UrlMatchRankPolicy.IsIncluded(r.rank, best, includeDomainRelation));
        included.Sort((a, b) => b.rank.CompareTo(a.rank));
        string policy = includeDomainRelation ? "relaxed (host + parent domain)" : "strict (best rank only)";
        Console.WriteLine($"{policy}: {string.Join(", ", included.ConvertAll(r => r.title))}");
      }
    }
#endif
  }
}
