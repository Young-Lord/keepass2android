/*
This file is part of Keepass2Android, Copyright 2013 Philipp Crocoll. This file is based on Keepassdroid, Copyright Brian Pellin.

  Keepass2Android is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 2 of the License, or
  (at your option) any later version.

  Keepass2Android is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with Keepass2Android.  If not, see <http://www.gnu.org/licenses/>.
  */
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Kp2aAutofillParser;
using KeePass.Util.Spr;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace keepass2android
{
  /// <summary>
  /// Helper class providing methods to search a given database for specific things
  /// </summary>
  public class SearchDbHelper
  {
    /// <summary>
    /// Scheme of the URLs which identify an installed app instead of a web site (see
    /// Util.SetNextFreeUrlField). They are stored in the additional URL fields, but
    /// they are no host names.
    /// </summary>
    private const string AndroidAppScheme = "androidapp://";

    private readonly IKp2aApp _app;


    public SearchDbHelper(IKp2aApp app)
    {
      _app = app;
    }


    public PwGroup SearchForText(Database database, string str)
    {
      SearchParameters sp = new SearchParameters { SearchString = str };

      return Search(database, sp, null);
    }
    public PwGroup Search(Database database, SearchParameters sp, IDictionary<PwUuid, KeyValuePair<string, string>> resultContexts)
    {

      if (sp.RegularExpression) // Validate regular expression
      {
        new Regex(sp.SearchString);
      }

      string strGroupName = _app.GetResourceString(UiStringKey.search_results) + " (\"" + sp.SearchString + "\")";
      PwGroup pgResults = new PwGroup(true, true, strGroupName, PwIcon.EMailSearch) { IsVirtual = true };

      PwObjectList<PwEntry> listResults = pgResults.Entries;


      database.Root.SearchEntries(sp, listResults, resultContexts, new NullStatusLogger());


      return pgResults;


    }


    public PwGroup SearchForExactUrl(Database database, string url)
    {
      SearchParameters sp = SearchParameters.None;
      sp.SearchInUrls = true;
      sp.SearchString = url;

      if (sp.RegularExpression) // Validate regular expression
      {
        new Regex(sp.SearchString);
      }

      string strGroupName = _app.GetResourceString(UiStringKey.search_results) + " (\"" + sp.SearchString + "\")";
      PwGroup pgResults = new PwGroup(true, true, strGroupName, PwIcon.EMailSearch) { IsVirtual = true };

      PwObjectList<PwEntry> listResults = pgResults.Entries;


      database.Root.SearchEntries(sp, listResults, new NullStatusLogger());

      // SearchEntries only examines the URL field. Additional URL fields
      // (KP2A_URL, KP2A_URL_1, ...) must be considered as well, so that a URL
      // remembered there is found with the same priority as one in the URL field.
      foreach (PwEntry entry in database.EntriesById.Values)
      {
        if (!entry.GetSearchingEnabled() || (pgResults.Entries.IndexOf(entry) >= 0))
          continue;
        foreach (string urlValue in GetUrlFieldValues(entry, database))
        {
          if (urlValue.IndexOf(url, StringComparison.InvariantCultureIgnoreCase) >= 0)
          {
            pgResults.AddEntry(entry, false);
            break;
          }
        }
      }

      return pgResults;

    }

    public PwGroup SearchForUuid(Database database, string uuid)
    {
      SearchParameters sp = SearchParameters.None;
      sp.SearchInUuids = true;
      sp.SearchString = uuid;

      if (sp.RegularExpression) // Validate regular expression
      {
        new Regex(sp.SearchString);
      }

      string strGroupName = _app.GetResourceString(UiStringKey.search_results);
      PwGroup pgResults = new PwGroup(true, true, strGroupName, PwIcon.EMailSearch) { IsVirtual = true };

      PwObjectList<PwEntry> listResults = pgResults.Entries;

      database.Root.SearchEntries(sp, listResults, new NullStatusLogger());

      return pgResults;

    }

    private static String ExtractHost(String url)
    {
      return UrlUtil.GetHost(url.Trim());
    }

    /// <summary>
    /// Returns the URL values of an entry which are relevant for URL matching: the
    /// standard URL field and all additional URL fields (see AdditionalUrlFields).
    /// </summary>
    private static IEnumerable<string> GetUrlFieldValues(PwEntry entry, Database database)
    {
      yield return GetCompiledFieldValue(entry, database, PwDefs.UrlField);

      foreach (KeyValuePair<string, ProtectedString> kvp in entry.Strings)
      {
        if (!AdditionalUrlFields.IsAdditionalUrlFieldName(kvp.Key))
          continue;
        yield return GetCompiledFieldValue(entry, database, kvp.Key);
      }
    }

    private static string GetCompiledFieldValue(PwEntry entry, Database database, string fieldName)
    {
      string value = entry.Strings.ReadSafe(fieldName);
      return SprEngine.Compile(value, new SprContext(entry, database.KpDatabase, SprCompileFlags.References));
    }

    public PwGroup SearchForHost(Database database, String url, bool allowSubdomains)
    {
      String host = ExtractHost(url);
      string strGroupName = _app.GetResourceString(UiStringKey.search_results) + " (\"" + host + "\")";
      PwGroup pgResults = new PwGroup(true, true, strGroupName, PwIcon.EMailSearch) { IsVirtual = true };
      if (String.IsNullOrWhiteSpace(host))
        return pgResults;
      foreach (PwEntry entry in database.EntriesById.Values)
      {
        if (!entry.GetSearchingEnabled())
          continue;
        foreach (string otherUrl in GetUrlFieldValues(entry, database))
        {
          if (otherUrl.StartsWith(AndroidAppScheme, StringComparison.OrdinalIgnoreCase))
            continue; // app identifiers are not host names

          if (UrlHostMatching.HostsMatch(host, ExtractHost(otherUrl), allowSubdomains))
          {
            pgResults.AddEntry(entry, false);
            break;
          }
        }
      }
      return pgResults;
    }

  }
}

