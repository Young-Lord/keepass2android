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

namespace Kp2aAutofillParser
{
  /// <summary>
  /// The entry fields which store additional URLs, free of KeePassLib references so that
  /// it can be unit tested (see Kp2aAutofillParser.Tests/AdditionalUrlFieldsTest.cs).
  /// </summary>
  public static class AdditionalUrlFields
  {
    // "KP2A_URL", "KP2A_URL_1", ... are written by "Remember search text" and by
    // KeePassXC's "Additional URLs" feature, "AndroidApp1", ... by
    // Util.SetNextFreeUrlField for androidapp:// URLs.
    private const string SiteUrlPrefix = "KP2A_URL";
    private const string AppUrlPrefix = "AndroidApp";

    /// <summary>
    /// Returns whether a field name denotes an additional URL field.
    /// </summary>
    public static bool IsAdditionalUrlFieldName(string fieldName)
    {
      return fieldName.StartsWith(SiteUrlPrefix, StringComparison.OrdinalIgnoreCase)
        || fieldName.StartsWith(AppUrlPrefix, StringComparison.OrdinalIgnoreCase);
    }
  }
}
