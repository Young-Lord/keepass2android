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
  /// Tests for the additional URL fields, i.e. the fields which "Remember search text",
  /// KeePassXC's "Additional URLs" and Util.SetNextFreeUrlField write.
  /// </summary>
  public class AdditionalUrlFieldsTest
  {
    [Theory]
    [InlineData("KP2A_URL")]
    [InlineData("KP2A_URL_1")]
    [InlineData("kp2a_url_2")]
    [InlineData("AndroidApp1")]
    [InlineData("androidapp1")]
    public void IsAdditionalUrlFieldNameAcceptsTheFieldsWrittenByKp2a(string fieldName)
    {
      Assert.True(AdditionalUrlFields.IsAdditionalUrlFieldName(fieldName));
    }

    [Theory]
    [InlineData("URL")]
    [InlineData("Title")]
    [InlineData("UserName")]
    [InlineData("KP2A_PASSWORD")]
    public void IsAdditionalUrlFieldNameRejectsTheOtherFields(string fieldName)
    {
      Assert.False(AdditionalUrlFields.IsAdditionalUrlFieldName(fieldName));
    }
  }
}
