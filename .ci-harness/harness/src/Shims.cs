// Minimal stand-ins for the Android/Java and Kp2aBusinessLogic APIs that the real
// KeePassLib2Android sources touch but that the harness does not need. Nothing here
// carries behavior that the verification depends on.

using System;
using System.Collections.Generic;
using KeePassLib;
using KeePassLib.Collections;

namespace Android.Graphics
{
  public class Bitmap
  {
    public int Width { get { return 0; } }
    public int Height { get { return 0; } }
  }
}

namespace Java.IO
{
  public class FileNotFoundException : System.Exception
  {
  }
}

namespace Java.Lang
{
  public class Exception : System.Exception
  {
    public Exception() { }
    public Exception(string message) : base(message) { }
  }

  public static class JavaSystem
  {
    public static void LoadLibrary(string library) { }
  }
}

namespace KeePassLib.Native
{
  /// <summary>Stand-in for NativeLib.cs, which needs the Java/Com bindings.</summary>
  public static class NativeLib
  {
    public static int PointerSize { get { return IntPtr.Size; } }
    public static ulong MonoVersion { get { return 0; } }
    public static bool IsUnix() { return true; }
    public static System.PlatformID GetPlatformID() { return System.PlatformID.Unix; }
    public static bool TransformKey256(byte[] pBuf256, byte[] pKey256, ulong uRounds) { return false; }
    public static bool TransformKeyBenchmark256(uint uTimeMs, out ulong puRounds) { puRounds = 0; return false; }
  }
}

namespace KeePassLib.Utility
{
  /// <summary>Stand-in for MessageService.cs, which is built on Android dialogs.</summary>
  public static class MessageService
  {
    public static string NewLine { get { return System.Environment.NewLine; } }
    public static string NewParagraph { get { return System.Environment.NewLine + System.Environment.NewLine; } }
    public static void ShowInfo(params object[] vLines) { }
    public static void ShowWarning(params object[] vLines) { }
  }

  /// <summary>Stand-in for GfxUtil.cs (Android bitmap decoding).</summary>
  public static class GfxUtil
  {
    public static Android.Graphics.Bitmap LoadImage(byte[] pb) { return null; }
  }
}

namespace keepass2android
{
  /// <summary>
  /// Stand-in for the Android logging class (Kp2aLog.cs is not compiled here).
  /// </summary>
  public static class Kp2aLog
  {
    public static void Log(string message) { }
    public static void LogUnexpectedError(Exception exception) { }
    public static void LogTask(object task, string activityName) { }
    public static bool LogToFile { get; set; }
    public static string LogFilename { get { return string.Empty; } }
    public static void CreateLogFile() { }
    public static void FinishLogFile() { }
    public static void SendLog(object ctx) { }
  }

  /// <summary>
  /// Stand-in for the app-side Database wrapper (src/Kp2aBusinessLogic/database/Database.cs),
  /// reduced to the members SearchDbHelper reads.
  /// </summary>
  public class Database
  {
    public Dictionary<PwUuid, PwEntry> EntriesById =
      new Dictionary<PwUuid, PwEntry>(new PwUuidEqualityComparer());
    public PwGroup Root;
    public PwDatabase KpDatabase;

    // Mirrors the real Database wrapper + SearchHelper delegation.
    private static readonly SearchDbHelper Helper = new SearchDbHelper(new StubApp());

    public PwGroup SearchForText(string str) { return Helper.SearchForText(this, str); }
    public PwGroup SearchForExactUrl(string url) { return Helper.SearchForExactUrl(this, url); }
    public PwGroup SearchForHost(string url, bool allowSubdomains) { return Helper.SearchForHost(this, url, allowSubdomains); }
    public PwGroup SearchForUuid(string uuid) { return Helper.SearchForUuid(this, uuid); }
  }

  /// <summary>
  /// Stand-in for IKp2aApp, reduced to the member SearchDbHelper reads.
  /// </summary>
  public interface IKp2aApp
  {
    string GetResourceString(UiStringKey key);
  }

  public class StubApp : IKp2aApp
  {
    public string GetResourceString(UiStringKey key) { return key.ToString(); }
  }

  /// <summary>Constant from the app project (src/keepass2android-app/KeePass.cs).</summary>
  public static class AndroidAppConstants
  {
    public const string Scheme = "androidapp://";
  }
}
