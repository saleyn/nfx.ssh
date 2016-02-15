using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using NFX;
using NFX.ApplicationModel;
using NFX.Environment;
using NFX.Erlang;


//Start Erlang with params:
//  werl.exe -sname r@localhost -setcookie hahaha
//In erlang console:
//  register(me, self()).
//  f(M), receive M -> io:format("Got message: ~p\n", [M]) end.

namespace ErlangSSHTest
{
  public class ConsoleHelper
  {
    /// <summary>
    /// Allocates a new console for current process.
    /// </summary>
    [DllImport("kernel32.dll")]
    public static extern Boolean AllocConsole();

    /// <summary>
    /// Frees the console.
    /// </summary>
    [DllImport("kernel32.dll")]
    public static extern Boolean FreeConsole();
  }

  internal class Program
  {
    private static void Main(string[] args)
    {
      //here we handle password requests
      ErlTransportPasswordSource.PasswordRequired += ps =>
      {
        Console.Write("Username: {0}\nPassword: ", ps.UserName);
        ps.Password = GetPassword();
        Console.WriteLine();
      };

      using (var app = new ServiceBaseApplication(args, null))
      {
        var cfg = (ConfigSectionNode)app.CommandArgs;

        var batchSize = cfg["batch"].AttrByIndex(0).ValueAsInt(1);
        var totalMsgs = cfg["count"].AttrByIndex(0).ValueAsInt(100000);
        var traceAttr = cfg["trace"].AttrByIndex(0);
        var trace     = traceAttr.ValueAsEnum(ErlTraceLevel.Handshake);
        var noSSH     = cfg["nossh"].Exists;
        var noTrace   = cfg["notrace"].Exists;
        var user      = cfg["user"].AttrByIndex(0).ValueAsString("");
        var privkey   = cfg["sshkey"].AttrByIndex(0).ValueAsString("");

        if (cfg["h", "help"].Exists)
        {
          Console.WriteLine(
            "Usage: {0} [-batch BatchSize] [-count Iterations] [-trace wire|handshake|send] [-notrace]\n" +
            "       [-nossh] [-user User] [-sshkey SSHKeyFile]",
            MiscUtils.EntryExeName(false));
          Environment.ExitCode = 1;
          return;
        }

        var n = ErlApp.Node;
        n.AcceptConnections = false;
        n.TraceLevel        = traceAttr.Exists && n.TraceLevel == ErlTraceLevel.Off
                            ? trace : n.TraceLevel;
        if (noTrace)
          n.TraceLevel = ErlTraceLevel.Off;

        n.Trace += (_n, t, d, text) =>
          Console.WriteLine("{0,-9} {1} {2}", t, d == Direction.Inbound ? "<-" : "->", text);

        //n.Start();

        cfg            = App.ConfigRoot["erlang"];
        var remote     = cfg.Children
                            .FirstOrDefault(nd => nd.IsSameName("node") && nd.Value.Contains("@"));
        var remoteName = remote.ValueAsString(string.Empty);

        if (noSSH)
        {
          var mmm = remote.Attributes.FirstOrDefault(c => c.IsSameName("transport-type"));
          if (mmm.Exists)
            mmm.Delete();
        }

        if (user.IsNotNullOrWhiteSpace())
          remote.AttrByName("ssh-user-name").Value = user;

        if (privkey.IsNotNullOrWhiteSpace())
        {
          remote.AttrByName("ssh-private-key-file").Value    = privkey;
          remote.AttrByName("ssh-authentication-type").Value = "PublicKey";
        }

        Console.WriteLine(
          "\n\nCopy echo_server.erl to remote node {0}, and execute in the same directory:",
          remoteName);
        Console.WriteLine("1> c(echo_server).");
        Console.WriteLine("2> echo_server:run({0}).\n", batchSize == 1 ? "1" : "");
        Console.WriteLine("Press <Enter> when ready...");

        Console.ReadLine();

        var m = n.CreateMbox("test");
        var a = new ErlAtom("hello");
        var msg = new ErlTuple(m.Self, a);
        var remoteNode = new ErlAtom(remoteName);

        DateTime empty = new DateTime(2000, 1, 1, 0, 0, 0);
        DateTime start = empty;
        long count = 0;

        do
        {
          int i = 0;
          for (; i < batchSize && count < totalMsgs; ++i, ++count)
          {
            var res = n.Send(m.Self, remoteNode, "me", msg);
            if (!res)
            {
              Console.WriteLine("Can not send message");
              goto DONE;
            }

            if (start == empty)
            {
              Console.WriteLine("\nTurning off tracing");
              n.TraceLevel = ErlTraceLevel.Off;
              start = DateTime.UtcNow;
            }
          }

          for (int j = 0; j < i; ++j)
          {
            var got = m.Receive(5000);

            if (got == null)
            {
              Console.WriteLine("Timeout waiting for reply (count = {0})".Args(count));
              goto DONE;
            }

            if (!got.Equals(a))
            {
              Console.WriteLine("Got wrong result! Expected: {0}, Got: {1}", a, got);
              count = -1;
              goto DONE;
            }
          }

          if ((count%10000) == 0)
            Console.WriteLine("Processed {0} messages", count);
        } while (count < totalMsgs);

      DONE:
        var end = DateTime.UtcNow;
        var diff = (end - start);

        if (count > 0)
          Console.WriteLine("Processed {0} messages. Speed: {1:F2}msgs/s, Latency: {2}us",
                            totalMsgs, totalMsgs/diff.TotalSeconds,
                            1000.0*diff.TotalMilliseconds/totalMsgs);
      }

      if (Debugger.IsAttached)
      {
        Console.WriteLine("Press <Enter> when ready...");
        Console.Read();
      }
    }

    public static SecureString GetPassword()
    {
      var pwd = new SecureString();
      while (true)
      {
        var i = Console.ReadKey(true);
        switch (i.Key)
        {
          case ConsoleKey.Enter:
            goto DONE;
          case ConsoleKey.Backspace:
            if (pwd.Length <= 0) continue;
            pwd.RemoveAt(pwd.Length - 1);
            Console.Write("\b \b");
            break;
          default:
            pwd.AppendChar(i.KeyChar);
            Console.Write("*");
            break;
        }
      }
    DONE:
      pwd.MakeReadOnly(); // prevent further changes to the encrypted pwd
      return pwd;
    }
  }
}