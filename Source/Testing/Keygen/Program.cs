﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SSHKeygen
{
  public static AsymmetricCipherKeyPair GenerateKeys(int keySizeInBits)
  {
    var r = new RsaKeyPairGenerator();
    r.Init(new KeyGenerationParameters(new SecureRandom(), keySizeInBits));
    var keys = r.GenerateKeyPair();
    return keys;
  }

  static void Main(string[] args)
  {
    var keys = GenerateKeys(2048);


    var publicKey = keys.Public.ToString();

    var textWriter = new StreamWriter("private.key");
    var pemWriter = new PemWriter(textWriter);
    pemWriter.WriteObject(keys.Private);
    pemWriter.Writer.Flush();
    textWriter.Close();


    textWriter = new StreamWriter("public.key");
    pemWriter = new PemWriter(textWriter);
    pemWriter.WriteObject(keys.Public);
    pemWriter.Writer.Flush();
    textWriter.Close();

    Console.ReadKey();


  }
}
