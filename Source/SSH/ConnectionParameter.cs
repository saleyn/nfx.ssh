/*
 Copyright (c) 2005 Poderosa Project, All Rights Reserved.
 This file is a part of the Granados SSH Client Library that is subject to
 the license included in the distributed package.
 You may not use this file except in compliance with the license.

 $Id: ConnectionParameter.cs,v 1.5 2011/10/27 23:21:56 kzmi Exp $
*/

using System;
using System.Security;
using NFX.SSH.PKI;

namespace NFX.SSH
{
  /// <summary>
  /// Fill the properties of ConnectionParameter object before you start the connection.
  /// </summary>
  /// <exclude/>
  public class SSHConnectionParameter : ICloneable
  {
    //protocol
    private SSHProtocol _protocol;

    public SSHProtocol Protocol
    {
      get { return _protocol; }
      set
      {
        VersionEOL = value == SSHProtocol.SSH1 ? "\n" : "\r\n";
        _protocol = value;
      }
    }

    //algorithm

    public CipherAlgorithm[] PreferableCipherAlgorithms { get; set; }
    public PublicKeyAlgorithm[] PreferableHostKeyAlgorithms { get; set; }

    //account

    public AuthenticationType AuthenticationType { get; set; }
    public string UserName { get; set; }
    public SecureString Password { get; set; }
    public string IdentityFile { get; set; }

    //host

    public HostKeyCheckCallback KeyCheck { get; set; }

    //terminal

    public string TerminalName        { get; set; }
    public int    TerminalWidth       { get; set; }
    public int    TerminalHeight      { get; set; }
    public int    TerminalPixelWidth  { get; set; }
    public int    TerminalPixelHeight { get; set; }
    public bool   CheckMACError       { get; set; }

    //SSH2 only property
    public int    WindowSize          { get; set; }
    public int    MaxPacketSize       { get; set; }

    //some server may expect irregular end-of-line character(s).
    //initial value is '\n' for SSH1 and '/r/n' for SSH2

    public string VersionEOL          { get; set; }

    //protocol negotiation tracer (optional)

    public ISSHEventTracer EventTracer { get; set; }

    //Agent forward (optional)

    public IAgentForward AgentForward { get; set; }

    public SSHConnectionParameter()
    {
      AuthenticationType = AuthenticationType.Password;
      TerminalName = "vt100";
      TerminalWidth = 80;
      TerminalHeight = 25;
      _protocol = SSHProtocol.SSH2;
      PreferableCipherAlgorithms = new[]
      {
        CipherAlgorithm.AES256CTR, CipherAlgorithm.AES256, CipherAlgorithm.AES192CTR,
        CipherAlgorithm.AES192, CipherAlgorithm.AES128CTR, CipherAlgorithm.AES128,
        CipherAlgorithm.Blowfish, CipherAlgorithm.TripleDES
      };
      PreferableHostKeyAlgorithms = new[]
      {PublicKeyAlgorithm.DSA, PublicKeyAlgorithm.RSA};
      WindowSize = 0x1000;
      MaxPacketSize = 0x10000;
      CheckMACError = true;
      EventTracer = null;
    }

    public object Clone()
    {
      var n = new SSHConnectionParameter
      {
        AuthenticationType          = AuthenticationType,
        PreferableCipherAlgorithms  = PreferableCipherAlgorithms,
        TerminalHeight              = TerminalHeight,
        PreferableHostKeyAlgorithms = PreferableHostKeyAlgorithms,
        IdentityFile                = IdentityFile,
        KeyCheck                    = KeyCheck,
        MaxPacketSize               = MaxPacketSize,
        Password                    = Password,
        _protocol                   = Protocol,
        TerminalName                = TerminalName,
        UserName                    = UserName,
        TerminalWidth               = TerminalWidth,
        WindowSize                  = WindowSize,
        CheckMACError               = CheckMACError,
        EventTracer                 = EventTracer,
        AgentForward                = AgentForward
      };
      return n;
    }
  }

  //To receive the events of the SSH protocol negotiation, set an implementation of this interface to ConnectionParameter
  //note that :
  // * these methods are called by different threads asynchronously
  // * DO NOT throw any exceptions in the implementation
  /// <summary>
  /// 
  /// </summary>
  /// <exclude/>
  public interface ISSHEventTracer
  {
    void OnTranmission(string type, string detail);
    void OnReception(string type, string detail);
  }
}
