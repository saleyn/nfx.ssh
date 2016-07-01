﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NFX.SSH;
using NFX.SSH.PKI;
using NFX.Environment;

namespace NFX.Erlang
{
  /// <summary>
  /// SSH tunnel transport.
  /// Provides tcp connection through SSH tunnel.
  /// </summary>
  public class ErlSshTransport : IErlTransport, ISSHConnectionEventReceiver,
    ISSHChannelEventReceiver, ISSHEventTracer, IConfigurable
  {
    #region CONSTS / Enums

    private const int    DEFAULT_SSH_PORT                    = 22;
    private const int    DEFAULT_SSH_CONNECT_TIMEOUT         = 20000; //ms
    private const string ERL_CREATE_SSH_TUNNEL_ERROR         = "Cannot create SSH tunnel";
    private const string ERL_CONN_CANT_CONNECT_TO_HOST_ERROR = "Cannot establish {0} connection to host {0}:{1}";

    #endregion;

    #region Static

    private static IPAddress ResolveHost(string hostname)
    {
      IPAddress res;

      if (!IPAddress.TryParse(hostname, out res))
        res = Dns.GetHostAddresses(hostname)[0];

      return res;
    }

    #endregion

    #region Fields

    private readonly Socket m_Client;
    private SSHConnection   m_Connection;
    private SSHChannel      m_Channel;
    private SshTunnelStream m_Stream;
    private IPEndPoint      m_RemoteTarget;
    private int             m_IsChannelReady;  // 0 = not ready, -1 = error, 1 = ready

    #endregion;

    #region Events

    /// <summary>
    /// Transmits trace messages
    /// </summary>
    public event TraceEventHandler Trace = delegate { };

    #endregion

    #region .ctor

    public ErlSshTransport()
    {
      //default settings
      SSHAuthenticationType = AuthenticationType.Password.ToString();
      SSHServerPort         = DEFAULT_SSH_PORT;
      ConnectTimeout        = DEFAULT_SSH_CONNECT_TIMEOUT;
      //create socket
      m_Client = new Socket(AddressFamily.InterNetwork, SocketType.Stream,
                            ProtocolType.Tcp);
    }

    #endregion

    #region Public

    /// <summary>
    /// Port of SSH server (by default: 22)
    /// </summary>
    public int SSHServerPort { get; set; }

    /// <summary>
    /// SSH user name
    /// </summary>
    public string SSHUserName { get; set; }

    /// <summary>
    /// Private key file path (only for AuthenticationType = PublicKey)
    /// Required SSH2 ENCRYPTED PRIVATE KEY format.
    /// </summary>
    public string SSHPrivateKeyFilePath { get; set; }

    /// <summary>
    /// Timeout of creation of SSH tunnel, ms (by default: 20000 ms)
    /// </summary>
    public int ConnectTimeout { get; set; }

    /// <summary>
    /// Type of auth on SSH server
    /// </summary>
    public string SSHAuthenticationType { get; set; }

    /// <summary>
    /// Remote Erlang node name
    /// </summary>
    public string NodeName { get; set; }

    /// <summary>
    /// Connect to remote host:port over SSH tunnel
    /// </summary>
    public void Connect(string host, int port)
    {
      Connect(host, port, ConnectTimeout);
    }

    /// <summary>
    /// Connect to remote host:port over SSH tunnel
    /// </summary>
    public void Connect(string host, int port, int timeout)
    {
      try
      {
        //remember remote target
        m_RemoteTarget = new IPEndPoint(ResolveHost(host), port);

        //connect to SSH server
        if (!connectAsync(m_RemoteTarget.Address, SSHServerPort).Wait(timeout))
          throw new ErlException(ERL_CONN_CANT_CONNECT_TO_HOST_ERROR.Args("SSH", host, port));

        //get password from user
        var pass                 = ErlTransportPasswordSource.GetPassword(this, NodeName, SSHUserName);

        //set params
        var param                = new SSHConnectionParameter();
        param.EventTracer        = this; //to receive detailed events
        param.UserName           = SSHUserName;
        param.Password           = pass;
        param.Protocol           = SSHProtocol.SSH2;
        param.AuthenticationType = (AuthenticationType)
                                   Enum.Parse(typeof (SSH.AuthenticationType), SSHAuthenticationType);

        if (param.AuthenticationType == AuthenticationType.PublicKey)
          param.IdentityFile = SSHPrivateKeyFilePath;

        //former algorithm is given priority in the algorithm negotiation
        param.PreferableHostKeyAlgorithms = new PublicKeyAlgorithm[]
                                            {PublicKeyAlgorithm.RSA, PublicKeyAlgorithm.DSA};
        param.PreferableCipherAlgorithms  = new CipherAlgorithm[]
        {
          CipherAlgorithm.Blowfish, CipherAlgorithm.TripleDES, CipherAlgorithm.AES192CTR,
          CipherAlgorithm.AES256CTR, CipherAlgorithm.AES128CTR
        };

        param.WindowSize            = 0x1000; //this option is ignored with SSH1

        //Creating a new SSH connection over the underlying socket
        m_Connection                = SSHConnection.Connect(param, this, m_Client);
        m_Connection.AutoDisconnect = true;
        m_IsChannelReady            = 0;

        //Local->Remote port forwarding (we use localhost:0 as local port, because local port is not required for us, we will use this tunnel directly)
        m_Channel = m_Connection.ForwardPort(this, host, port, "localhost", 0);
        var deadLine = DateTime.Now.AddMilliseconds(timeout);
        while (m_IsChannelReady == 0 && deadLine > DateTime.Now)
          System.Threading.Thread.Sleep(50); //wait response

        //if timeouted - throw exception
        if (m_IsChannelReady <= 0)
          throw new ErlException(ERL_CREATE_SSH_TUNNEL_ERROR);

        //create network stream
        m_Stream = new SshTunnelStream(m_Channel);

        //Remote->Local
        // if you want to listen to a port on the SSH server, follow this line:
        //_conn.ListenForwardedPort("0.0.0.0", 10000);

        //NOTE: if you use SSH2, dynamic key exchange feature is supported.
        //((SSH2Connection)_conn).ReexchangeKeys();
      }
      catch (Exception ex)
      {
        OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound, ex.Message);
        throw;
      }
    }

    public Stream GetStream() { return m_Stream; }

    public int ReceiveBufferSize
    {
      get { return m_Client.ReceiveBufferSize; }
      set { m_Client.ReceiveBufferSize = value; }
    }

    public int SendBufferSize
    {
      get { return m_Client.SendBufferSize; }
      set { m_Client.SendBufferSize = value; }
    }

    public bool NoDelay
    {
      get { return m_Client.NoDelay; }
      set { m_Client.NoDelay = value; }
    }

    public void Close()   { m_Stream.Close(); m_Client.Close(); }
    public void Dispose() { m_Client.Dispose(); }

    public void SetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName,
                                bool optionValue)
    {
      m_Client.SetSocketOption(optionLevel, optionName, optionValue);
    }

    public EndPoint RemoteEndPoint { get { return m_RemoteTarget; } }

    public void OnData(byte[] data, int offset, int count)
    {
      m_Stream.EnqueueData(data, offset, count);
    }

    public void OnDebugMessage(bool always_display, byte[] data)
    {
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound,
              "DEBUG: " + Encoding.ASCII.GetString(data));
    }

    public void OnIgnoreMessage(byte[] data)
    {
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound,
              "Ignore: " + Encoding.ASCII.GetString(data));
    }

    public void OnAuthenticationPrompt(string[] msg)
    {
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound,
              "Auth Prompt " + (msg.Length > 0 ? msg[0] : "(empty)"));
    }

    public void OnError(Exception error)
    {
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound, "ERROR: " + error.Message);
    }

    public void OnChannelClosed()
    {
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound, "Channel closed");
      //_conn.AsyncReceive(this);
    }

    public void OnChannelEOF()
    {
      m_Channel.Close();

      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound, "Channel EOF");
      //close connection
      m_Connection.Close();
    }

    public void OnExtendedData(int type, byte[] data)
    {
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound, "EXTENDED DATA");
    }

    public void OnConnectionClosed()
    {
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound, "Connection closed");
    }

    public void OnUnknownMessage(byte type, byte[] data)
    {
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound, "Unknown Message " + type);
    }

    public void OnChannelReady()
    {
      m_IsChannelReady = 1;
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound, "Channel Ready");
    }

    public void OnChannelError(Exception error)
    {
      m_IsChannelReady = -1;
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound, "Channel ERROR: " + error.Message);
    }

    public void OnMiscPacket(byte type, byte[] data, int offset, int length) {}

    public PortForwardingCheckResult CheckPortForwardingRequest(string host, int port,
                                                                string originator_host,
                                                                int originator_port)
    {
      PortForwardingCheckResult r = new PortForwardingCheckResult();
      r.allowed = true;
      r.channel = this;
      return r;
    }

    public void EstablishPortforwarding(ISSHChannelEventReceiver rec, SSHChannel channel)
    {
      this.m_Channel = channel;
    }

    public void OnTranmission(string type, string detail)
    {
      OnTrace(ErlTraceLevel.Ctrl, Direction.Outbound, "SSH:" + type + ":" + detail);
    }

    public void OnReception(string type, string detail)
    {
      OnTrace(ErlTraceLevel.Ctrl, Direction.Inbound, "SSH:" + type + ":" + detail);
    }

    public void Configure(IConfigSectionNode node) {}

    #endregion

    #region Private

    private void OnTrace(ErlTraceLevel level, Direction dir, string message)
    {
      Trace(this, level, dir, "SSH " + message);
    }

    /// <summary>
    /// Connects the client to a remote TCP host using the specified IP address and port number as an asynchronous operation.
    /// </summary>
    /// 
    /// <returns>
    /// Returns <see cref="T:System.Threading.Tasks.Task"/>The task object representing the asynchronous operation.
    /// </returns>
    /// <param name="address">The <see cref="T:System.Net.IPAddress"/> of the host to which you intend to connect.</param>
    /// <param name="port">The port number to which you intend to connect. </param>
    /// <exception cref="T:System.ArgumentNullException">The <paramref name="address"/> parameter is null.</exception>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The <paramref name="port"/> is not between
    ///   <see cref="F:System.Net.IPEndPoint.MinPort"/> and <see cref="F:System.Net.IPEndPoint.MaxPort"/>.
    /// </exception>
    /// <exception cref="T:System.Net.Sockets.SocketException">An error occurred when accessing the socket.
    /// See the Remarks section for more information. </exception>
    /// <exception cref="T:System.ObjectDisposedException"><see cref="T:System.Net.Sockets.TcpClient"/> is closed.</exception>
    private Task connectAsync(IPAddress address, int port)
    {
      return Task.Factory.FromAsync<IPAddress, int>
        (new Func<IPAddress, int, AsyncCallback, object, IAsyncResult>
          (this.beginConnect), new Action<IAsyncResult>(this.endConnect), address, port, (object)null);
    }

    /// <summary>
    /// Connects the client to the specified TCP port on the specified host as an asynchronous operation.
    /// </summary>
    /// 
    /// <returns>
    /// Returns <see cref="T:System.Threading.Tasks.Task"/>The task object representing the asynchronous operation.
    /// </returns>
    /// <param name="host">The DNS name of the remote host to which you intend to connect.</param>
    /// <param name="port">The port number of the remote host to which you intend to connect.</param>
    /// <exception cref="T:System.ArgumentNullException">The <paramref name="hostname"/> parameter is null.</exception>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The <paramref name="port"/> parameter is not between
    ///   <see cref="F:System.Net.IPEndPoint.MinPort"/> and <see cref="F:System.Net.IPEndPoint.MaxPort"/>.</exception>
    /// <exception cref="T:System.Net.Sockets.SocketException">An error occurred when accessing the socket.
    /// See the Remarks section for more information.</exception>
    /// <exception cref="T:System.ObjectDisposedException"><see cref="T:System.Net.Sockets.TcpClient"/> is closed.</exception>
    private Task connectAsync(string host, int port)
    {
      return Task.Factory.FromAsync<string, int>
        (new Func<string, int, AsyncCallback, object, IAsyncResult>
          (this.beginConnect), new Action<IAsyncResult>(this.endConnect), host, port, (object)null);
    }

    private IAsyncResult beginConnect(string host, int port, AsyncCallback requestCallback, object state)
    {
      return m_Client.BeginConnect(host, port, requestCallback, state);
    }

    private IAsyncResult beginConnect(IPAddress address, int port, AsyncCallback requestCallback, object state)
    {
      return m_Client.BeginConnect(address, port, requestCallback, state);
    }

    private void endConnect(IAsyncResult asyncResult)
    {
      m_Client.EndConnect(asyncResult);
    }

    #endregion
  }
}