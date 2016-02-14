using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace NFX.SSH
{
  public static class CryptoExtensions
  {
    public unsafe static void HashBlock(this ICryptoTransform cipher, SecureString str, bool final = true)
    {
      using (var input = new SecureStringToByteArrayAdapter(str))
      {
        var managedBytes   = new byte[input.Length];
        fixed (byte* dummy = managedBytes)
        { //pin it
          try
          {
            //populate it in pinned block
            UnmanagedBytesToManagedBytes(input, managedBytes);
            if (final)
              cipher.TransformFinalBlock(managedBytes, 0, input.Length);
            else
              cipher.TransformBlock(managedBytes, 0, input.Length, null, 0);
          }
          finally
          {
            //clear it before we leave pinned block
            Clear(managedBytes);
          }
        }
      }
    }

    #region UnmanagedArray
    /// <summary>
    /// Places an array facade on an unmanaged memory data structure that
    /// holds senstive data. (In C# placing senstive data in managed 
    /// memory is considered unsecure since the memory model allows
    /// data to be copied around).
    /// </summary>
    public interface UnmanagedArray<T> : IDisposable
    {
      int Length          { get; }
      T   this[int index] { get; set; }
    }
    #endregion

    #region AbstractUnmanagedArray
    public abstract class AbstractUnmanagedArray<T> : UnmanagedArray<T>
    {
      private readonly int m_Length;
      private bool m_Disposed;

      protected AbstractUnmanagedArray(int length)
      {
        if (length < 0)
          throw new ArgumentException("Invalid length: " + length);
        m_Length = length;
      }

      public int Length
      {
        get
        {
          if (m_Disposed)
            throw new ObjectDisposedException("UnmanagedArray");
          return m_Length;
        }
      }

      public T this[int index]
      {
        get
        {
          if (m_Disposed)
            throw new ObjectDisposedException("UnmanagedArray");
          if (index < 0 || index >= Length)
            throw new IndexOutOfRangeException();
          return GetValue(index);
        }
        set
        {
          if (m_Disposed)
            throw new ObjectDisposedException("SecureStringAdapter");
          if (index < 0 || index >= Length)
            throw new IndexOutOfRangeException();
          SetValue(index, value);
        }
      }
      public void Dispose()
      {
        if (m_Disposed) return;
        for (var i = 0; i < Length; i++)
          this[i] = default(T);
        m_Disposed = true;
        FreeMemory();
      }

      abstract protected T    GetValue(int index);
      abstract protected void SetValue(int index, T val);
      abstract protected void FreeMemory();
    }
    #endregion

    #region SecureStringAdapter
    internal class SecureStringAdapter : AbstractUnmanagedArray<char>
    {
      private readonly IntPtr m_StrPtr;
      public SecureStringAdapter(SecureString secureString)
          : base(secureString.Length)
      {
        m_StrPtr = Marshal.SecureStringToBSTR(secureString);
      }
      protected override char GetValue(int index)
      {
        unsafe { return *((char*)m_StrPtr + index); }
      }
      protected override void SetValue(int index, char c)
      {
        unsafe { *((char*)m_StrPtr + index) = c; }
      }
      protected override void FreeMemory()
      {
        Marshal.ZeroFreeBSTR(m_StrPtr);
      }
    }
    #endregion

    #region SecureStringToByteArrayAdapter
    internal class SecureStringToByteArrayAdapter : AbstractUnmanagedArray<byte>
    {
      private readonly IntPtr m_StrPtr;
      public SecureStringToByteArrayAdapter(SecureString secureString)
        : base(secureString.Length)
      {
        m_StrPtr = Marshal.SecureStringToBSTR(secureString);
      }
      protected override byte GetValue(int index)
      {
        unsafe { return (byte)*((char*)m_StrPtr + index); }
      }
      protected override void SetValue(int index, byte b)
      {
        unsafe { *((char*)m_StrPtr + index) = (char)b; }
      }
      protected override void FreeMemory()
      {
        Marshal.ZeroFreeBSTR(m_StrPtr);
      }
    }
    #endregion

    /// <summary>
    /// Copies an unmanaged byte array into a managed byte array.
    /// </summary>
    /// <remarks>
    /// NOTE: it is imperative for security reasons that this only
    /// be done in a context where the byte array in question is pinned.
    /// moreover, the byte array must be cleared prior to leaving the
    /// pinned block
    /// </remarks>
    public static void UnmanagedBytesToManagedBytes(UnmanagedArray<byte> array,
                                                    byte[] bytes)
    {
      for (var i = 0; i < array.Length; i++)
        bytes[i] = array[i];
    }

    /// <summary>
    /// Clears an array of potentially sensitive bytes
    /// </summary>
    /// <param name="bytes">The bytes. May be null.
    /// NOTE: because this is C#, this alone is not enough. The
    /// array must be pinned during the interval it is in-use or
    /// it could be copied out from under you.</param>
    public static void Clear(byte[] bytes)
    {
      if (bytes == null) return;
      for (var i = 0; i < bytes.Length; i++)
        bytes[i] = 0;
    }

    /// <summary>
    /// Clears an array of potentially sensitive chars
    /// </summary>
    /// <param name="chars">The characters. May be null.
    /// NOTE: because this is C#, this alone is not enough. The
    /// array must be pinned during the interval it is in-use or
    /// it could be copied out from under you.</param>
    public static void Clear(char[] chars)
    {
      if (chars == null) return;
      for (var i = 0; i < chars.Length; i++)
        chars[i] = (char)0;
    }
  }
}
