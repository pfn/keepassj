package com.hanhuy.keepassj;
/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2014 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

import java.io.*;
import java.util.ArrayList;
import java.util.List;

/*
abstract class WrapperStream : Stream

	{
		private readonly Stream m_s;
		protected Stream BaseStream
		{
			get { return m_s; }
		}

		public override boolean CanRead
		{
			get { return m_s.CanRead; }
		}

		public override boolean CanSeek
		{
			get { return m_s.CanSeek; }
		}

		public override boolean CanTimeout
		{
			get { return m_s.CanTimeout; }
		}

		public override boolean CanWrite
		{
			get { return m_s.CanWrite; }
		}

		public override long Length
		{
			get { return m_s.Length; }
		}

		public override long Position
		{
			get { return m_s.Position; }
			set { m_s.Position = value; }
		}

		public override int ReadTimeout
		{
			get { return m_s.ReadTimeout; }
			set { m_s.ReadTimeout = value; }
		}

		public override int WriteTimeout
		{
			get { return m_s.WriteTimeout; }
			set { m_s.WriteTimeout = value; }
		}

		public WrapperStream(Stream sBase) : base()
		{
			if(sBase == null) throw new ArgumentNullException("sBase");

			m_s = sBase;
		}

		public override IAsyncResult BeginRead(byte[] buffer, int offset,
			int count, AsyncCallback callback, object state)
		{
			return m_s.BeginRead(buffer, offset, count, callback, state);
		}

		public override IAsyncResult BeginWrite(byte[] buffer, int offset,
			int count, AsyncCallback callback, object state)
		{
			return BeginWrite(buffer, offset, count, callback, state);
		}

		public override void Close()
		{
			m_s.Close();
		}

		public override int EndRead(IAsyncResult asyncResult)
		{
			return m_s.EndRead(asyncResult);
		}

		public override void EndWrite(IAsyncResult asyncResult)
		{
			m_s.EndWrite(asyncResult);
		}

		public override void Flush()
		{
			m_s.Flush();
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			return m_s.Read(buffer, offset, count);
		}

		public override int ReadByte()
		{
			return m_s.ReadByte();
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			return m_s.Seek(offset, origin);
		}

		public override void SetLength(long value)
		{
			m_s.SetLength(value);
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			m_s.Write(buffer, offset, count);
		}

		public override void WriteByte(byte value)
		{
			m_s.WriteByte(value);
		}
	}

	class IocStream : WrapperStream
	{
		private readonly boolean m_bWrite; // Initially opened for writing

		public IocStream(Stream sBase) : base(sBase)
		{
			m_bWrite = sBase.CanWrite;
		}

		public override void Close()
		{
			base.Close();

			if(MonoWorkarounds.IsRequired(10163) && m_bWrite)
			{
				try
				{
					Stream s = this.BaseStream;
					Type t = s.GetType();
					if(t.Name == "WebConnectionStream")
					{
						PropertyInfo pi = t.GetProperty("Request",
							BindingFlags.Instance | BindingFlags.NonPublic);
						if(pi != null)
						{
							WebRequest wr = (pi.GetValue(s, null) as WebRequest);
							if(wr != null)
								IOConnection.DisposeResponse(wr.GetResponse(), false);
							else { assert false; }
						}
						else { assert false; }
					}
				}
				catch(Exception) { assert false; }
			}
		}

		public static Stream WrapIfRequired(Stream s)
		{
			if(s == null) { assert false; return null; }

			if(MonoWorkarounds.IsRequired(10163) && s.CanWrite)
				return new IocStream(s);

			return s;
		}
	}
	*/

	public class IOConnection
	{

		// Web request methods
		public final static String WrmDeleteFile = "DELETEFILE";
		public final static String WrmMoveFile = "MOVEFILE";

		// Web request headers
		public final static String WrhMoveFileTo = "MoveFileTo";

		public static List<EventHandler<IOAccessEventArgs>> IOAccessPre = new ArrayList<>();

		public static InputStream OpenRead(IOConnectionInfo ioc) throws IOException
		{
			RaiseIOAccessPreEvent(ioc, IOAccessType.Read);

			return OpenReadLocal(ioc);
		}

		private static InputStream OpenReadLocal(IOConnectionInfo ioc) throws IOException
		{
			return new FileInputStream(ioc.getPath());
		}

		public static OutputStream OpenWrite(IOConnectionInfo ioc) throws IOException
		{
			RaiseIOAccessPreEvent(ioc, IOAccessType.Write);

			return OpenWriteLocal(ioc);
		}

		private static OutputStream OpenWriteLocal(IOConnectionInfo ioc) throws IOException
		{
			return new FileOutputStream(ioc.getPath(), false);
		}

		public static boolean FileExists(IOConnectionInfo ioc)
		{
			return FileExists(ioc, false);
		}

		public static boolean FileExists(IOConnectionInfo ioc, boolean bThrowErrors)
		{
			if(ioc == null) { assert false; return false; }

			RaiseIOAccessPreEvent(ioc, IOAccessType.Exists);

			if(ioc.IsLocalFile()) return new File(ioc.getPath()).exists();

			try
			{
				InputStream s = OpenRead(ioc);
				if(s == null) throw new FileNotFoundException();

				try { s.read(); }
				catch(Exception e) { }

				// We didn't download the file completely; close may throw
				// an exception -- that's okay
				try { s.close(); }
				catch(Exception e) { }
			}
			catch(Exception e)
			{
				if(bThrowErrors) throw new RuntimeException(e);
				return false;
			}

			return true;
		}

		public static boolean DeleteFile(IOConnectionInfo ioc)
		{
			RaiseIOAccessPreEvent(ioc, IOAccessType.Delete);

			if(ioc.IsLocalFile()) { return new File(ioc.getPath()).delete(); }
            return false;
		}

		/// <summary>
		/// Rename/move a file. For local file system and WebDAV, the
		/// specified file is moved, i.e. the file destination can be
		/// in a different directory/path. In contrast, for FTP the
		/// file is renamed, i.e. its destination must be in the same
		/// directory/path.
		/// </summary>
		/// <param name="iocFrom">Source file path.</param>
		/// <param name="iocTo">Target file path.</param>
		public static void RenameFile(IOConnectionInfo iocFrom, IOConnectionInfo iocTo)
		{
			RaiseIOAccessPreEvent(iocFrom, iocTo, IOAccessType.Move);

            File from = new File(iocFrom.getPath());
            File to = new File(iocTo.getPath());
			if(iocFrom.IsLocalFile()) { from.renameTo(to); return; }


			// using(Stream sIn = IOConnection.OpenRead(iocFrom))
			// {
			//	using(Stream sOut = IOConnection.OpenWrite(iocTo))
			//	{
			//		MemUtil.CopyStream(sIn, sOut);
			//		sOut.Close();
			//	}
			//
			//	sIn.Close();
			// }
			// DeleteFile(iocFrom);
		}

		public static byte[] ReadFile(IOConnectionInfo ioc) throws IOException
		{
			InputStream sIn = null;
			ByteArrayOutputStream ms = null;
			try
			{
				sIn = IOConnection.OpenRead(ioc);
				if(sIn == null) return null;

				ms = new ByteArrayOutputStream();
				MemUtil.CopyStream(sIn, ms);

				return ms.toByteArray();
			}
			catch(Exception e) { }
			finally
			{
				if(sIn != null) sIn.close();
				if(ms != null) ms.close();
			}

			return null;
		}

		private static void RaiseIOAccessPreEvent(IOConnectionInfo ioc, IOAccessType t)
		{
			RaiseIOAccessPreEvent(ioc, null, t);
		}

		private static void RaiseIOAccessPreEvent(IOConnectionInfo ioc,
			IOConnectionInfo ioc2, IOAccessType t)
		{
			if(ioc == null) { assert false; return; }
			// ioc2 may be null

			for (EventHandler<IOAccessEventArgs> h : IOConnection.IOAccessPre) {
				IOConnectionInfo ioc2Lcl = ((ioc2 != null) ? ioc2.CloneDeep() : null);
				IOAccessEventArgs e = new IOAccessEventArgs(ioc.CloneDeep(), ioc2Lcl, t);
				h.delegate(null, e);
			}
		}
	}
