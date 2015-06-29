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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;

class HashingInputStreamEx extends InputStream implements HashingStreamEx {
    final InputStream base;
    final StreamHashing hashing;
    public HashingInputStreamEx(InputStream base) {
        this.base = base;
        hashing = new StreamHashing();
    }

    @Override
    public int read() throws IOException {
        byte[] b = new byte[1];
        return read(b, 0, 1);
    }
    @Override
    public int read(byte[] pbBuffer, int nOffset, int nCount) throws IOException
    {
        int nRead = base.read(pbBuffer, nOffset, nCount);
        int nPartialRead = nRead;
        while((nRead < nCount) && (nPartialRead != -1))
        {
            nPartialRead = base.read(pbBuffer, nOffset + nRead,
                    nCount - nRead);
            if (nPartialRead != -1)
                nRead += nPartialRead;
        }

        if(nRead > 0)
            hashing.hash(pbBuffer, nOffset, nRead);

        return nRead;
    }

    @Override
    public byte[] getHash() {
        return hashing.getHash();
    }

    @Override
    public void close() throws IOException {
        hashing.Dispose(true);
        base.close();
    }
}
class HashingOutputStreamEx extends OutputStream implements HashingStreamEx {
    final OutputStream base;
    final StreamHashing hashing;
    public HashingOutputStreamEx(OutputStream base) {
        this.base = base;
        hashing = new StreamHashing();
    }

    @Override
    public void write(int b) throws IOException {
        byte[] buf = { (byte)b };
        write(buf, 0, 1);
    }
    @Override
    public void write(byte[] pbBuffer, int nOffset, int nCount) throws IOException
    {
        if(nCount > 0)
            hashing.hash(pbBuffer, nOffset, nCount);

        base.write(pbBuffer, nOffset, nCount);
    }

    @Override
    public byte[] getHash() {
        return hashing.getHash();
    }

    @Override
    public void close() throws IOException {
        hashing.Dispose(true);
        base.close();
    }

    @Override
    public void flush() throws IOException {
        base.flush();
    }
}

interface HashingStreamEx {
    public byte[] getHash();
}
class StreamHashing
	{
		private MessageDigest m_hash;

		private byte[] m_pbFinalHash = null;

		public byte[] getHash()
		{
            if (m_pbFinalHash == null) throw new IllegalStateException("hash not ready");
			return m_pbFinalHash;
		}

		public StreamHashing()
		{

            try {
                m_hash = Digests.getInstance().sha256();
            } catch (Exception e) { throw new RuntimeException(e); }
			if(m_hash == null) { assert false; }
		}

		protected void Dispose(boolean disposing)
		{
			if(!disposing) return;
			if(m_hash != null)
			{
				try
				{
					m_pbFinalHash = m_hash.digest();
				}
				catch(Exception e) { assert false; }

				m_hash = null;
			}
		}

        void hash(byte[] buffer, int offset, int count) {
            m_hash.update(buffer, offset, count);
        }


	}
