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

import com.google.common.io.BaseEncoding;
import com.google.common.io.LittleEndianDataInputStream;
import com.google.common.io.LittleEndianDataOutputStream;

import java.io.*;

public class HashedBlockStream {

    public static class Output extends OutputStream {
        private final static int m_nDefaultBufferSize = 1024 * 1024; // 1 MB

        private LittleEndianDataOutputStream m_bwOutput;
        private byte[] m_pbBuffer;
        private int m_nBufferPos = 0;
        private int m_uBufferIndex = 0;
        @Override
        public void write(int b) throws IOException {
            byte[] buf = { (byte) b };
            write(buf, 0, buf.length);
        }
        @Override
        public void write(byte[] pbBuffer, int nOffset, int nCount) throws IOException
        {
            while(nCount > 0)
            {
                if(m_nBufferPos == m_pbBuffer.length)
                    WriteHashedBlock();

                int nCopy = Math.min(m_pbBuffer.length - m_nBufferPos, nCount);

                System.arraycopy(pbBuffer, nOffset, m_pbBuffer, m_nBufferPos, nCopy);

                nOffset += nCopy;
                m_nBufferPos += nCopy;

                nCount -= nCopy;
            }
        }

        private void WriteHashedBlock() throws IOException
        {
            m_bwOutput.writeInt(m_uBufferIndex);
            ++m_uBufferIndex;

            if(m_nBufferPos > 0)
            {
                byte[] pbHash;
                if(m_nBufferPos == m_pbBuffer.length)
                    pbHash = Digests.sha256(m_pbBuffer);
                else
                {
                    byte[] pbData = new byte[m_nBufferPos];
                    System.arraycopy(m_pbBuffer, 0, pbData, 0, m_nBufferPos);
                    pbHash = Digests.sha256(pbData);
                }

                m_bwOutput.write(pbHash);
            }
            else
            {
                m_bwOutput.writeLong(0); // Zero hash
                m_bwOutput.writeLong(0);
                m_bwOutput.writeLong(0);
                m_bwOutput.writeLong(0);
            }

            m_bwOutput.writeInt(m_nBufferPos);

            if(m_nBufferPos > 0)
                m_bwOutput.write(m_pbBuffer, 0, m_nBufferPos);

            m_nBufferPos = 0;
        }
        @Override
        public void flush() throws IOException
        {
            m_bwOutput.flush();
        }
        @Override
        public void close() throws IOException
        {
            if(m_nBufferPos == 0) // No data left in buffer
                WriteHashedBlock(); // Write terminating block
            else
            {
                WriteHashedBlock(); // Write remaining buffered data
                WriteHashedBlock(); // Write terminating block
            }

            flush();
            m_bwOutput.close();
            m_bwOutput = null;

        }

        public Output(OutputStream base, int nBufferSize) {
            if(nBufferSize < 0) throw new ArrayIndexOutOfBoundsException("nBufferSize");

            if(nBufferSize == 0) nBufferSize = m_nDefaultBufferSize;
            m_bwOutput = new LittleEndianDataOutputStream(base);
            m_pbBuffer = new byte[nBufferSize];
        }
    }

    public static class Input extends InputStream {
        private boolean m_bVerify;
        private boolean m_bEos = false;


        private byte[] m_pbBuffer;
        private int m_nBufferPos = 0;

        private int m_uBufferIndex = 0;

        private LittleEndianDataInputStream m_brInput;
        @Override
        public int read() throws IOException {
            byte[] buf = new byte[1];
            if (read(buf, 0, 1) == 1)
                return buf[0] & 0xff;
            else throw new IOException("could not read 1 byte");
        }

        @Override
        public int read(byte[] pbBuffer, int nOffset, int nCount)
                throws IOException
        {
            int nRemaining = nCount;
            while(nRemaining > 0)
            {
                if(m_nBufferPos == m_pbBuffer.length)
                {
                    if(!ReadHashedBlock())
                        return !m_bEos || nCount - nRemaining > 0 ? nCount - nRemaining : -1; // Bytes actually read
                }

                int nCopy = Math.min(m_pbBuffer.length - m_nBufferPos, nRemaining);

                System.arraycopy(m_pbBuffer, m_nBufferPos, pbBuffer, nOffset, nCopy);

                nOffset += nCopy;
                m_nBufferPos += nCopy;

                nRemaining -= nCopy;
            }

            return m_bEos ? -1 : nCount;
        }

        private boolean ReadHashedBlock() throws IOException
        {
            if(m_bEos) return false; // End of stream reached already

            m_nBufferPos = 0;

            if(m_brInput.readInt() != m_uBufferIndex)
                throw new KdbxFileFormatException("invalid hashed data");
            ++m_uBufferIndex;

            byte[] pbStoredHash = new byte[32];
            m_brInput.readFully(pbStoredHash);
            if((pbStoredHash == null) || (pbStoredHash.length != 32))
                throw new KdbxFileFormatException("invalid hashed data");

            int nBufferSize = m_brInput.readInt();

            if(nBufferSize < 0)
                throw new KdbxFileFormatException("no buffer");

            if(nBufferSize == 0)
            {
                for(int iHash = 0; iHash < 32; ++iHash)
                {
                    if(pbStoredHash[iHash] != 0)
                        throw new KdbxFileFormatException("invalid hash");
                }

                m_bEos = true;
                m_pbBuffer = new byte[0];
                return false;
            }

            m_pbBuffer = new byte[nBufferSize];
//            m_brInput.readFully(m_pbBuffer);

            int read = 0;
            int r = 0;
            while (read < nBufferSize && r != -1) {
                r = m_brInput.read(m_pbBuffer, read, nBufferSize - read);
                read += r;
            }

            if(m_bVerify)
            {
                byte[] pbComputedHash = Digests.sha256(m_pbBuffer);
                if((pbComputedHash == null) || (pbComputedHash.length != 32))
                    throw new KdbxFileFormatException("invalid hash");

                for(int iHashPos = 0; iHashPos < 32; ++iHashPos)
                {
                    if(pbStoredHash[iHashPos] != pbComputedHash[iHashPos])
                        throw new KdbxFileFormatException("invalid hash: " +
                            BaseEncoding.base16().encode(pbStoredHash) +
                                    " != " +
                                    BaseEncoding.base16().encode(pbComputedHash));
                }
            }

            return true;
        }
        @Override
        public void close() throws IOException
        {
            m_brInput.close();
            m_brInput = null;
        }

        public Input(InputStream base, boolean bVerify) {
            m_brInput = new LittleEndianDataInputStream(base);
            m_bVerify = bVerify;
            m_pbBuffer = new byte[0];
        }
    }
}
