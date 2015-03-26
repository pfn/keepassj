package com.hanhuy.keepassj.stream;
/*
* Copyright 2010-2013 Brian Pellin.
*
* This file is part of KeePassDroid.
*
* KeePassDroid is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* KeePassDroid is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with KeePassDroid. If not, see <http://www.gnu.org/licenses/>.
*
*/

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import com.hanhuy.keepassj.HashedBlockStream;
import org.junit.Test;

public class HashedBlock {
	
	private static Random rand = new Random();

    @Test
	public void testBlockAligned() throws IOException {
		testSize(1024, 1024);
	}

    @Test
	public void testOffset() throws IOException {
		testSize(1500, 1024);
	}

	private void testSize(int blockSize, int bufferSize) throws IOException {
		byte[] orig = new byte[blockSize];
		
		rand.nextBytes(orig);
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		HashedBlockStream.Output output = new HashedBlockStream.Output(bos, 0);
		output.write(orig);
		output.close();
		
		byte[] encoded = bos.toByteArray();
		
		ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
		HashedBlockStream.Input input = new HashedBlockStream.Input(bis, true);

		ByteArrayOutputStream decoded = new ByteArrayOutputStream();
		while ( true ) {
			byte[] buf = new byte[1024];
			int read = input.read(buf);
			if ( read == -1 ) {
				break;
			}
			
			decoded.write(buf, 0, read);
		}
		
		byte[] out = decoded.toByteArray();
		
		assertArrayEquals(orig, out);
		
	}

    @Test
	public void testGZIPStream() throws IOException {
		final int testLength = 512000;
		
		byte[] orig = new byte[testLength];
		rand.nextBytes(orig);
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		HashedBlockStream.Output hos = new HashedBlockStream.Output(bos, testLength);
		GZIPOutputStream zos = new GZIPOutputStream(hos);
		
		zos.write(orig);
		zos.close();
		
		byte[] compressed = bos.toByteArray();
		ByteArrayInputStream bis = new ByteArrayInputStream(compressed);
		HashedBlockStream.Input his = new HashedBlockStream.Input(bis, true);
		GZIPInputStream zis = new GZIPInputStream(his);
		
		byte[] uncompressed = new byte[testLength];
		
		int read = 0;
		while (read != -1 && testLength - read > 0) {
			read += zis.read(uncompressed, read, testLength - read);
			
		}
		
		assertArrayEquals("Output not equal to input", orig, uncompressed);
		
		
	}
}
