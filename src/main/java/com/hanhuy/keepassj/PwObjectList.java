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
import java.util.*;

/// <summary>
	/// List of objects that implement <c>IDeepCloneable</c>,
	/// and cannot be <c>null</c>.
	/// </summary>
	/// <typeparam name="T">Type specifier.</typeparam>
	public class PwObjectList<T extends IDeepCloneable<T>> implements Iterable<T>
	{
		private List<T> m_vObjects = new ArrayList<T>();

		/// <summary>
		/// Get number of objects in this list.
		/// </summary>
		public int getUCount()
		{
			return (int)m_vObjects.size();
		}

		/// <summary>
		/// Construct a new list of objects.
		/// </summary>
		public PwObjectList()
		{
		}

		public Iterator<T> iterator()
		{
			return m_vObjects.iterator();
		}

		public void Clear()
		{
			// Do not destroy contained objects!
			m_vObjects.clear();
		}

		/// <summary>
		/// Clone the current <c>PwObjectList</c>, including all
		/// stored objects (deep copy).
		/// </summary>
		/// <returns>New <c>PwObjectList</c>.</returns>
		public PwObjectList<T> CloneDeep()
		{
			PwObjectList<T> pl = new PwObjectList<T>();

			for(T po : m_vObjects)
				pl.Add(po.CloneDeep());

			return pl;
		}

		public PwObjectList<T> CloneShallow()
		{
			PwObjectList<T> tNew = new PwObjectList<T>();

			for(T po : m_vObjects) tNew.Add(po);

			return tNew;
		}

		public List<T> CloneShallowToList()
		{
			PwObjectList<T> tNew = CloneShallow();
			return tNew.m_vObjects;
		}

		/// <summary>
		/// Add an object to this list.
		/// </summary>
		/// <param name="pwObject">Object to be added.</param>
		/// <exception cref="System.IllegalArgumentException">Thrown if the input
		/// parameter is <c>null</c>.</exception>
		public void Add(T pwObject)
		{
			assert pwObject != null;
			if(pwObject == null) throw new IllegalArgumentException("pwObject");

			m_vObjects.add(pwObject);
		}

		public void Add(PwObjectList<T> vObjects)
		{
			assert vObjects != null;
			if(vObjects == null) throw new IllegalArgumentException("vObjects");

			for(T po : vObjects)
			{
				m_vObjects.add(po);
			}
		}

		public void Add(List<T> vObjects)
		{
			assert vObjects != null;
			if(vObjects == null) throw new IllegalArgumentException("vObjects");

			for(T po : vObjects)
			{
				m_vObjects.add(po);
			}
		}

		public void Insert(int uIndex, T pwObject)
		{
			assert pwObject != null;
			if(pwObject == null) throw new IllegalArgumentException("pwObject");

			m_vObjects.add(uIndex, pwObject);
		}

		/// <summary>
		/// Get an object of the list.
		/// </summary>
		/// <param name="uIndex">Index of the object to get. Must be valid, otherwise an
		/// exception is thrown.</param>
		/// <returns>Reference to an existing <c>T</c> object. Is never <c>null</c>.</returns>
		public T GetAt(int uIndex)
		{
			assert uIndex < m_vObjects.size();
			if(uIndex >= m_vObjects.size()) throw new ArrayIndexOutOfBoundsException("uIndex");

			return m_vObjects.get(uIndex);
		}

		public void SetAt(int uIndex, T pwObject)
		{
			assert pwObject != null;
			if(pwObject == null) throw new IllegalArgumentException("pwObject");
			if(uIndex >= (int)m_vObjects.size())
				throw new ArrayIndexOutOfBoundsException("uIndex");

			m_vObjects.set(uIndex, pwObject);
		}

		/// <summary>
		/// Get a range of objects.
		/// </summary>
		/// <param name="uStartIndexIncl">Index of the first object to be
		/// returned (inclusive).</param>
		/// <param name="uEndIndexIncl">Index of the last object to be
		/// returned (inclusive).</param>
		/// <returns></returns>
		public List<T> GetRange(int uStartIndexIncl, int uEndIndexIncl)
		{
			if(uStartIndexIncl >= (int)m_vObjects.size())
				throw new ArrayIndexOutOfBoundsException("uStartIndexIncl");
			if(uEndIndexIncl >= (int)m_vObjects.size())
				throw new ArrayIndexOutOfBoundsException("uEndIndexIncl");
			if(uStartIndexIncl > uEndIndexIncl)
				throw new IllegalArgumentException();

			List<T> list = new ArrayList<T>((int)(uEndIndexIncl - uStartIndexIncl) + 1);
			for(int u = uStartIndexIncl; u <= uEndIndexIncl; ++u)
			{
				list.add(m_vObjects.get(u));
			}

			return list;
		}

		public int IndexOf(T pwReference)
		{
			assert pwReference != null; if(pwReference == null) throw new IllegalArgumentException("pwReference");

			return m_vObjects.indexOf(pwReference);
		}

		/// <summary>
		/// Delete an object of this list. The object to be deleted is identified
		/// by a reference handle.
		/// </summary>
		/// <param name="pwReference">Reference of the object to be deleted.</param>
		/// <returns>Returns <c>true</c> if the object was deleted, <c>false</c> if
		/// the object wasn't found in this list.</returns>
		/// <exception cref="System.IllegalArgumentException">Thrown if the input
		/// parameter is <c>null</c>.</exception>
		public boolean Remove(T pwReference)
		{
			assert pwReference != null; if(pwReference == null) throw new IllegalArgumentException("pwReference");

			return m_vObjects.remove(pwReference);
		}

		public void RemoveAt(int uIndex)
		{
			m_vObjects.remove((int)uIndex);
		}

		/// <summary>
		/// Move an object up or down.
		/// </summary>
		/// <param name="tObject">The object to be moved.</param>
		/// <param name="bUp">Move one up. If <c>false</c>, move one down.</param>
		public void MoveOne(T tObject, boolean bUp)
		{
			assert tObject != null;
			if(tObject == null) throw new IllegalArgumentException("tObject");

			int nCount = m_vObjects.size();
			if(nCount <= 1) return;

			int nIndex = m_vObjects.indexOf(tObject);
			if(nIndex < 0) { assert false; return; }

			if(bUp && (nIndex > 0)) // No assert for top item
			{
				T tTemp = m_vObjects.get(nIndex - 1);
				m_vObjects.set(nIndex - 1, m_vObjects.get(nIndex));
				m_vObjects.set(nIndex, tTemp);
			}
			else if(!bUp && (nIndex != (nCount - 1))) // No assert for bottom item
			{
				T tTemp = m_vObjects.get(nIndex + 1);
				m_vObjects.set(nIndex + 1, m_vObjects.get(nIndex));
				m_vObjects.set(nIndex, tTemp);
			}
		}

		public void MoveOne(T[] vObjects, boolean bUp)
		{
			assert vObjects != null;
			if(vObjects == null) throw new IllegalArgumentException("vObjects");

			List<Integer> lIndices = new ArrayList<Integer>();
			for(T t : vObjects)
			{
				if(t == null) { assert false; continue; }

				int p = IndexOf(t);
				if(p >= 0) lIndices.add(p);
				else { assert false; }
			}

			MoveOne(lIndices.toArray(new Integer[0]), bUp);
		}

		public void MoveOne(Integer[] vIndices, boolean bUp)
		{
			assert vIndices != null;
			if(vIndices == null) throw new IllegalArgumentException("vIndices");

			int n = m_vObjects.size();
			if(n <= 1) return; // No moving possible

			int m = vIndices.length;
			if(m == 0) return; // Nothing to move

			int[] v = new int[m];
			System.arraycopy(vIndices, 0, v, 0, m);
			Arrays.sort(v);

			if((bUp && (v[0] <= 0)) || (!bUp && (v[m - 1] >= (n - 1))))
				return; // Moving as a block is not possible

			int iStart = (bUp ? 0 : (m - 1));
			int iExcl = (bUp ? m : -1);
			int iStep = (bUp ? 1 : -1);

			for(int i = iStart; i != iExcl; i += iStep)
			{
				int p = v[i];
				if((p < 0) || (p >= n)) { assert false; continue; }

				T t = m_vObjects.get(p);

				if(bUp)
				{
					assert p > 0;
					m_vObjects.remove(p);
					m_vObjects.add(p - 1, t);
				}
				else // Down
				{
					assert p < (n - 1);
					m_vObjects.remove(p);
					m_vObjects.add(p + 1, t);
				}
			}
		}

		/// <summary>
		/// Move some of the objects in this list to the top/bottom.
		/// </summary>
		/// <param name="vObjects">List of objects to be moved.</param>
		/// <param name="bTop">Move to top. If <c>false</c>, move to bottom.</param>
		public void MoveTopBottom(T[] vObjects, boolean bTop)
		{
			assert vObjects != null;
			if(vObjects == null) throw new IllegalArgumentException("vObjects");

			if(vObjects.length == 0) return;

			int nCount = m_vObjects.size();
			for(T t : vObjects) m_vObjects.remove(t);

			if(bTop)
			{
				int nPos = 0;
				for(T t : vObjects)
				{
					m_vObjects.add(nPos, t);
					++nPos;
				}
			}
			else // Move to bottom
			{
				for(T t : vObjects) m_vObjects.add(t);
			}

			assert nCount == m_vObjects.size();
			if(nCount != m_vObjects.size())
				throw new IllegalArgumentException("At least one of the T objects in the vObjects list doesn't exist!");
		}

		public void Sort(Comparator<T> tComparer)
		{
			if(tComparer == null) throw new IllegalArgumentException("tComparer");

			Collections.sort(m_vObjects, tComparer);
		}

		public static <T extends IDeepCloneable<T>> PwObjectList FromArray(T[] tArray)
		{
			if(tArray == null) throw new IllegalArgumentException("tArray");

			PwObjectList<T> l = new PwObjectList<T>();
			for(T t : tArray) { l.Add(t); }
			return l;
		}

		public static <T extends IDeepCloneable<T>> PwObjectList FromList(List<T> tList)
		{
			if(tList == null) throw new IllegalArgumentException("tList");

			PwObjectList<T> l = new PwObjectList<T>();
			l.Add(tList);
			return l;
		}
	}
