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

	/// <summary>
	/// Compression algorithm specifiers.
	/// </summary>
	enum PwCompressionAlgorithm
	{
		/// <summary>
		/// No compression.
		/// </summary>
		None,

		/// <summary>
		/// GZip compression.
		/// </summary>
		GZip,

		/// <summary>
		/// Virtual field: currently known number of algorithms. Should not be used
		/// by plugins or libraries -- it's used internally only.
		/// </summary>
		Count
	}

	/// <summary>
	/// Tree traversal methods.
	/// </summary>
	enum TraversalMethod
	{
		/// <summary>
		/// Don't traverse the tree.
		/// </summary>
		None,

		/// <summary>
		/// Traverse the tree in pre-order mode, i.e. first visit all items
		/// in the current node, then visit all subnodes.
		/// </summary>
		PreOrder
	}

	/// <summary>
	/// Methods for merging password databases/entries.
	/// </summary>
	enum PwMergeMethod
	{
		// Do not change the explicitly assigned values, otherwise
		// serialization (e.g. of Ecas triggers) breaks
		None,
		OverwriteExisting,
		KeepExisting,
		OverwriteIfNewer,
		CreateNewUuids,
		Synchronize
	}

enum ProxyServerType
	{
		None,
		System,
		Manual
	}

enum ProxyAuthType
{
		None,

		/// <summary>
		/// Use default user credentials (provided by the system).
		/// </summary>
		Default,

		Manual,

		/// <summary>
		/// <c>Default</c> or <c>Manual</c>, depending on whether
		/// manual credentials are available.
		/// This type exists for supporting upgrading from KeePass
		/// 2.28 to 2.29; the user cannot select this type.
		/// </summary>
		Auto
		}

	/// <summary>
	/// Comparison modes for in-memory protected objects.
	/// </summary>
	enum MemProtCmpMode
	{
		/// <summary>
		/// Ignore the in-memory protection states.
		/// </summary>
		None,

		/// <summary>
		/// Ignore the in-memory protection states of standard
		/// objects; do compare in-memory protection states of
		/// custom objects.
		/// </summary>
		CustomOnly,

		/// <summary>
		/// Compare in-memory protection states.
		/// </summary>
		Full
	}

    //[Flags]
	enum PwCompareOptions
	{
		None(0x0),

		/// <summary>
		/// Empty standard string fields are considered to be the
		/// same as non-existing standard string fields.
		/// This doesn't affect custom string comparisons.
		/// </summary>
		NullEmptyEquivStd(0x1),

		IgnoreParentGroup(0x2),
		IgnoreLastAccess(0x4),
		IgnoreLastMod(0x8),
		IgnoreHistory(0x10),
		IgnoreLastBackup(0x20),

		// For groups:
		PropertiesOnly(0x40),

		IgnoreTimes(IgnoreLastAccess.value | IgnoreLastMod.value);

        final int value;
        PwCompareOptions(int value) {
            this.value = value;
        }

        public static Options or(PwCompareOptions... options) {
            int option = 0;
            for (PwCompareOptions o : options) option |= o.value;
            Options opt = new Options();
            opt.value = option;
            return opt;
        }
        static class Options {
            int value;
            public boolean contains(PwCompareOptions option) {
                return (value & option.value) != option.value;
            }

            public void or(PwCompareOptions option) {
                value |= option.value;
            }
        }
	}

	enum IOAccessType
	{
		None,

		/// <summary>
		/// The IO connection is being opened for reading.
		/// </summary>
		Read,

		/// <summary>
		/// The IO connection is being opened for writing.
		/// </summary>
		Write,

		/// <summary>
		/// The IO connection is being opened for testing
		/// whether a file/object exists.
		/// </summary>
		Exists,

		/// <summary>
		/// The IO connection is being opened for deleting a file/object.
		/// </summary>
		Delete,

		/// <summary>
		/// The IO connection is being opened for renaming/moving a file/object.
		/// </summary>
		Move
	}

	// public enum PwLogicalOp
	// {
	//	None = 0,
	//	Or = 1,
	//	And = 2,
	//	NOr = 3,
	//	NAnd = 4
	// }

    //[Flags]
	enum AppRunFlags
	{
		None,// = 0,
		GetStdOutput,// = 1,
		WaitForExit,// = 2,

		// https://sourceforge.net/p/keepass/patches/84/
		/// <summary>
		/// This flag prevents any handles being garbage-collected
		/// before the started process has terminated, without
		/// blocking the current thread.
		/// </summary>
		GCKeepAlive,// = 4,

		// https://sourceforge.net/p/keepass/patches/85/
		DoEvents,// = 8,
		DisableForms// = 16
	}
	//[Flags]
	enum ScaleTransformFlags
{
		None,

		/// <summary>
		/// <c>UIIcon</c> indicates that the returned image is going
		/// to be displayed as icon in the UI and that it is not
		/// subject to future changes in size.
		/// </summary>
		UIIcon
		}

