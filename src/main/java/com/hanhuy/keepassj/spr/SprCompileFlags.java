package com.hanhuy.keepassj.spr;

/**
 * @author pfnguyen
 */ //	[Flags]
	public enum SprCompileFlags
	{
		None(0),

		AppPaths(0x1), // Paths to IE, Firefox, Opera, ...
		PickChars(0x2),
		EntryStrings(0x4),
		EntryStringsSpecial(0x8), // {URL:RMVSCM}, ...
		PasswordEnc(0x10),
		Group(0x20),
		Paths(0x40), // App-dir, doc-dir, path sep, ...
		AutoType(0x80), // Replacements like {CLEARFIELD}, ...
		DateTime(0x100),
		References(0x200),
		EnvVars(0x400),
		NewPassword(0x800),
		HmacOtp(0x1000),
		Comments(0x2000),
		TextTransforms(0x10000),
		Env(0x20000), // {BASE}, ...

		ExtActive(0x4000), // Active transformations provided by plugins
		ExtNonActive(0x8000), // Non-active transformations provided by plugins

		// Next free: 0x40000
		All(0x3FFFF),

		// Internal:
		UIInteractive(SprCompileFlags.PickChars.value),
		StateChanging((SprCompileFlags.NewPassword.value | SprCompileFlags.HmacOtp.value)),

		Active((SprCompileFlags.UIInteractive.value | SprCompileFlags.StateChanging.value |
			SprCompileFlags.ExtActive.value)),
		NonActive((SprCompileFlags.All.value & ~SprCompileFlags.Active.value)),

		Deref((SprCompileFlags.EntryStrings.value | SprCompileFlags.EntryStringsSpecial.value |
			SprCompileFlags.References.value));

        public final int value;
        public final Flags flags = or(this);
        SprCompileFlags(int value) {
            this.value = value;
        }
        public static Flags or(SprCompileFlags... options) {
            int option = 0;
            for (SprCompileFlags o : options) option |= o.value;
            Flags opt = new Flags();
            opt.value = option;
            return opt;
        }
        public static class Flags {
            int value;
            public boolean contains(SprCompileFlags option) {
                return (value & option.value) != option.value;
            }
            public boolean contains(Flags option) {
                return (value & option.value) != option.value;
            }

            public void or(SprCompileFlags option) {
                value |= option.value;
            }
        }
	}
