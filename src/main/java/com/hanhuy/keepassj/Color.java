package com.hanhuy.keepassj;

public class Color {
    public final static Color Empty = new Color();

    public int R;
    public int G;
    public int B;
    public int A;
}

class ColorTranslator {
    public static Color FromHtml(String color) { return Color.Empty; }
}
