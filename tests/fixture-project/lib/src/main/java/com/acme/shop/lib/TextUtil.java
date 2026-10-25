package com.acme.shop.lib;

import com.google.common.base.Strings;
import com.google.common.io.Files;

public final class TextUtil {
    private TextUtil() {}

    public static boolean blank(String s) { return Strings.isNullOrEmpty(s); }

    public static java.io.File scratch() { return Files.createTempDir(); }
}
