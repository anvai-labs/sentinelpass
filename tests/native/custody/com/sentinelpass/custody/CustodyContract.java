package com.sentinelpass.custody;

import java.nio.file.Files;
import java.nio.file.Path;

/** Host JVM contract probe, not an Android provider or replacement Kotlin facade. */
public final class CustodyContract {
    public static native int validateMetadata(int abi, int kind, byte[] metadata);

    private static void expect(int expected, int actual) {
        if (expected != actual) throw new AssertionError("custody metadata JNI result mismatch");
    }

    public static void main(String[] args) throws Exception {
        System.load(Path.of(args[0]).toAbsolutePath().toString());
        byte[] scope = Files.readAllBytes(Path.of(args[1], "scope.golden.json"));
        byte[] reference = Files.readAllBytes(Path.of(args[1], "reference.golden.json"));
        expect(0, validateMetadata(2, 1, scope));
        expect(0, validateMetadata(2, 2, reference));
        expect(-14, validateMetadata(1, 1, scope));
        expect(-14, validateMetadata(3, 1, scope));
        expect(-1, validateMetadata(2, 0, scope));
        expect(-1, validateMetadata(2, 1, reference));
        expect(-1, validateMetadata(2, 1, null));
        expect(-1, validateMetadata(2, 1, new byte[4097]));
        expect(-1, validateMetadata(2, 1, new byte[] {(byte) 0xff}));
        String[] names = {"scope", "reference", "capabilities"};
        for (int index = 0; index < names.length; index++) {
            byte[] bytes = Files.readAllBytes(Path.of(args[1], names[index] + ".array.invalid.json"));
            expect(-1, validateMetadata(2, index + 1, bytes));
        }
        System.out.println("custody metadata host JVM: 12 checks passed");
    }
}
