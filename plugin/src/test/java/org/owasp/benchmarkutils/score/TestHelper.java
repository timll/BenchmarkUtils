package org.owasp.benchmarkutils.score;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import org.apache.commons.io.IOUtils;

public class TestHelper {

    public static ResultFile resultFileOf(String filename) {
        try {
            return new ResultFile(filename, contentOf(filename));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] contentOf(String filename) {
        try {
            return IOUtils.toByteArray(asStream(filename));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static InputStream asStream(String filename) {
        InputStream stream = TestHelper.class.getClassLoader().getResourceAsStream(filename);
        if (stream == null) {
            System.out.println("TEST ERROR: Test file: " + filename + " does not exist");
        }
        return Objects.requireNonNull(stream);
    }
}