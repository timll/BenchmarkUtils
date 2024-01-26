package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.*;

public class VUSCReaderTest extends ReaderTestBase {
    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_VUSC-v2.0.0-dev.json");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlyVUSCReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, VUSCReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        VUSCReader reader = new VUSCReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("VUSC", result.getToolName());
        assertEquals(3, result.getTotalResults());
        Set<Integer> cwes =
                result.keySet().stream()
                        .map(result::get)
                        .flatMap(rl -> rl.stream().map(TestCaseResult::getCWE))
                        .collect(Collectors.toSet());
        assertEquals(3, cwes.size());
        assertFalse(cwes.contains(0));
    }
}
