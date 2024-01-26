package org.owasp.benchmarkutils.score.parsers;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.*;

/**
 * Reads in .json from the /api/jobs/{id} endpoint.
 *
 * @see <a href="https://www.sit.fraunhofer.de/en/vusc/">VUSC</a>
 */
public class VUSCReader extends Reader {
    private static final String FINISH_DATE = "finishDate";
    private static final String SUBMIT_DATE = "submitDate";
    private static final String JOB_RESULTS = "jobResults";
    private static final String VULN_FINDINGS = "vulnerabilityFindings";
    private static final String LOCATION = "location";
    private static final String TYPE = "type";
    private static final String CODE_LOCATION = "CodeLocation";
    private static final String CLASS_NAME = "className";
    private static final String REFERENCES = "references";
    private static final String VERSION = "analysisServerVersion";
    private static final String CATEGORY = "category";
    private static final String DESCRIPTION = "description";
    private static final String STATUS = "status";

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson() && resultFile.json().has("analysisServerVersion");
    }

    private final Pattern pattern =
            Pattern.compile("https?:\\/\\/cwe\\.mitre\\.org\\/data\\/definitions\\/(\\d*?)\\.html");

    private int guessCWE(JSONObject vuln) {
        String type = vuln.getString(TYPE);
        if (type.equals("Storage_DirectoryTraversalWrite")
                || type.equals("Storage_DirectoryTraversalRead")) return CweNumber.PATH_TRAVERSAL;

        System.err.println(type);
        if (type.equals("XSSAnalysis_XSS")) {
            return CweNumber.XSS;
        }

        System.err.println("Failed to guess CWE for type " + type);
        return 0;
    }

    private int extractCWE(JSONObject vuln) {
        if (!vuln.has(REFERENCES)) return guessCWE(vuln);

        Matcher matcher = pattern.matcher(vuln.getJSONArray(REFERENCES).toString());
        List<Integer> allMatches = new ArrayList<>();
        while (matcher.find()) allMatches.add(Integer.parseInt(matcher.group(1)));
        switch (allMatches.size()) {
            case 0:
                return guessCWE(vuln);
            case 1:
                return allMatches.get(0);
            default:
                // Command injection and XSS injection are also described with more specific CWEs
                if (allMatches.contains(78)) return CweNumber.COMMAND_INJECTION;
                if (allMatches.contains(79)) return CweNumber.XSS;

                // CWEs of insecure crypto and weak hashing are in a parent-child relationship. VUSC
                // groups both into a single category, but the OWASP benchmark only expects one.
                if (allMatches.size() == 2
                        && allMatches.contains(327)
                        && allMatches.contains(328)) {
                    if (vuln.getJSONObject(LOCATION)
                            .getString("statement")
                            .contains("MessageDigest")) return CweNumber.WEAK_HASH_ALGO;
                    else return CweNumber.WEAK_CRYPTO_ALGO;
                }

                System.err.println("Unexpected CWES: " + allMatches.toString());
                return 0;
        }
    }

    private String getCategory(TestCaseResult tc) {
        switch (tc.getCWE()) {
            case CweNumber.COMMAND_INJECTION:
                return "cmdi";
            case CweNumber.WEAK_CRYPTO_ALGO:
                return "crypto";
            case CweNumber.WEAK_HASH_ALGO:
                return "hash";
            case CweNumber.LDAP_INJECTION:
                return "ldapi";
            case CweNumber.PATH_TRAVERSAL:
                return "pathtraver";
            case CweNumber.INSECURE_COOKIE:
                return "securecookie";
            case CweNumber.SQL_INJECTION:
                return "sqli";
            case CweNumber.TRUST_BOUNDARY_VIOLATION:
                return "trustbound";
            case CweNumber.WEAK_RANDOM:
                return "weakrand";
            case CweNumber.XPATH_INJECTION:
                return "xpathi";
            case CweNumber.XSS:
                return "xss";
        }

        return null;
    }

    private TestCaseResult parseVulnerabilityFinding(JSONObject vuln) {
        if (!vuln.has(LOCATION)) return null;

        JSONObject loc = vuln.getJSONObject(LOCATION);
        if (!loc.getString(TYPE).equals(CODE_LOCATION)) return null;

        String className = loc.getString(CLASS_NAME);
        int innerClassIndex = className.indexOf('$');
        className =
                className.substring(
                        className.lastIndexOf('.') + 1,
                        innerClassIndex == -1 ? className.length() : innerClassIndex);
        if (!className.startsWith(BenchmarkScore.TESTCASENAME)) return null;

        TestCaseResult tc = new TestCaseResult();
        tc.setTestCaseName(className);
        tc.setNumber(Reader.testNumber(className));
        tc.setConfidence(0); // We do not have a confidence
        tc.setCWE(extractCWE(vuln));
        tc.setCategory(getCategory(tc));

        if (vuln.has(DESCRIPTION)) tc.setEvidence(vuln.getString(DESCRIPTION));

        return tc;
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        JSONObject json = resultFile.json();

        TestSuiteResults tr = new TestSuiteResults("VUSC", true, TestSuiteResults.ToolType.SAST);
        if (json.has(STATUS)) {
            int millis = json.getJSONObject(STATUS).getInt(FINISH_DATE) - json.getInt(SUBMIT_DATE);
            tr.setTime(TestSuiteResults.formatTime(millis));
        }
        tr.setToolVersion(json.getString(VERSION));

        if (!json.has(JOB_RESULTS)) return tr;

        JSONObject jr = json.getJSONObject(JOB_RESULTS);
        if (!jr.has(VULN_FINDINGS)) return tr;

        JSONArray vulns = jr.getJSONArray(VULN_FINDINGS);
        for (int i = 0; i < vulns.length(); i++) {
            TestCaseResult tc = parseVulnerabilityFinding(vulns.getJSONObject(i));
            if (tc != null) {
                tr.put(tc);
            }
        }

        return tr;
    }
}
