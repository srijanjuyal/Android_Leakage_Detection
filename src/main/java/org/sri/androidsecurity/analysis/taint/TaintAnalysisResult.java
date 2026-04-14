package org.sri.androidsecurity.analysis.taint;

public class TaintAnalysisResult {

    private static boolean leakFound = false;

    public static void reportLeak() {
        leakFound = true;
    }

    public static boolean isLeakFound() {
        return leakFound;
    }

    public static boolean hasLeak() {
        return leakFound;
    }

    public static void reset() {
        leakFound = false;
    }
}