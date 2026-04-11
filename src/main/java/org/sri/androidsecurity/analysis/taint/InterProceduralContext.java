package org.sri.androidsecurity.analysis.taint;

import java.util.Map;

public class InterProceduralContext {

    public static Map<String, MethodTaintSummary> summaries;

    public static MethodTaintSummary getSummary(String sig) {
        if (summaries == null) return null;
        return summaries.get(sig);
    }
}