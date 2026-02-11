package org.sri.androidsecurity.analysis.taint;

import java.util.HashSet;
import java.util.Set;

public class MethodTaintSummary {

    public final String methodSignature;

    // If return value is tainted
    public boolean returnsTainted = false;

    // Which parameters cause taint propagation
    public final Set<Integer> taintedParams = new HashSet<>();

    public MethodTaintSummary(String methodSignature) {
        this.methodSignature = methodSignature;
    }
}