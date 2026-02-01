package org.sri.androidsecurity.analysis.taint;

import soot.Local;
import soot.SootMethod;

import java.util.HashSet;
import java.util.Set;

public class MethodTaintSummary {

    public final SootMethod method;

    // If return value is tainted
    public boolean returnsTainted = false;

    // Which parameters cause taint propagation
    public final Set<Integer> taintedParams = new HashSet<>();

    public MethodTaintSummary(SootMethod method) {
        this.method = method;
    }
}