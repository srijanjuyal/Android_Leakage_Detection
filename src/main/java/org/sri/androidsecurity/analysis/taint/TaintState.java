package org.sri.androidsecurity.analysis.taint;

import java.util.HashSet;
import java.util.Set;

public class TaintState {

    private final Set<String> taintedLocals = new HashSet<>();

    public boolean isTainted(String var) {
        return taintedLocals.contains(var);
    }

    public void addTainted(String var) {
        taintedLocals.add(var);
    }

    public void addAll(Set<String> vars) {
        taintedLocals.addAll(vars);
    }

    public Set<String> getTaintedLocals() {
        return taintedLocals;
    }

    public TaintState copy() {
        TaintState copy = new TaintState();
        copy.addAll(this.taintedLocals);
        return copy;
    }

    public boolean merge(TaintState other) {
        return taintedLocals.addAll(other.taintedLocals);
    }
}