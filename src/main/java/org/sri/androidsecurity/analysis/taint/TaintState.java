package org.sri.androidsecurity.analysis.taint;

import soot.Local;

import java.util.HashSet;
import java.util.Set;

public class TaintState {

    private final Set<Local> taintedLocals = new HashSet<>();

    public boolean isTainted(Local l) {
        return taintedLocals.contains(l);
    }

    public void taint(Local l) {
        taintedLocals.add(l);
    }

    public void taintAll(Set<Local> locals) {
        taintedLocals.addAll(locals);
    }

    public Set<Local> getTaintedLocals() {
        return taintedLocals;
    }

    public TaintState copy() {
        TaintState copy = new TaintState();
        copy.taintAll(this.taintedLocals);
        return copy;
    }

    public boolean merge(TaintState other) {
        return taintedLocals.addAll(other.taintedLocals);
    }
}