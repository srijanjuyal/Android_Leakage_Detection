package org.sri.androidsecurity.analysis.ir;

import java.util.List;

public class ProgramModel {

    private final List<MethodIR> methods;

    public ProgramModel(List<MethodIR> methods) {
        this.methods = methods;
    }

    public List<MethodIR> getMethods() {
        return methods;
    }
}
