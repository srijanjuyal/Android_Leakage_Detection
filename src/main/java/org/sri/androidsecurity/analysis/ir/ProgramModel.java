package org.sri.androidsecurity.analysis.ir;

import java.util.*;

public class ProgramModel {

    private final List<MethodIR> methods;

    // 🔥 ADD THIS
    private final Map<String, MethodIR> methodMap = new HashMap<>();

    public ProgramModel(List<MethodIR> methods) {
        this.methods = methods;

        // 🔥 BUILD MAP
        for (MethodIR m : methods) {
            methodMap.put(m.getSignature(), m);
        }
    }

    public List<MethodIR> getMethods() {
        return methods;
    }

    // 🔥 ADD THIS METHOD (CRITICAL)
    public MethodIR getMethodBySignature(String signature) {
        return methodMap.get(signature);
    }
}