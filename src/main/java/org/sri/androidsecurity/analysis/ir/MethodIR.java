package org.sri.androidsecurity.analysis.ir;

import java.util.List;

public class MethodIR {

    private final String methodSignature;
    private final List<Statement> statements;
    private final CFG cfg;

    public MethodIR(String methodSignature,
                    List<Statement> statements,
                    CFG cfg) {
        this.methodSignature = methodSignature;
        this.statements = statements;
        this.cfg = cfg;
    }

    public String getMethodSignature() {
        return methodSignature;
    }

    public List<Statement> getStatements() {
        return statements;
    }

    public CFG getCfg() {
        return cfg;
    }
}