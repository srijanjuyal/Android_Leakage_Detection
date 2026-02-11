package org.sri.androidsecurity.analysis.ir;

import java.util.List;

public class MethodIR {

    // signature is methodSignature
    private final String signature;
    private final List<Statement> statements;
    private final CFG cfg;

    public MethodIR(String signature,
                    List<Statement> statements,
                    CFG cfg) {
        this.signature = signature;
        this.statements = statements;
        this.cfg = cfg;
    }

    public String getSignature() {
        return signature;
    }

    public List<Statement> getStatements() {
        return statements;
    }

    public CFG getCfg() {
        return cfg;
    }
}