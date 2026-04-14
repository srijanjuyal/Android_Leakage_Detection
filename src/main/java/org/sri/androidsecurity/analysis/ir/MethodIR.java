package org.sri.androidsecurity.analysis.ir;

import java.util.ArrayList;
import java.util.List;

public class MethodIR {

    private final String signature;
    private final List<Statement> statements;
    private final CFG cfg;

    // ==========================================
    // 🔥 NEW: PARAMETERS (CRITICAL FOR TAINT)
    // ==========================================
    private List<String> parameters = new ArrayList<>();

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

    // ==========================================
    // 🔥 PARAMETER SUPPORT
    // ==========================================

    public void setParameters(List<String> params) {
        this.parameters = params;
    }

    public List<String> getParameters() {
        return parameters;
    }

    public String getParameter(int index) {
        if (parameters == null || index >= parameters.size()) return null;
        return parameters.get(index);
    }

    // ==========================================
    // (Optional Debug Helper)
    // ==========================================

    @Override
    public String toString() {
        return "MethodIR{" +
                "signature='" + signature + '\'' +
                ", parameters=" + parameters +
                '}';
    }
}