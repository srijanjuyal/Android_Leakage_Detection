package org.sri.androidsecurity.analysis.ir;

import soot.Local;
import soot.Value;
import soot.ValueBox;
import soot.jimple.*;

import java.util.ArrayList;
import java.util.List;

public class Statement {

    private final Stmt sootStmt;

    public Statement(Stmt sootStmt) {
        this.sootStmt = sootStmt;
    }

    public Stmt getSootStmt() {
        return sootStmt;
    }

    // ==========================================
    // RETURN
    // ==========================================
    public boolean isReturnStatement() {
        return sootStmt instanceof ReturnStmt;
    }

    public String getReturnedLocal() {
        if (sootStmt instanceof ReturnStmt rs) {
            if (rs.getOp() instanceof Local l) {
                return l.getName();
            }
        }
        return null;
    }

    // ==========================================
    // INVOKE
    // ==========================================
    public boolean isInvoke() {
        return sootStmt.containsInvokeExpr();
    }

    public String getInvokeMethodSignature() {
        if (!isInvoke()) return null;

        InvokeExpr invoke = sootStmt.getInvokeExpr();
        return invoke.getMethod().getSignature();
    }

    // ==========================================
    // DEFINED VARIABLE (LEFT SIDE)
    // ==========================================
    public String getDefinedLocal() {
        if (sootStmt instanceof DefinitionStmt ds) {
            Value left = ds.getLeftOp();
            if (left instanceof Local l) {
                return l.getName();
            }
        }
        return null;
    }

    // ==========================================
    // USED VARIABLES (RIGHT SIDE / ARGS)
    // ==========================================
    public List<String> getUsedLocals() {

        List<String> locals = new ArrayList<>();

        for (ValueBox vb : sootStmt.getUseBoxes()) {
            Value v = vb.getValue();

            if (v instanceof Local l) {
                locals.add(l.getName());
            }
        }

        return locals;
    }
}