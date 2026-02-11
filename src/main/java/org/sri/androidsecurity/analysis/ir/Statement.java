package org.sri.androidsecurity.analysis.ir;

import soot.Local;
import soot.jimple.ReturnStmt;
import soot.jimple.Stmt;

public class Statement {

    private final Stmt sootStmt;

    public Statement(Stmt sootStmt) {
        this.sootStmt = sootStmt;
    }

    public Stmt getSootStmt() {
        return sootStmt;
    }


    public boolean isReturnStatement() {
        return sootStmt instanceof ReturnStmt;
    }

    public Local getReturnedLocal() {
        if (sootStmt instanceof ReturnStmt rs) {
            if (rs.getOp() instanceof Local l) {
                return l;
            }
        }
        return null;
    }

    public boolean containsInvoke() {
        return sootStmt.containsInvokeExpr();
    }
}