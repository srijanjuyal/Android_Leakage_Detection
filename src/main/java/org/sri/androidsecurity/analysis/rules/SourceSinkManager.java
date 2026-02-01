package org.sri.androidsecurity.analysis.rules;

import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

public class SourceSinkManager {

    public static boolean isSource(Stmt stmt) {
        if (!stmt.containsInvokeExpr()) return false;

        InvokeExpr invoke = stmt.getInvokeExpr();
        SootMethod target = invoke.getMethod();

        return SourceSpec.isSourceMethod(target);
    }

    public static boolean isSink(Stmt stmt) {
        if (!stmt.containsInvokeExpr()) return false;

        InvokeExpr invoke = stmt.getInvokeExpr();
        SootMethod target = invoke.getMethod();

        return SinkSpec.isSinkMethod(target);
    }
}