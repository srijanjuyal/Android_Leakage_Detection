package org.sri.androidsecurity.analysis.rules;

import soot.SootMethod;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

public class SourceSinkManager {

    // =========================
    // SOURCE DETECTION
    // =========================
    public static boolean isSource(Stmt stmt) {

        if (!stmt.containsInvokeExpr()) return false;

        InvokeExpr invoke = stmt.getInvokeExpr();
        SootMethod target = invoke.getMethod();

        boolean isSource = SourceSpec.isSourceMethod(target);

        if (isSource) {
            System.out.println("\n======================");
            System.out.println("[SOURCE DETECTED]");
            System.out.println("Method: " + target.getSignature());
            System.out.println("Statement: " + stmt);
            System.out.println("======================");
        }

        return isSource;
    }

    // =========================
    // SINK DETECTION
    // =========================
    public static boolean isSink(Stmt stmt) {

        if (!stmt.containsInvokeExpr()) return false;

        InvokeExpr invoke = stmt.getInvokeExpr();
        SootMethod target = invoke.getMethod();

        boolean isSink = SinkSpec.isSinkMethod(target);

        if (isSink) {
            System.out.println("\n======================");
            System.out.println("[SINK DETECTED]");
            System.out.println("Method: " + target.getSignature());
            System.out.println("Statement: " + stmt);
            System.out.println("======================");
        }

        return isSink;
    }

    // =========================
    // OPTIONAL: Get Method Signature
    // =========================
    public static String getMethodSignature(Stmt stmt) {
        if (!stmt.containsInvokeExpr()) return null;
        return stmt.getInvokeExpr().getMethod().getSignature();
    }
}