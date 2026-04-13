package org.sri.androidsecurity.analysis.taint;

import org.sri.androidsecurity.analysis.ir.Statement;
import org.sri.androidsecurity.analysis.rules.SourceSinkManager;
import soot.Local;
import soot.Value;
import soot.jimple.*;

public class TaintTransfer {

    public static boolean apply(Statement stmt, TaintState in, TaintState out) {

        boolean changed = false;
        var sootStmt = stmt.getSootStmt();

        // ============================
        // Assignment: x = y OR x = foo()
        // ============================
        if (sootStmt instanceof AssignStmt as) {

            Value left = as.getLeftOp();
            Value right = as.getRightOp();

            // Case 1: x = y
            if (left instanceof Local l && right instanceof Local r) {
                if (in.isTainted(r) && !out.isTainted(l)) {
                    out.taint(l);
                    changed = true;
                }
            }

            // Case 2: x = source()
            if (right instanceof InvokeExpr ie && left instanceof Local l) {

                // Source detection
                if (SourceSinkManager.isSource(sootStmt)) {
                    if (!out.isTainted(l)) {
                        out.taint(l);
                        changed = true;
                    }
                }

                // 🔥 NEW: Return taint propagation
                String methodSig = ie.getMethod().getSignature();

                MethodTaintSummary summary =
                        InterProceduralContext.getSummary(methodSig);

                if (summary != null && summary.returnsTainted) {
                    if (!out.isTainted(l)) {
                        out.taint(l);
                        changed = true;
                    }
                }
            }
        }

        // ============================
        // Method invocation (SINK)
        // ============================
        if (sootStmt.containsInvokeExpr()) {

            InvokeExpr ie = sootStmt.getInvokeExpr();

            if (SourceSinkManager.isSink(sootStmt)) {

                for (Value arg : ie.getArgs()) {

                    if (arg instanceof Local l &&
                            (in.isTainted(l) || out.isTainted(l))) {

                        System.out.println(" LEAK DETECTED at: " + stmt);
                        System.out.println("   Tainted variable: " + l);
                    }
                }
            }
        }

        return changed;
    }
}