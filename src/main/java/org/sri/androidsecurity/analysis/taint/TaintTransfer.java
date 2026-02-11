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

        // Assignment: x = y
        if (sootStmt instanceof AssignStmt as) {

            Value left = as.getLeftOp();
            Value right = as.getRightOp();

            if (left instanceof Local l && right instanceof Local r) {
                if (in.isTainted(r) && !out.isTainted(l)) {
                    out.taint(l);
                    changed = true;
                }
            }

            // SOURCE: x = source()
            if (SourceSinkManager.isSource(sootStmt) && left instanceof Local l) {
                if (!out.isTainted(l)) {
                    out.taint(l);
                    changed = true;
                }
            }
        }

        // Method invocation
        if (sootStmt.containsInvokeExpr()) {
            InvokeExpr ie = sootStmt.getInvokeExpr();

            // SINK detection
            if (SourceSinkManager.isSink(sootStmt)) {
                for (Value arg : ie.getArgs()) {
                    if (arg instanceof Local l && in.isTainted(l)) {
                        System.out.println("🔥 LEAK DETECTED at: " + stmt);
                    }
                }
            }
        }

        return changed;
    }
}