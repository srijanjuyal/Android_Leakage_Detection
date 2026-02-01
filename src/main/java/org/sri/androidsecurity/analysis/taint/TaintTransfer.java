package org.sri.androidsecurity.analysis.taint;

import org.sri.androidsecurity.analysis.rules.SourceSinkManager;
import soot.Local;
import soot.Value;
import soot.jimple.*;

public class TaintTransfer {

    public static boolean apply(Stmt stmt, TaintState in, TaintState out) {

        boolean changed = false;

        // Assignment: x = y
        if (stmt instanceof AssignStmt as) {

            Value left = as.getLeftOp();
            Value right = as.getRightOp();

            if (left instanceof Local l && right instanceof Local r) {
                if (in.isTainted(r) && !out.isTainted(l)) {
                    out.taint(l);
                    changed = true;
                }
            }

            // SOURCE: x = source()
            if (SourceSinkManager.isSource(stmt) && left instanceof Local l) {
                if (!out.isTainted(l)) {
                    out.taint(l);
                    changed = true;
                }
            }
        }

        // Method invocation
        if (stmt.containsInvokeExpr()) {
            InvokeExpr ie = stmt.getInvokeExpr();

            // SINK detection
            if (SourceSinkManager.isSink(stmt)) {
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