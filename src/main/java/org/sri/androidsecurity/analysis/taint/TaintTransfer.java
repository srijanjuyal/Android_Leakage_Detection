package org.sri.androidsecurity.analysis.taint;

import org.sri.androidsecurity.analysis.ir.Statement;

public class TaintTransfer {

    public static boolean apply(Statement stmt, TaintState in, TaintState out) {

        boolean changed = false;

        String left = stmt.getDefinedLocal();

        // ==========================================
        // 1. NORMAL ASSIGNMENT: x = y
        // ==========================================
        if (left != null) {

            for (String used : stmt.getUsedLocals()) {

                if (in.isTainted(used)) {

                    // Propagate taint to LHS
                    if (!out.isTainted(left)) {
                        out.addTainted(left);
                        changed = true;
                    }
                }
            }
        }

        // ==========================================
        // 2. METHOD CALL HANDLING (CORE LOGIC)
        // ==========================================
        if (stmt.isInvoke()) {

            String methodSig = stmt.getInvokeMethodSignature();

            boolean anyArgTainted = false;

            for (String arg : stmt.getUsedLocals()) {
                if (in.isTainted(arg)) {
                    anyArgTainted = true;
                    break;
                }
            }

            // ==========================================
            // 2A. ARG → RETURN FLOW (x = foo(tainted))
            // ==========================================
            if (anyArgTainted && left != null) {

                if (!out.isTainted(left)) {
                    out.addTainted(left);
                    changed = true;
                }
            }

            // ==========================================
            // 2B. VOID METHOD PROPAGATION (🔥 CRITICAL FIX)
            // Handles cases like:
            // access$0(obj, taintedData)
            // ==========================================
            if (anyArgTainted && left == null) {

                for (String arg : stmt.getUsedLocals()) {

                    if (!out.isTainted(arg)) {
                        out.addTainted(arg);
                        changed = true;
                    }
                }
            }

            // ==========================================
            // 2C. INTERPROCEDURAL RETURN FLOW
            // ==========================================
            MethodTaintSummary summary =
                    InterProceduralContext.getSummary(methodSig);

            if (summary != null && summary.returnsTainted && left != null) {

                if (!out.isTainted(left)) {
                    out.addTainted(left);
                    changed = true;
                }
            }
        }

        return changed;
    }
}