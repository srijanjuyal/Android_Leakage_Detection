package org.sri.androidsecurity.analysis.taint;

import org.sri.androidsecurity.analysis.callgraph.CallGraphModel;
import org.sri.androidsecurity.analysis.ir.MethodIR;
import org.sri.androidsecurity.analysis.ir.ProgramModel;
import org.sri.androidsecurity.analysis.ir.Statement;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class InterProceduralAnalyzer {

    private final Map<String, MethodTaintSummary> summaries = new HashMap<>();

    public void analyzeProgram(
            ProgramModel programModel,
            CallGraphModel callGraphModel,
            Set<String> entryPoints) {

        // IMPORTANT (Missing in your code)
        InterProceduralContext.summaries = summaries;

        System.out.println("[+] Entry points: " + entryPoints.size());

        for (String entry : entryPoints) {
            if (!methodExists(entry, programModel)) continue;

            propagateFrom(entry, programModel, callGraphModel);
        }

        System.out.println("\n===== Tainted Methods =====");

        for (var entry : summaries.entrySet()) {
            if (entry.getValue().returnsTainted) {
                System.out.println("[TAINTED RETURN] " + entry.getKey());
            }
        }
    }

    // ============================================================

    private void propagateFrom(
            String entrySig,
            ProgramModel programModel,
            CallGraphModel callGraphModel) {

        boolean changed;
        int iteration = 0;
        int maxIterations = 100;

        do {
            changed = false;
            iteration++;

            if (iteration > maxIterations) {
                System.out.println("⚠️ Max iteration reached, stopping analysis");
                break;
            }

            for (MethodIR method : programModel.getMethods()) {

                String methodSig = method.getSignature();

                if (!isReachable(entrySig, methodSig, callGraphModel))
                    continue;

                MethodTaintSummary summary =
                        summaries.computeIfAbsent(methodSig, MethodTaintSummary::new);

                boolean intraChanged = analyzeMethod(method, summary);

                if (intraChanged) changed = true;

                // Interprocedural propagation
                for (String calleeSig : callGraphModel.getCallees(methodSig)) {

                    MethodTaintSummary calleeSummary = summaries.get(calleeSig);
                    if (calleeSummary == null) continue;

                    if (calleeSummary.returnsTainted && !summary.returnsTainted) {
                        summary.returnsTainted = true;
                        changed = true;
                    }
                }
            }

        } while (changed);
    }

    // ============================================================

    private boolean analyzeMethod(
        MethodIR method,
        MethodTaintSummary summary) {

    TaintState state = new TaintState();
    boolean changed;

    do {
        changed = false;

        for (Statement stmtWrapper : method.getStatements()) {

            var stmt = stmtWrapper.getSootStmt(); // 🔥 KEY FIX

            TaintState newState = state.copy();

            // ==========================================
            // 1. NORMAL TAINT PROPAGATION
            // ==========================================
            TaintTransfer.apply(stmtWrapper, state, newState);

            // ==========================================
            // 2. SOURCE DETECTION
            // ==========================================
            if (stmt.containsInvokeExpr()) {

                var invoke = stmt.getInvokeExpr();
                var methodSig = invoke.getMethod().getSignature();

                if (org.sri.androidsecurity.analysis.rules.SourceSpec
                        .isSourceMethod(invoke.getMethod())) {

                    // Get assigned variable (LHS)
                    if (stmt instanceof soot.jimple.AssignStmt assign) {

                        if (assign.getLeftOp() instanceof soot.Local left) {

                            newState.taint(left);

                            System.out.println("\n======================");
                            System.out.println("[SOURCE DETECTED]");
                            System.out.println("Method: " + method.getSignature());
                            System.out.println("Variable: " + left);
                            System.out.println("======================");
                        }
                    }
                }
            }

            // ==========================================
            // 3. SINK + LEAK DETECTION
            // ==========================================
            if (stmt.containsInvokeExpr()) {

                var invoke = stmt.getInvokeExpr();
                var methodSig = invoke.getMethod().getSignature();

                if (org.sri.androidsecurity.analysis.rules.SinkSpec
                        .isSinkMethod(invoke.getMethod())) {

                    for (var arg : invoke.getArgs()) {

                        if (arg instanceof soot.Local local &&
                                state.isTainted(local)) {

                            System.out.println("\n======================");
                            System.out.println("🔥 [LEAK DETECTED]");
                            System.out.println("Method: " + method.getSignature());
                            System.out.println("Sink Call: " + methodSig);
                            System.out.println("Tainted Argument: " + local);
                            System.out.println("======================");
                        }
                    }
                }
            }

            // ==========================================
            // 4. STATE UPDATE
            // ==========================================
            if (!state.getTaintedLocals().equals(newState.getTaintedLocals())) {
                state = newState;
                changed = true;
            }

            // ==========================================
            // 5. RETURN TAINT
            // ==========================================
            if (stmtWrapper.isReturnStatement()) {

                var ret = stmtWrapper.getReturnedLocal();

                if (ret != null && state.isTainted(ret)
                        && !summary.returnsTainted) {

                    summary.returnsTainted = true;
                    changed = true;
                }
            }
        }

    } while (changed);

    return summary.returnsTainted;
}

    // ============================================================

    private boolean isReachable(
            String entry,
            String target,
            CallGraphModel cg) {

        if (entry.equals(target)) return true;

        Set<String> visited = new HashSet<>();
        return dfs(entry, target, cg, visited);
    }

    private boolean dfs(
            String current,
            String target,
            CallGraphModel cg,
            Set<String> visited) {

        if (current.equals(target)) return true;

        if (visited.contains(current)) return false;
        visited.add(current);

        for (String callee : cg.getCallees(current)) {
            if (dfs(callee, target, cg, visited)) return true;
        }

        return false;
    }

    // ============================================================

    private boolean methodExists(
            String signature,
            ProgramModel programModel) {

        for (MethodIR m : programModel.getMethods()) {
            if (m.getSignature().equals(signature))
                return true;
        }
        return false;
    }

    public Map<String, MethodTaintSummary> getSummaries() {
        return summaries;
    }
}