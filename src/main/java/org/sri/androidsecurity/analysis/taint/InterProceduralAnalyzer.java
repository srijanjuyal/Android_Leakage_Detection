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

    // Method signature → summary
    private final Map<String, MethodTaintSummary> summaries = new HashMap<>();

    public void analyzeProgram(
            ProgramModel programModel, CallGraphModel callGraphModel, Set<String> entryPoints) {

        System.out.println("[+] Entry points: " + entryPoints.size());

        for (String entry : entryPoints) {

            if (!methodExists(entry, programModel)) {
                continue;
            }

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
    // Core propagation from a single Android lifecycle entry
    // ============================================================

    private void propagateFrom(
            String entrySig,
            ProgramModel programModel,
            CallGraphModel callGraphModel) {
        boolean changed;

        do {
            changed = false;

            for (MethodIR method : programModel.getMethods()) {

                String methodSig = method.getSignature();

                if (!isReachable(entrySig, methodSig, callGraphModel))
                    continue;

                MethodTaintSummary summary =
                        summaries.computeIfAbsent(
                                methodSig,
                                MethodTaintSummary::new
                        );

                // Analyze this method intra-procedurally first
                boolean intraChanged =
                        analyzeMethod(method, summary);

                if (intraChanged) {
                    changed = true;
                }

                // Propagate taint inter-procedurally
                Set<String> callees =
                        callGraphModel.getCallees(methodSig);

                for (String calleeSig : callees) {

                    MethodTaintSummary calleeSummary =
                            summaries.get(calleeSig);

                    if (calleeSummary == null) continue;

                    // If callee returns tainted → caller returns tainted
                    if (calleeSummary.returnsTainted
                            && !summary.returnsTainted) {

                        summary.returnsTainted = true;
                        changed = true;
                    }
                }
            }
        } while (changed);
    }

    /**
     * Intra-procedural analysis of a single method.
     */
    private boolean analyzeMethod(
            MethodIR method,
            MethodTaintSummary summary) {

        TaintState state = new TaintState();
        boolean changed;

        do {
            changed = false;

            for (Statement stmt : method.getStatements()) {

                // Create a copy to detect real changes
                TaintState before = state.copy();

                TaintTransfer.apply(stmt, state, state);

                if (!before.getTaintedLocals()
                        .equals(state.getTaintedLocals())) {

                    changed = true;
                }

                // Handle return taint
                if (stmt.isReturnStatement()) {
                    var ret = stmt.getReturnedLocal();

                    if (ret != null
                            && state.isTainted(ret)
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
    // Reachability from entry using DFS on CallGraphModel
    // ============================================================

    private boolean isReachable(
            String entry,
            String target,
            CallGraphModel cg) {

        if (entry.equals(target))
            return true;

        Set<String> visited = new HashSet<>();
        return dfs(entry, target, cg, visited);
    }

    private boolean dfs(
            String current,
            String target,
            CallGraphModel cg,
            Set<String> visited) {

        if (current.equals(target))
            return true;

        if (!visited.add(current))
            return false;

        for (String callee : cg.getCallees(current)) {

            if (dfs(callee, target, cg, visited))
                return true;
        }

        return false;
    }

    // ============================================================
    // Utility
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