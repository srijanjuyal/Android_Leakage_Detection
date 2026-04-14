package org.sri.androidsecurity.analysis.taint;

import org.sri.androidsecurity.analysis.callgraph.CallGraphModel;
import org.sri.androidsecurity.analysis.ir.MethodIR;
import org.sri.androidsecurity.analysis.ir.ProgramModel;
import org.sri.androidsecurity.analysis.ir.Statement;

import java.util.*;

public class InterProceduralAnalyzer {

    private final Map<String, MethodTaintSummary> summaries = new HashMap<>();

    // Prevent recursion loops
    private final Set<String> visiting = new HashSet<>();

    // 🔥 NEW: Avoid duplicate leak printing
    private final Set<String> reportedLeaks = new HashSet<>();

    // 🔥 NEW: Avoid re-analyzing same method repeatedly
    private final Set<String> analyzedMethods = new HashSet<>();

    // ============================================================

    public void analyzeProgram(
            ProgramModel programModel,
            CallGraphModel callGraphModel,
            Set<String> entryPoints) {

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

        do {
            changed = false;
            iteration++;

            if (iteration > 50) break; // 🔥 limit

            for (MethodIR method : programModel.getMethods()) {

                if (TaintAnalysisResult.hasLeak()) return; // 🔥 early stop

                String methodSig = method.getSignature();

                if (!isReachable(entrySig, methodSig, callGraphModel))
                    continue;

                MethodTaintSummary summary =
                        summaries.computeIfAbsent(methodSig, MethodTaintSummary::new);

                boolean intraChanged = analyzeMethod(method, programModel);

                if (intraChanged) changed = true;

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
            ProgramModel programModel) {

        // 🔥 Skip already analyzed methods
        if (analyzedMethods.contains(method.getSignature())) return false;
        analyzedMethods.add(method.getSignature());

        MethodTaintSummary summary =
                summaries.computeIfAbsent(method.getSignature(), MethodTaintSummary::new);

        TaintState state = new TaintState();
        boolean changed;
        int iter = 0;

        do {
            changed = false;
            iter++;

            if (iter > 50) break;

            for (Statement stmt : method.getStatements()) {

                if (TaintAnalysisResult.hasLeak()) return true; // 🔥 stop early

                TaintState newState = state.copy();

                // ==========================================
                // 1. NORMAL PROPAGATION
                // ==========================================
                TaintTransfer.apply(stmt, state, newState);

                // ==========================================
                // 2. SOURCE DETECTION
                // ==========================================
                if (stmt.isInvoke()) {

                    String sig = stmt.getInvokeMethodSignature();

                    if (org.sri.androidsecurity.analysis.rules.SourceSpec
                            .isSourceMethodSignature(sig)) {

                        String def = stmt.getDefinedLocal();

                        if (def != null) newState.addTainted(def);

                        for (String used : stmt.getUsedLocals()) {
                            newState.addTainted(used);
                        }

                        System.out.println("\n======================");
                        System.out.println("[SOURCE DETECTED]");
                        System.out.println("Method: " + method.getSignature());
                        System.out.println("Source Call: " + sig);
                        System.out.println("======================");
                    }
                }

                // ==========================================
                // 3. INTERPROCEDURAL CALL
                // ==========================================
                if (stmt.isInvoke()) {

                    String calleeSig = stmt.getInvokeMethodSignature();
                    MethodIR callee = programModel.getMethodBySignature(calleeSig);

                    if (callee != null && !visiting.contains(calleeSig)) {

                        visiting.add(calleeSig);

                        TaintState calleeState = new TaintState();

                        List<String> args = stmt.getUsedLocals();
                        List<String> params = callee.getParameters();

                        int limit = Math.min(args.size(), params.size());

                        for (int i = 0; i < limit; i++) {

                            String arg = args.get(i);

                            if (newState.isTainted(arg)) {

                                String param = params.get(i);

                                if (param != null) {
                                    calleeState.addTainted(param);
                                }
                            }
                        }

                        analyzeMethodWithState(callee, calleeState, programModel);

                        visiting.remove(calleeSig);

                        MethodTaintSummary calleeSummary =
                                summaries.computeIfAbsent(calleeSig, MethodTaintSummary::new);

                        if (calleeSummary.returnsTainted) {

                            String left = stmt.getDefinedLocal();

                            if (left != null && !newState.isTainted(left)) {
                                newState.addTainted(left);
                                changed = true;
                            }
                        }
                    }
                }

                // ==========================================
                // 4. SINK DETECTION (DEDUP FIX)
                // ==========================================
                if (stmt.isInvoke()) {

                    String sig = stmt.getInvokeMethodSignature();

                    if (org.sri.androidsecurity.analysis.rules.SinkSpec
                            .isSinkMethodSignature(sig)
                            || sig.contains("access$")) {

                        for (String arg : stmt.getUsedLocals()) {

                            if (newState.isTainted(arg)) {

                                String leakKey =
                                        method.getSignature() + "|" + sig + "|" + arg;

                                if (!reportedLeaks.contains(leakKey)) {

                                    reportedLeaks.add(leakKey);

                                    System.out.println("\n======================");
                                    System.out.println("🔥 [LEAK DETECTED]");
                                    System.out.println("Method: " + method.getSignature());
                                    System.out.println("Sink Call: " + sig);
                                    System.out.println("Tainted Argument: " + arg);
                                    System.out.println("======================");

                                    TaintAnalysisResult.reportLeak();
                                }
                            }
                        }
                    }
                }

                // ==========================================
                // 5. UPDATE STATE
                // ==========================================
                if (!state.getTaintedLocals().equals(newState.getTaintedLocals())) {
                    state = newState;
                    changed = true;
                }

                // ==========================================
                // 6. RETURN TAINT
                // ==========================================
                if (stmt.isReturnStatement()) {

                    String ret = stmt.getReturnedLocal();

                    if (ret != null && state.isTainted(ret)) {
                        summary.returnsTainted = true;
                    }
                }
            }

        } while (changed);

        return summary.returnsTainted;
    }

    // ============================================================

    private boolean analyzeMethodWithState(
            MethodIR method,
            TaintState initialState,
            ProgramModel programModel) {

        MethodTaintSummary summary =
                summaries.computeIfAbsent(method.getSignature(), MethodTaintSummary::new);

        TaintState state = initialState.copy();
        boolean changed;
        int iter = 0;

        do {
            changed = false;
            iter++;

            if (iter > 50) break;

            for (Statement stmt : method.getStatements()) {

                if (TaintAnalysisResult.hasLeak()) return true;

                TaintState newState = state.copy();

                TaintTransfer.apply(stmt, state, newState);

                if (stmt.isInvoke()) {

                    String sig = stmt.getInvokeMethodSignature();

                    if (org.sri.androidsecurity.analysis.rules.SinkSpec
                            .isSinkMethodSignature(sig)
                            || sig.contains("access$")) {

                        for (String arg : stmt.getUsedLocals()) {

                            if (newState.isTainted(arg)) {

                                String leakKey =
                                        method.getSignature() + "|" + sig + "|" + arg;

                                if (!reportedLeaks.contains(leakKey)) {

                                    reportedLeaks.add(leakKey);

                                    System.out.println("\n======================");
                                    System.out.println("🔥 [LEAK DETECTED - INTERPROC]");
                                    System.out.println("Method: " + method.getSignature());
                                    System.out.println("Sink Call: " + sig);
                                    System.out.println("Tainted Argument: " + arg);
                                    System.out.println("======================");

                                    TaintAnalysisResult.reportLeak();
                                }
                            }
                        }
                    }
                }

                if (!state.getTaintedLocals().equals(newState.getTaintedLocals())) {
                    state = newState;
                    changed = true;
                }

                if (stmt.isReturnStatement()) {

                    String ret = stmt.getReturnedLocal();

                    if (ret != null && state.isTainted(ret)) {
                        summary.returnsTainted = true;
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