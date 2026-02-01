package org.sri.androidsecurity.analysis.taint;

import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.HashMap;
import java.util.Map;

public class InterProceduralAnalyzer {

    private static final Map<SootMethod, MethodTaintSummary> summaries = new HashMap<>();

    public static void analyzeProgram() {

        CallGraph cg = Scene.v().getCallGraph();

        boolean changed;

        do {
            changed = false;

            for (SootClass sc : Scene.v().getApplicationClasses()) {
                for (SootMethod m : sc.getMethods()) {

                    if (!m.isConcrete()) continue;

                    MethodTaintSummary summary =
                            summaries.computeIfAbsent(m, MethodTaintSummary::new);

                    Body body = m.retrieveActiveBody();

                    for (Unit u : body.getUnits()) {
                        Stmt stmt = (Stmt) u;

                        if (!stmt.containsInvokeExpr()) continue;

                        InvokeExpr ie = stmt.getInvokeExpr();
                        SootMethod callee = ie.getMethod();

                        MethodTaintSummary calleeSummary =
                                summaries.get(callee);

                        if (calleeSummary == null) continue;

                        // Propagate return taint
                        if (calleeSummary.returnsTainted &&
                                stmt instanceof soot.jimple.AssignStmt as &&
                                as.getLeftOp() instanceof Local l) {

                            summary.returnsTainted = true;
                            changed = true;
                        }
                    }
                }
            }
        } while (changed);
    }
}