package org.sri.androidsecurity.analysis.callgraph;

import soot.*;
import soot.jimple.toolkits.callgraph.*;

public class CallGraphBuilder {

    public static void buildAndPrint() {

        CallGraph cg = Scene.v().getCallGraph();

        if (cg == null) {
            throw new IllegalStateException("Call graph not initialized");
        }

        System.out.println("\n===== CALL GRAPH EDGES =====");

        for (Edge edge : cg) {

            SootMethod src = edge.src();
            SootMethod tgt = edge.tgt();

            // Filter out framework noise (important)
            if (!src.getDeclaringClass().isApplicationClass()
                    || !tgt.getDeclaringClass().isApplicationClass()) {
                continue;
            }

            System.out.println(
                    src.getSignature() + "  -->  " + tgt.getSignature()
            );
        }
    }
}