package org.sri.androidsecurity.analysis.callgraph;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.Iterator;

public class CallGraphBuilder {

    public static CallGraphModel buildCallGraphModel() {

        CallGraphModel model = new CallGraphModel();

        CallGraph sootCG = Scene.v().getCallGraph();

        Iterator<Edge> it = sootCG.iterator();

        while (it.hasNext()) {

            Edge edge = it.next();

            SootMethod src = edge.src();
            SootMethod tgt = edge.tgt();

            // Only consider application-to-application calls
            if (!src.getDeclaringClass().isApplicationClass()) continue;
            if (!tgt.getDeclaringClass().isApplicationClass()) continue;

            String callerSig = src.getSignature();
            String calleeSig = tgt.getSignature();

            model.addEdge(callerSig, calleeSig);
        }

        return model;
    }
}