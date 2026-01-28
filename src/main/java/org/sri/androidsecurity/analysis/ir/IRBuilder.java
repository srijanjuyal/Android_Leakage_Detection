package org.sri.androidsecurity.analysis.ir;

import soot.*;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;

public class IRBuilder {

    public static void buildIR() {

        for (SootClass sc : Scene.v().getApplicationClasses()) {

            for (SootMethod method : sc.getMethods()) {

                if (!method.isConcrete()) continue;

                Body body = method.retrieveActiveBody();

                // This is REAL IR
                System.out.println("Method: " + method.getSignature());

                for (Unit unit : body.getUnits()) {
                    System.out.println("  " + unit);
                }

                // REAL CFG
                UnitGraph cfg = new ExceptionalUnitGraph(body);

                System.out.println("CFG edges:");
                for (Unit u : cfg) {
                    for (Unit succ : cfg.getSuccsOf(u)) {
                        System.out.println("  " + u + " --> " + succ);
                    }
                }
            }
        }
    }
}
