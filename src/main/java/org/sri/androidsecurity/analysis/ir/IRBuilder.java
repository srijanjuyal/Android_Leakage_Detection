package org.sri.androidsecurity.analysis.ir;

import soot.*;
import soot.jimple.Stmt;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;

import java.util.*;

public class IRBuilder {

    public static ProgramModel buildProgramModel() {

        List<MethodIR> methods = new ArrayList<>();

        for (SootClass sc : Scene.v().getApplicationClasses()) {

            for (SootMethod method : sc.getMethods()) {

                if (!method.isConcrete()) continue;

                Body body = method.retrieveActiveBody();

                // This is REAL IR
                System.out.println("Method: " + method.getSignature());

                // Build Statement list
                List<Statement> statements = new ArrayList<>();
                Map<Unit, Statement> unitToStmt = new HashMap<>();

                for (Unit unit : body.getUnits()) {
//                    System.out.println("  " + unit);
                    if (!(unit instanceof Stmt sootStmt)) continue;

                    Statement stmt = new Statement(sootStmt);
                    statements.add(stmt);
                    unitToStmt.put(unit, stmt);
                }

                // Build CFG (your abstraction)
                CFG cfg = buildCFG(body, unitToStmt);

//                System.out.println("CFG edges:");
//                for (Unit u : cfg) {
//                    for (Unit succ : cfg.getSuccsOf(u)) {
//                        System.out.println("  " + u + " --> " + succ);
//                    }
//                }
                MethodIR methodIR = new MethodIR(
                        method.getSignature(),
                        statements,
                        cfg
                );

                methods.add(methodIR);
            }
        }
        return new ProgramModel(methods);
    }

    private static CFG buildCFG(
            Body body,
            Map<Unit, Statement> unitToStmt) {

        UnitGraph sootCFG = new ExceptionalUnitGraph(body);

        CFG cfg = new CFG();

        for (Unit unit : sootCFG) {

            Statement from = unitToStmt.get(unit);
            if (from == null) continue;

            for (Unit succ : sootCFG.getSuccsOf(unit)) {

                Statement to = unitToStmt.get(succ);
                if (to == null) continue;

                cfg.addEdge(from, to);
            }
        }

        // Set entry node
        if (!sootCFG.getHeads().isEmpty()) {
            Unit head = sootCFG.getHeads().get(0);
            Statement entry = unitToStmt.get(head);
            cfg.setEntry(entry);
        }

        return cfg;
    }
}
