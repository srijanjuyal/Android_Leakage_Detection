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

                System.out.println("Method: " + method.getSignature());

                // ==========================================
                // 1. BUILD STATEMENTS
                // ==========================================
                List<Statement> statements = new ArrayList<>();
                Map<Unit, Statement> unitToStmt = new HashMap<>();

                for (Unit unit : body.getUnits()) {

                    if (!(unit instanceof Stmt sootStmt)) continue;

                    Statement stmt = new Statement(sootStmt);
                    statements.add(stmt);
                    unitToStmt.put(unit, stmt);
                }

                // ==========================================
                // 2. BUILD CFG
                // ==========================================
                CFG cfg = buildCFG(body, unitToStmt);

                // ==========================================
                // 🔥 3. EXTRACT PARAMETERS (CRITICAL FIX)
                // ==========================================
                List<String> params = new ArrayList<>();

                if (!method.isStatic()) {
                    params.add("this"); // or actual local name
                }

                for (Local param : body.getParameterLocals()) {
                    params.add(param.getName());
                }

                // ==========================================
                // 4. BUILD METHOD IR
                // ==========================================
                MethodIR methodIR = new MethodIR(
                        method.getSignature(),
                        statements,
                        cfg
                );

                // 🔥 SET PARAMETERS
                methodIR.setParameters(params);

                methods.add(methodIR);
            }
        }

        return new ProgramModel(methods);
    }

    // ============================================================

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

        // Entry node
        if (!sootCFG.getHeads().isEmpty()) {
            Unit head = sootCFG.getHeads().get(0);
            Statement entry = unitToStmt.get(head);
            cfg.setEntry(entry);
        }

        return cfg;
    }
}