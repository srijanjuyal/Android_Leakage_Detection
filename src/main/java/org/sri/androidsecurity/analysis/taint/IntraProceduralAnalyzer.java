package org.sri.androidsecurity.analysis.taint;

import soot.Body;
import soot.Unit;
import soot.toolkits.graph.UnitGraph;

import java.util.*;

public class IntraProceduralAnalyzer {

    public static TaintState analyze(Body body) {

        UnitGraph cfg = new soot.toolkits.graph.ExceptionalUnitGraph(body);

        Map<Unit, TaintState> inMap = new HashMap<>();
        Map<Unit, TaintState> outMap = new HashMap<>();

        Deque<Unit> worklist = new ArrayDeque<>();

        for (Unit u : cfg) {
            inMap.put(u, new TaintState());
            outMap.put(u, new TaintState());
        }

        Unit entry = cfg.getHeads().get(0);
        worklist.add(entry);

        while (!worklist.isEmpty()) {
            Unit u = worklist.poll();

            TaintState in = new TaintState();
            for (Unit pred : cfg.getPredsOf(u)) {
                in.merge(outMap.get(pred));
            }

            inMap.put(u, in);

            TaintState out = in.copy();
            boolean changed = TaintTransfer.apply((soot.jimple.Stmt) u, in, out);

            if (changed) {
                outMap.put(u, out);
                worklist.addAll(cfg.getSuccsOf(u));
            }
        }

        return outMap.get(entry); // not final yet
    }
}