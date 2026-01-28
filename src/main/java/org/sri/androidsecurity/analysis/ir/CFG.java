package org.sri.androidsecurity.analysis.ir;

import java.util.*;

public class CFG {

    private final Map<Statement, List<Statement>> edges = new HashMap<>();
    private Statement entry;

    public void setEntry(Statement entry) {
        this.entry = entry;
    }

    public Statement getEntry() {
        return entry;
    }

    public void addEdge(Statement from, Statement to) {
        edges.computeIfAbsent(from, k -> new ArrayList<>()).add(to);
    }

    public List<Statement> getSuccessors(Statement s) {
        return edges.getOrDefault(s, List.of());
    }
}