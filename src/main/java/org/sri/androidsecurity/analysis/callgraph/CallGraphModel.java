package org.sri.androidsecurity.analysis.callgraph;

import java.util.*;

public class CallGraphModel {

    private final Map<String, Set<String>> edges = new HashMap<>();

    public void addEdge(String caller, String callee) {
        edges.computeIfAbsent(caller, k -> new HashSet<>()).add(callee);
    }

    public Set<String> getCallees(String caller) {
        return edges.getOrDefault(caller, Set.of());
    }
}