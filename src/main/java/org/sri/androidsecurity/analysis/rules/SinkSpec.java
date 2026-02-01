package org.sri.androidsecurity.analysis.rules;

import soot.SootMethod;

import java.util.Set;

public class SinkSpec {

    private static final Set<String> SINK_METHODS = Set.of(
            "<java.net.HttpURLConnection: void connect()>",
            "<java.net.HttpURLConnection: java.io.OutputStream getOutputStream()>",
            "<java.io.OutputStream: void write(byte[])>",
            "<android.util.Log: int d(java.lang.String,java.lang.String)>",
            "<android.content.Intent: android.content.Intent putExtra(java.lang.String,java.lang.String)>"
    );

    public static boolean isSinkMethod(SootMethod method) {
        return SINK_METHODS.contains(method.getSignature());
    }
}