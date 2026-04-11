package org.sri.androidsecurity.analysis.rules;

import soot.SootMethod;
import java.util.Set;

public class SinkSpec {

    private static final Set<String> SINK_METHODS = Set.of(

            // =========================
            // NETWORK
            // =========================
            "<java.net.HttpURLConnection: void connect()>",
            "<java.net.HttpURLConnection: java.io.OutputStream getOutputStream()>",
            "<java.io.OutputStream: void write(byte[])>",

            // =========================
            // SMS
            // =========================
            "<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)>",

            // =========================
            // FILE WRITE
            // =========================
            "<java.io.FileOutputStream: void write(byte[])>",

            // =========================
            // INTENT SHARING
            // =========================
            "<android.content.Intent: android.content.Intent putExtra(java.lang.String,java.lang.String)>",

            // =========================
            // LOGGING
            // =========================
            "<android.util.Log: int d(java.lang.String,java.lang.String)>"
    );

    // ==========================================
    // Soot-based detection
    // ==========================================
    public static boolean isSinkMethod(SootMethod method) {
        return isSinkMethodSignature(method.getSignature());
    }

    // ==========================================
    // Signature-based detection (MAIN LOGIC)
    // ==========================================
    public static boolean isSinkMethodSignature(String sig) {

        if (sig == null) return false;

        // ✅ Exact match
        if (SINK_METHODS.contains(sig)) return true;

        // =========================
        // STANDARD SINKS
        // =========================
        if (sig.contains("HttpURLConnection") ||
            sig.contains("URLConnection")) {
            return true;
        }

        if (sig.contains("OutputStream") &&
            sig.contains("write")) {
            return true;
        }

        if (sig.contains("SmsManager") &&
            sig.contains("sendTextMessage")) {
            return true;
        }

        if (sig.contains("Intent") &&
            sig.contains("putExtra")) {
            return true;
        }

        if (sig.contains("Log")) {
            return true;
        }

        // =========================
        // 🔥 MALWARE / CUSTOM SINKS
        // =========================
        if (sig.contains("writeConfig") ||
            sig.contains("saveData") ||
            sig.contains("sendData") ||
            sig.contains("upload") ||
            sig.contains("post")) {
            return true;
        }

        // Broad suspicious sinks
        if (sig.contains("java.io") ||
            sig.contains("java.net") ||
            sig.contains("android.webkit")) {
            return true;
        }

        return false;
    }
}