package org.sri.androidsecurity.analysis.rules;

import soot.SootMethod;
import java.util.Set;

public class SourceSpec {

    private static final Set<String> SOURCE_METHODS = Set.of(

            // =========================
            // DEVICE IDENTIFIERS
            // =========================
            "<android.telephony.TelephonyManager: java.lang.String getDeviceId()>",
            "<android.telephony.TelephonyManager: java.lang.String getImei()>",
            "<android.telephony.TelephonyManager: java.lang.String getSubscriberId()>",
            "<android.telephony.TelephonyManager: java.lang.String getLine1Number()>",

            // =========================
            // LOCATION
            // =========================
            "<android.location.Location: double getLatitude()>",
            "<android.location.Location: double getLongitude()>",
            "<android.location.LocationManager: android.location.Location getLastKnownLocation()>",

            // =========================
            // ANDROID ID
            // =========================
            "<android.provider.Settings$Secure: java.lang.String getString(android.content.ContentResolver,java.lang.String)>",

            // =========================
            // CONTACTS / DATA
            // =========================
            "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>",

            // =========================
            // NETWORK / DEVICE INFO
            // =========================
            "<android.net.wifi.WifiInfo: java.lang.String getMacAddress()>",
            "<android.accounts.AccountManager: android.accounts.Account[] getAccounts()>"
    );

    // ==========================================
    // Soot-based exact detection
    // ==========================================
    public static boolean isSourceMethod(SootMethod method) {
        return isSourceMethodSignature(method.getSignature());
    }

    // ==========================================
    // Signature-based detection (MAIN LOGIC)
    // ==========================================
    public static boolean isSourceMethodSignature(String sig) {

        if (sig == null) return false;

        // ✅ Exact match
        if (SOURCE_METHODS.contains(sig)) return true;

        // =========================
        // STANDARD ANDROID SOURCES
        // =========================
        if (sig.contains("TelephonyManager") &&
                (sig.contains("getDeviceId") ||
                 sig.contains("getSubscriberId") ||
                 sig.contains("getLine1Number") ||
                 sig.contains("getImei"))) {
            return true;
        }

        if (sig.contains("Location") &&
                (sig.contains("getLatitude") ||
                 sig.contains("getLongitude") ||
                 sig.contains("getLastKnownLocation"))) {
            return true;
        }

        if (sig.contains("ContentResolver") &&
                sig.contains("query")) {
            return true;
        }

        // =========================
        // 🔥 MALWARE / CUSTOM SOURCES
        // =========================
        if (sig.contains("readConfig") ||
            sig.contains("getDevice") ||
            sig.contains("getData") ||
            sig.contains("loadData")) {
            return true;
        }

        // Broad Android sensitive APIs
        if (sig.contains("android.telephony") ||
            sig.contains("android.location") ||
            sig.contains("android.accounts") ||
            sig.contains("android.net")) {
            return true;
        }

        return false;
    }
}