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

    // ==========================================
    // 1. EXACT MATCH (MOST RELIABLE)
    // ==========================================
    if (SOURCE_METHODS.contains(sig)) return true;

    // ==========================================
    // 2. CONTROLLED PATTERN MATCHING (SAFE)
    // ==========================================

    // DEVICE IDENTIFIERS
    if (sig.contains("TelephonyManager") &&
        (sig.contains("getDeviceId") ||
         sig.contains("getSubscriberId") ||
         sig.contains("getLine1Number") ||
         sig.contains("getImei"))) {
        return true;
    }

    // LOCATION (ONLY DATA ACCESS, NOT REGISTRATION APIs)
    if (sig.contains("android.location.Location") &&
        (sig.contains("getLatitude") ||
         sig.contains("getLongitude"))) {
        return true;
    }

    if (sig.contains("LocationManager") &&
        sig.contains("getLastKnownLocation")) {
        return true;
    }

    // CONTENT RESOLVER (CONTACTS ETC.)
    if (sig.contains("ContentResolver") &&
        sig.contains("query")) {
        return true;
    }

    // ==========================================
    // 3. CUSTOM / MALWARE SOURCES (OPTIONAL)
    // ==========================================
    if (sig.contains("readConfig") ||
        sig.contains("getDevice") ||
        sig.contains("getData") ||
        sig.contains("loadData")) {
        return true;
    }

    // ==========================================
    // 🚫 REMOVE ALL BROAD MATCHING
    // ==========================================
    // ❌ NO sig.contains("android.location")
    // ❌ NO sig.contains("android.telephony")
    // ❌ NO sig.contains("android.net")

    return false;
    }
}