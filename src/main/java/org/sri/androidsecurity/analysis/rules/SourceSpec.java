package org.sri.androidsecurity.analysis.rules;

import soot.SootMethod;

import java.util.Set;

public class SourceSpec {

    // Fully-qualified method signatures (Jimple-style)
    private static final Set<String> SOURCE_METHODS = Set.of(
            "<android.telephony.TelephonyManager: java.lang.String getDeviceId()>",
            "<android.telephony.TelephonyManager: java.lang.String getImei()>",
            "<android.provider.Settings$Secure: java.lang.String getString(android.content.ContentResolver,java.lang.String)>",
            "<android.location.Location: double getLatitude()>",
            "<android.location.Location: double getLongitude()>"
    );

    public static boolean isSourceMethod(SootMethod method) {
        return SOURCE_METHODS.contains(method.getSignature());
    }
}