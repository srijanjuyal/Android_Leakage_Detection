package org.sri.androidsecurity.analysis.test;

import org.sri.androidsecurity.analysis.ir.SootSetup;
import org.sri.androidsecurity.analysis.ir.IRBuilder;

public class TestIRGeneration {
    public static void main(String[] args) {

        // CHANGE THESE PATHS
        String androidPlatforms = "C:/Android/platforms";
        String apkPath = "E:/college/BEIT/android-privacy-taint/src/main/resources/paytm.apk";

        System.out.println("[+] Initializing Soot...");
        SootSetup.init(androidPlatforms, apkPath);

        System.out.println("[+] Building IR and CFG...");
        IRBuilder.buildIR();

        System.out.println("[+] Step 2 test completed.");
    }
}
