package org.sri.androidsecurity.analysis.test;

import org.sri.androidsecurity.analysis.ir.SootSetup;
import org.sri.androidsecurity.analysis.ir.IRBuilder;
import org.sri.androidsecurity.analysis.callgraph.CallGraphBuilder;

public class TestCallGraph {

    public static void main(String[] args) {

        String androidPlatforms = "C:/Android/platforms";
        String apkPath = "E:/college/BEIT/android-privacy-taint/src/main/resources/minecraft-1-20-1.apk";

        System.out.println("[+] Initializing Soot");
        SootSetup.init(androidPlatforms, apkPath);

        System.out.println("[+] Verifying IR");
        IRBuilder.buildIR();

        System.out.println("[+] Building Call Graph");
        CallGraphBuilder.buildAndPrint();

        System.out.println("[+] Step 3 completed");
    }
}
