package org.sri.androidsecurity.analysis.test;

import org.sri.androidsecurity.analysis.ir.SootSetup;
import org.sri.androidsecurity.analysis.taint.InterProceduralAnalyzer;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;

public class TestTaintAnalysis {

    public static void main(String[] args) {

        // CHANGE THESE PATHS
        String androidPlatforms = "C:/Android/platforms";
        String apkPath = "E:/college/BEIT/android-privacy-taint/src/main/resources/backflash.apk";

        System.out.println("[+] Initializing Soot");
        SootSetup.init(androidPlatforms, apkPath);

        System.out.println("[+] Running taint analysis");
        InterProceduralAnalyzer.analyzeProgram();

        System.out.println("[+] Analysis finished");
    }
}
