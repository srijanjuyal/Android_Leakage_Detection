package org.sri.androidsecurity.analysis.test;

import org.sri.androidsecurity.analysis.apk.ApkInfo;
import org.sri.androidsecurity.analysis.apk.ApkParser;
import org.sri.androidsecurity.analysis.apk.EntryPointResolver;
import org.sri.androidsecurity.analysis.callgraph.CallGraphBuilder;
import org.sri.androidsecurity.analysis.callgraph.CallGraphModel;
import org.sri.androidsecurity.analysis.ir.IRBuilder;
import org.sri.androidsecurity.analysis.ir.ProgramModel;
import org.sri.androidsecurity.analysis.ir.SootSetup;
import org.sri.androidsecurity.analysis.taint.InterProceduralAnalyzer;
import org.sri.androidsecurity.analysis.taint.MethodTaintSummary;

// 🔥 ADD THIS IMPORT
import org.sri.androidsecurity.analysis.taint.TaintAnalysisResult;

import java.util.Map;
import java.util.Set;

public class TestTaintAnalysis {

    public static void main(String[] args) {

        // RESET BEFORE RUN
        TaintAnalysisResult.reset();

        // CHANGE THESE PATHS
        String androidPlatforms = "C:/Android/platforms";
        String apkRootPath = "E:/college/BEIT/android-privacy-taint/src/main/resources/";
        String apkPath = apkRootPath + "paytm.apk";

        System.out.println("[+] Initializing Soot");
        SootSetup.init(androidPlatforms, apkPath);

        System.out.println("[+] Parsing Manifest");
        ApkParser apkParser = new ApkParser();
        ApkInfo apkInfo = apkParser.parseApk(new java.io.File(apkPath));

        System.out.println("[+] Resolving Entry Points");
        Set<String> entryPoints =
                EntryPointResolver.resolveEntryPoints(apkInfo);

        entryPoints.add("<de.ecspride.LocationLeak1$MyLocationListener: void onLocationChanged(android.location.Location)>");

        System.out.println("[+] Building Program Model");
        ProgramModel programModel = IRBuilder.buildProgramModel();

        System.out.println("[+] Building Call Graph Model");
        CallGraphModel callGraphModel = CallGraphBuilder.buildCallGraphModel();

        System.out.println("[+] Running Inter-Procedural Taint Analysis");

        InterProceduralAnalyzer analyzer = new InterProceduralAnalyzer();
        analyzer.analyzeProgram(programModel, callGraphModel, entryPoints);

        System.out.println("[+] Analysis finished");

        // Optional: print summaries
        System.out.println("\n===== Method Taint Summaries =====");

        Map<String, MethodTaintSummary> summaries =
                analyzer.getSummaries();

        for (var entry : summaries.entrySet()) {

            String methodSig = entry.getKey();
            MethodTaintSummary summary = entry.getValue();

            if (summary.returnsTainted) {
                System.out.println(
                        "[TAINTED RETURN] " + methodSig
                );
            }
        }

        // ==========================================
        // 🔥 FINAL VERDICT (ADD THIS BLOCK)
        // ==========================================

        System.out.println("\n=================================");
        System.out.println("🔍 FINAL SECURITY RESULT");
        System.out.println("=================================");

        if (TaintAnalysisResult.isLeakFound()) {
            System.out.println("❌ APK STATUS: UNSAFE (Data Leak Detected)");
        } else {
            System.out.println("✅ APK STATUS: SAFE (No Data Leak Found)");
        }

        System.out.println("\n[✓] Done.");
    }
}