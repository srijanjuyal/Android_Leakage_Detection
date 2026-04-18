package org.sri.androidsecurity.analysis.web;

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
import org.sri.androidsecurity.analysis.taint.TaintAnalysisResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;

/**
 * Runs the taint analysis asynchronously.
 * Captures every System.out.println() call and streams them to the job's queue.
 */
@Service
public class AnalysisService {

    @Value("${android.platforms.path:C:/Android/platforms}")
    private String androidPlatformsPath;

    // In-memory store of active/recent jobs (could be replaced with a cache)
    private final ConcurrentHashMap<String, AnalysisJob> jobs = new ConcurrentHashMap<>();

    private final ExecutorService executor = Executors.newCachedThreadPool();

    // -----------------------------------------------------------------------
    //  Public API
    // -----------------------------------------------------------------------

    /**
     * Submit an APK for analysis. Returns the job immediately; analysis runs
     * in background. Use {@link #getJob(String)} + SSE to stream output.
     */
    public AnalysisJob submitJob(Path apkPath) {
        String jobId = UUID.randomUUID().toString();
        AnalysisJob job = new AnalysisJob(jobId);
        jobs.put(jobId, job);

        executor.submit(() -> runAnalysis(job, apkPath));
        return job;
    }

    public AnalysisJob getJob(String jobId) {
        return jobs.get(jobId);
    }

    // -----------------------------------------------------------------------
    //  Internal – runs on a worker thread
    // -----------------------------------------------------------------------

    private void runAnalysis(AnalysisJob job, Path apkPath) {

        // Redirect System.out so every println goes to the job queue
        PrintStream originalOut = System.out;
        PrintStream capturingStream = buildCapturingStream(originalOut, job);
        System.setOut(capturingStream);

        try {
            TaintAnalysisResult.reset();
            String apkFile = apkPath.toAbsolutePath().toString();

            job.pushLine("[+] Initializing Soot");
            SootSetup.init(androidPlatformsPath, apkFile);

            job.pushLine("[+] Parsing Manifest");
            ApkParser apkParser = new ApkParser();
            ApkInfo apkInfo = apkParser.parseApk(apkPath.toFile());

            job.pushLine("[+] Resolving Entry Points");
            Set<String> entryPoints = EntryPointResolver.resolveEntryPoints(apkInfo);

            job.pushLine("[+] Building Program Model");
            ProgramModel programModel = IRBuilder.buildProgramModel();

            job.pushLine("[+] Building Call Graph Model");
            CallGraphModel callGraphModel = CallGraphBuilder.buildCallGraphModel();

            job.pushLine("[+] Running Inter-Procedural Taint Analysis");
            InterProceduralAnalyzer analyzer = new InterProceduralAnalyzer();
            analyzer.analyzeProgram(programModel, callGraphModel, entryPoints);

            job.pushLine("[+] Analysis finished");

            // --- Method taint summaries ---
            job.pushLine("");
            job.pushLine("===== Method Taint Summaries =====");
            Map<String, MethodTaintSummary> summaries = analyzer.getSummaries();
            int taintedCount = 0;
            for (var entry : summaries.entrySet()) {
                if (entry.getValue().returnsTainted) {
                    job.pushLine("[TAINTED RETURN] " + entry.getKey());
                    taintedCount++;
                }
            }
            if (taintedCount == 0) {
                job.pushLine("(no tainted return methods found)");
            }

            // --- Final verdict ---
            job.pushLine("");
            job.pushLine("=================================");
            job.pushLine("FINAL SECURITY RESULT");
            job.pushLine("=================================");
            boolean leak = TaintAnalysisResult.isLeakFound();
            if (leak) {
                job.pushLine("APK STATUS: UNSAFE - Data Leak Detected");
            } else {
                job.pushLine("APK STATUS: SAFE - No Data Leak Found");
            }
            job.pushLine("");
            job.pushLine("[✓] Done.");

            job.finish(leak);

        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            job.fail("Exception during analysis: " + e.getMessage() + "\n" + sw);
        } finally {
            // Always restore original System.out
            System.setOut(originalOut);
            // Clean up temp APK after a delay
            executor.submit(() -> {
                try { Thread.sleep(60_000); apkPath.toFile().delete(); } catch (InterruptedException ignored) {}
            });
        }
    }

    /**
     * Builds a PrintStream that writes to both the real stdout AND the job queue.
     * This means all Soot/library println() calls are also captured automatically.
     */
    private PrintStream buildCapturingStream(PrintStream original, AnalysisJob job) {
        OutputStream tee = new OutputStream() {
            private final StringBuilder lineBuffer = new StringBuilder();

            @Override
            public void write(int b) {
                char c = (char) b;
                if (c == '\n') {
                    String line = lineBuffer.toString().stripTrailing();
                    lineBuffer.setLength(0);
                    if (!line.isEmpty()) {
                        job.pushLine(line);
                    }
                } else {
                    lineBuffer.append(c);
                }
                original.write(b);
            }

            @Override
            public void write(byte[] buf, int off, int len) {
                String chunk = new String(buf, off, len);
                for (String line : chunk.split("\n", -1)) {
                    String trimmed = line.stripTrailing();
                    if (!trimmed.isEmpty()) {
                        job.pushLine(trimmed);
                    }
                }
                original.write(buf, off, len);
            }
        };
        return new PrintStream(tee, true);
    }
}
