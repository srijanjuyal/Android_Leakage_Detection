package org.sri.androidsecurity.analysis.web;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Represents a single APK analysis job.
 * Holds the streaming output queue and final result.
 */
public class AnalysisJob {

    public enum Status { QUEUED, RUNNING, COMPLETED, FAILED }

    private final String jobId;
    private volatile Status status = Status.QUEUED;
    private volatile boolean leakFound = false;

    // Lines are pushed here as the analysis produces output
    private final BlockingQueue<String> outputQueue = new LinkedBlockingQueue<>();

    // Sentinel value signalling the stream is done
    public static final String END_SIGNAL = "__END__";

    // Full log kept for re-reads (e.g. page refresh)
    private final List<String> fullLog = new ArrayList<>();

    public AnalysisJob(String jobId) {
        this.jobId = jobId;
    }

    // ---- Writers (called from analysis thread) ----

    public void pushLine(String line) {
        fullLog.add(line);
        outputQueue.offer(line);
    }

    public void finish(boolean leakFound) {
        this.leakFound = leakFound;
        this.status = Status.COMPLETED;
        outputQueue.offer(END_SIGNAL);
    }

    public void fail(String errorMessage) {
        this.status = Status.FAILED;
        pushLine("[ERROR] " + errorMessage);
        outputQueue.offer(END_SIGNAL);
    }

    // ---- Readers (called from SSE/HTTP thread) ----

    public String jobId()            { return jobId; }
    public Status status()           { return status; }
    public boolean isLeakFound()     { return leakFound; }
    public List<String> fullLog()    { return List.copyOf(fullLog); }
    public BlockingQueue<String> outputQueue() { return outputQueue; }
}
