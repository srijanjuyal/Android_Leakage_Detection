package org.sri.androidsecurity.analysis.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.nio.file.*;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * REST endpoints:
 *
 *   POST /api/analyze          — Upload APK, returns { jobId }
 *   GET  /api/analyze/{jobId}/stream  — SSE stream of analysis output lines
 *   GET  /api/analyze/{jobId}/status  — Final status (for polling fallback)
 */
@RestController
@RequestMapping("/api/analyze")
@CrossOrigin(origins = "*")   // allow the frontend (any origin in dev)
public class AnalysisController {

    @Autowired
    private AnalysisService analysisService;

    // ------------------------------------------------------------------
    //  1.  Upload endpoint
    // ------------------------------------------------------------------

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> uploadApk(@RequestParam("apk") MultipartFile file) {

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "No file uploaded"));
        }

        String originalName = file.getOriginalFilename();
        if (originalName == null || !originalName.toLowerCase().endsWith(".apk")) {
            return ResponseEntity.badRequest().body(Map.of("error", "Only .apk files are accepted"));
        }

        try {
            // Save to a temp location so Soot can read it as a file
            Path tempDir = Files.createTempDirectory("apk-analysis-");
            Path apkPath = tempDir.resolve(originalName);
            file.transferTo(apkPath);

            AnalysisJob job = analysisService.submitJob(apkPath);
            return ResponseEntity.ok(Map.of("jobId", job.jobId()));

        } catch (IOException e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to save uploaded file: " + e.getMessage()));
        }
    }

    // ------------------------------------------------------------------
    //  2.  SSE streaming endpoint
    // ------------------------------------------------------------------

    @GetMapping(value = "/{jobId}/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamOutput(@PathVariable String jobId) {

        AnalysisJob job = analysisService.getJob(jobId);
        if (job == null) {
            SseEmitter emitter = new SseEmitter();
            try {
                emitter.send(SseEmitter.event().name("error").data("Job not found: " + jobId));
            } catch (IOException ignored) {}
            emitter.complete();
            return emitter;
        }

        // Long timeout – analysis can take minutes
        SseEmitter emitter = new SseEmitter(10 * 60 * 1000L);

        Thread streamer = new Thread(() -> {
            BlockingQueue<String> queue = job.outputQueue();
            try {
                while (true) {
                    // Block up to 30 s between lines so we can detect stalls
                    String line = queue.poll(30, TimeUnit.SECONDS);

                    if (line == null) {
                        // Timeout – send a keepalive comment
                        emitter.send(SseEmitter.event().comment("keepalive"));
                        continue;
                    }

                    if (AnalysisJob.END_SIGNAL.equals(line)) {
                        // Send final verdict event then close
                        String verdict = job.isLeakFound() ? "UNSAFE" : "SAFE";
                        emitter.send(SseEmitter.event()
                                .name("verdict")
                                .data(verdict));
                        emitter.complete();
                        return;
                    }

                    // Normal log line
                    emitter.send(SseEmitter.event()
                            .name("log")
                            .data(line));
                }
            } catch (InterruptedException | IOException e) {
                emitter.completeWithError(e);
            }
        }, "sse-streamer-" + jobId);

        streamer.setDaemon(true);
        streamer.start();

        emitter.onTimeout(streamer::interrupt);
        emitter.onError(t -> streamer.interrupt());

        return emitter;
    }

    // ------------------------------------------------------------------
    //  3.  Status polling endpoint (fallback / page-refresh recovery)
    // ------------------------------------------------------------------

    @GetMapping("/{jobId}/status")
    public ResponseEntity<?> getStatus(@PathVariable String jobId) {
        AnalysisJob job = analysisService.getJob(jobId);
        if (job == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Map.of(
                "jobId",     job.jobId(),
                "status",    job.status().name(),
                "leakFound", job.isLeakFound(),
                "log",       job.fullLog()
        ));
    }
}
