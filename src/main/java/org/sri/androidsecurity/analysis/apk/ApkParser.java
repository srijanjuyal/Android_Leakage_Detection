package org.sri.androidsecurity.analysis.apk;

import java.io.File;

public class ApkParser {

    private final ManifestParser manifestParser = new ManifestParser();

    public ApkInfo parseApk(File apkFile) {
        return manifestParser.parse(apkFile);
    }
}