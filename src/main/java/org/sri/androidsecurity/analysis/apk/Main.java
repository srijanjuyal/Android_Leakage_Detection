package org.sri.androidsecurity.analysis.apk;

import java.io.File;

public class Main {
    public static void main(String[] args) {
        ApkParser parser = new ApkParser();
        ApkInfo info = parser.parseApk(new File("E:/college/BEIT/android-privacy-taint/src/main/resources/minecraft-1-20-1.apk"));

        System.out.println("Package: " + info.getPackageName());

        for (ComponentInfo c : info.getComponents()) {
            System.out.println(c.getType() + ": " + c.getClassName());
        }
    }
}
