package org.sri.androidsecurity.analysis.ir;

import soot.*;
import soot.options.Options;

import java.util.Collections;

public class SootSetup {

    public static void init(String androidJarPath, String apkPath) {

        G.reset();

        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(Collections.singletonList(apkPath));

        Options.v().set_android_jars(androidJarPath);
        Options.v().set_force_android_jar(androidJarPath + "/android-30/android.jar");

        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);

        Options.v().set_output_format(Options.output_format_none);

        System.out.println(Scene.v().getSootClass("android.app.Activity"));

        Scene.v().loadNecessaryClasses();
    }
}