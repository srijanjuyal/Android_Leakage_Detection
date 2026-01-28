package org.sri.androidsecurity.analysis.ir;

import soot.*;
import soot.options.Options;

import java.util.ArrayList;
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

        // REQUIRED for call graph
        Options.v().setPhaseOption("cg.cha", "on");

        Options.v().set_output_format(Options.output_format_none);

        System.out.println(Scene.v().getSootClass("android.app.Activity"));

        Scene.v().loadNecessaryClasses();

        // VERY IMPORTANT: set entry points AFTER loading classes
        Scene.v().setEntryPoints(
                new ArrayList<>(Scene.v().getApplicationClasses()
                        .stream()
                        .flatMap(c -> c.getMethods().stream())
                        .filter(SootMethod::isConcrete)
                        .toList())
        );

        // THIS is what actually builds the call graph
        PackManager.v().runPacks();
    }
}