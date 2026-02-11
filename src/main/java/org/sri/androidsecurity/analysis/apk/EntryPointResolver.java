package org.sri.androidsecurity.analysis.apk;

import java.util.HashSet;
import java.util.Set;

public class EntryPointResolver {

    public static Set<String> resolveEntryPoints(ApkInfo apkInfo) {

        Set<String> entryPoints = new HashSet<>();

        for (ComponentInfo component : apkInfo.getComponents()) {

            String className = component.getClassName();

            switch (component.getType()) {

                case ACTIVITY -> {
                    entryPoints.add(
                            "<" + className +
                                    ": void onCreate(android.os.Bundle)>"
                    );
                }

                case SERVICE -> {
                    entryPoints.add(
                            "<" + className +
                                    ": int onStartCommand(android.content.Intent,int,int)>"
                    );
                }

                case RECEIVER -> {
                    entryPoints.add(
                            "<" + className +
                                    ": void onReceive(android.content.Context,android.content.Intent)>"
                    );
                }

                case PROVIDER -> {
                    entryPoints.add(
                            "<" + className +
                                    ": boolean onCreate()>"
                    );
                }
            }
        }

        return entryPoints;
    }
}
