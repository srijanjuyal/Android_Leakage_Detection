package org.sri.androidsecurity.analysis.apk;

import java.util.List;

public class ComponentInfo {

    private final String className;
    private final ComponentType type;
    private final List<String> entryMethods;

    public ComponentInfo(String className,
                         ComponentType type,
                         List<String> entryMethods) {
        this.className = className;
        this.type = type;
        this.entryMethods = entryMethods;
    }

    public String getClassName() {
        return className;
    }

    public ComponentType getType() {
        return type;
    }

    public List<String> getEntryMethods() {
        return entryMethods;
    }
}