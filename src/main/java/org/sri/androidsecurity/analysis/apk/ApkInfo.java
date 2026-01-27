package org.sri.androidsecurity.analysis.apk;

import java.util.List;

public class ApkInfo {

    private final String packageName;
    private final List<ComponentInfo> components;
    private final List<String> permissions;

    public ApkInfo(String packageName,
                   List<ComponentInfo> components,
                   List<String> permissions) {
        this.packageName = packageName;
        this.components = components;
        this.permissions = permissions;
    }

    public String getPackageName() {
        return packageName;
    }

    public List<ComponentInfo> getComponents() {
        return components;
    }

    public List<String> getPermissions() {
        return permissions;
    }
}