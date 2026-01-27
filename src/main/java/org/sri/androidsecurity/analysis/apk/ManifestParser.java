package org.sri.androidsecurity.analysis.apk;

import net.dongliu.apk.parser.ApkFile;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ManifestParser {

    public ApkInfo parse(File apkFile) {
        try (ApkFile apk = new ApkFile(apkFile)) {

            String packageName = apk.getApkMeta().getPackageName();
            List<String> permissions = apk.getApkMeta().getUsesPermissions();

            String manifestXml = apk.getManifestXml();

            List<ComponentInfo> components = parseComponents(manifestXml);

            return new ApkInfo(packageName, components, permissions);

        } catch (Exception e) {
            throw new RuntimeException("Failed to parse APK", e);
        }
    }

    private List<ComponentInfo> parseComponents(String manifestXml) throws Exception {
        List<ComponentInfo> components = new ArrayList<>();

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);

        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(
                new ByteArrayInputStream(manifestXml.getBytes(StandardCharsets.UTF_8))
        );

        // Activities
        NodeList activities = doc.getElementsByTagName("activity");
        for (int i = 0; i < activities.getLength(); i++) {
            String name = activities.item(i)
                    .getAttributes()
                    .getNamedItem("android:name")
                    .getNodeValue();

            components.add(new ComponentInfo(
                    name,
                    ComponentType.ACTIVITY,
                    List.of("onCreate", "onStart", "onResume")
            ));
        }

        // Services
        NodeList services = doc.getElementsByTagName("service");
        for (int i = 0; i < services.getLength(); i++) {
            String name = services.item(i)
                    .getAttributes()
                    .getNamedItem("android:name")
                    .getNodeValue();

            components.add(new ComponentInfo(
                    name,
                    ComponentType.SERVICE,
                    List.of("onCreate", "onStartCommand")
            ));
        }

        // Receivers
        NodeList receivers = doc.getElementsByTagName("receiver");
        for (int i = 0; i < receivers.getLength(); i++) {
            String name = receivers.item(i)
                    .getAttributes()
                    .getNamedItem("android:name")
                    .getNodeValue();

            components.add(new ComponentInfo(
                    name,
                    ComponentType.RECEIVER,
                    List.of("onReceive")
            ));
        }

        // Providers
        NodeList providers = doc.getElementsByTagName("provider");
        for (int i = 0; i < providers.getLength(); i++) {
            String name = providers.item(i)
                    .getAttributes()
                    .getNamedItem("android:name")
                    .getNodeValue();

            components.add(new ComponentInfo(
                    name,
                    ComponentType.PROVIDER,
                    List.of("onCreate")
            ));
        }

        return components;
    }
}