package com.buzznacker.moddetector;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class Main {

    private final byte[] BUFFER = new byte[2048];

    private final Set<String> detections = new HashSet<>();

    private final Set<String> clazzNames = new HashSet<>();

    private static String pathMods; //We use this in case the user is running Minecraft on a MAC/Linux so he could be running Minecraft from another directory.

    private Main() throws IOException {
        setDetections();
        startRoutine();
    }

    public static void main(String[] args) throws IOException {
        pathMods = JOptionPane.showInputDialog(null, "Path to mods folder");
        if(pathMods == null)
            System.exit(0);
        new Main();
    }

    private void setDetections() throws IOException {
        ClassLoader classLoader = this.getClass().getClassLoader();
        InputStream methodStream = classLoader.getResourceAsStream("classNames.txt");
        BufferedReader in = new BufferedReader(new InputStreamReader(methodStream));
        String line;
        while ((line = in.readLine()) != null) {
            clazzNames.add(line.toLowerCase());
        }
    }

    private void startRoutine() throws IOException {
        File modDir = new File(pathMods);
        for(File modFile : modDir.listFiles()) {
            if(modFile.isFile() && modFile.getName().endsWith(".jar")) {
                JarFile jarFile = new JarFile(modFile.getPath());
                Enumeration<? extends JarEntry> entries = jarFile.entries();
                InputStream in = null;
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    in = jarFile.getInputStream(entry);
                    if(entry.getName().endsWith(".class"))
                        analyzeClazz(in, jarFile.getName());
                }
                assert in != null;
                in.close();
            }
        }
        final File outPutFile = new File("logs.txt");
        BufferedWriter writer = new BufferedWriter(new PrintWriter(outPutFile));
        detections.forEach(s -> {
            try {
                writer.write(s + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        writer.flush();
        writer.close();
        Desktop.getDesktop().open(outPutFile);
    }

    private void analyzeClazz(InputStream in, String modName) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        int length;
        while ((length = in.read(BUFFER)) > 0)
            bos.write(BUFFER, 0, length);

        in.close();

        final byte[] CLAZZ_BYTES = bos.toByteArray();

        bos.close();

        ClassNode classNode = new ClassNode();
        new ClassReader(CLAZZ_BYTES).accept(classNode, ClassReader.SKIP_DEBUG);

        final String CLAZZ_NAME = classNode.name.replaceAll("/", ".");

        clazzNames.forEach(s -> {
            if(CLAZZ_NAME.toLowerCase().contains(s))
                addDetection("Found suspicious class: " + CLAZZ_NAME, modName);
        });

        if(classNode.superName.equals("net/minecraft/client/renderer/EntityRenderer"))
            addDetection("Found suspicious super class to class: " + classNode.name + "(net/minecraft/client/renderer/EntityRenderer)", modName);

        for (Object o : classNode.methods) {
            if (o instanceof MethodNode) {
                MethodNode methodNode = (MethodNode) o;
                AbstractInsnNode insn = methodNode.instructions.getFirst();
                while (insn != null) {
                    if (insn instanceof MethodInsnNode) {
                        MethodInsnNode methodInsn = (MethodInsnNode) insn;
                        if(methodInsn.name.equals("func_70614_a") && methodInsn.desc.equals("(DF)Lnet/minecraft/util/MovingObjectPosition;"))
                            addDetection("Found suspicious method usage(EntityLivingBase#rayTrace [Reach]) in: " + CLAZZ_NAME, modName);
                    }
                    insn = insn.getNext();
                }
            }
        }
    }

    private void addDetection(String detection, String modName) {
        detection = "[" + modName + "] " + detection;
        detections.add(detection);
    }


}
