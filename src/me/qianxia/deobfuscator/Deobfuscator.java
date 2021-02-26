package me.qianxia.deobfuscator;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class Deobfuscator {
    public Map<String, ClassNode> classes = new HashMap<>();
    private Map<String, byte[]> resources = new HashMap<>();
    private String COMMENT = "Deobfuscator By QianXia(https://github.com/L0serQianXia/JavaDeobfuscator)";

    public void run() throws UnsupportedEncodingException {
        System.out.println(
                "This deobfuscator only able to deobfuscate the file that obfuscated by QianXia's JavaObfuscator v1.0!");
        System.out.println("You should put the obfuscated file with the deobfuscator.");
        System.out.println("And rename it into \"in.jar\"");

        loadInput("in.jar");
        deobf();
        writeFile("out.jar");
    }

    private void writeFile(String outputName) {
        System.out.println("开始导出文件");
        File outputFile = new File(outputName);
        if (outputFile.exists()) {
            outputFile.renameTo(new File(outputName + System.currentTimeMillis()));
            System.out.println(String.format("文件已经存在 将老文件保存为%s", outputName + System.currentTimeMillis()));
            outputFile = new File(outputName);
        }
        try {
            ZipOutputStream zOut = new ZipOutputStream(new FileOutputStream(outputFile));
            classes.values().forEach(classNode -> {
                try {
                    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
                    try {
                        classNode.accept(cw);
                    } catch (NegativeArraySizeException | ArrayIndexOutOfBoundsException e) {
                        System.out.println("计算帧失败！可能是被反混淆程序并非使用(https://github.com/L0serQianXia/JavaObfuscator)混淆处理");
                        System.out.println("也可能被混淆处理多次");
                        System.out.println("若坚信该程序无以上情况，请提交issues并附带被反混淆的程序");
                        cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
                        classNode.accept(cw);
                    }
                    byte[] b = cw.toByteArray();
                    ZipEntry entry = new ZipEntry(classNode.name + (classNode.name.endsWith(".class") ? "" : ".class"));
                    zOut.putNextEntry(entry);
                    zOut.write(b);
                    zOut.closeEntry();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            });

            resources.forEach((name, b) -> {
                ZipEntry entry = new ZipEntry(name);

                try {
                    zOut.putNextEntry(entry);
                    if (entry.getName().contains("MANIFEST.MF")) {
                        String someString = new String(b).substring(0, new String(b).length() - 1)
                                + "Deobfuscator-By: QianXia(https://github.com/L0serQianXia/JavaDeobfuscator)\r\t";
                        b = someString.getBytes("UTF-8");
                    }
                    zOut.write(b);
                    zOut.closeEntry();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            zOut.setComment(COMMENT);
            zOut.flush();
            zOut.close();
            System.out.println("导出完毕 导出为" + outputFile);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(String.format("导出%s出错 错误信息：%s", outputFile.getName(), e.getMessage()));
        }
    }

    private void deobf() throws UnsupportedEncodingException {
        
        /** Invoke */
        ClassNode hideInvokeClassNode = null;
        int num = 0;
        
        for (ClassNode classNode : classes.values()) {
            for (MethodNode methodNode : classNode.methods) {
                for (AbstractInsnNode abstractInsnNode : methodNode.instructions) {
                    if (abstractInsnNode.getOpcode() != Opcodes.INVOKESTATIC) {
                        continue;
                    }

                    MethodInsnNode methodInsnNode = (MethodInsnNode) abstractInsnNode;
                    hideInvokeClassNode = classes.get(methodInsnNode.owner);
                    MethodNode hideInvokeMethod = null;

                    if (hideInvokeClassNode == null) {
                        continue;
                    }

                    for (MethodNode method : hideInvokeClassNode.methods) {
                        if (method.name.equals(methodInsnNode.name) && method.desc.equals(methodInsnNode.desc)) {
                            if (!isHideInvokeMethod(method)) {
                                break;
                            }

                            hideInvokeMethod = method;
                            break;
                        }
                    }

                    if (hideInvokeMethod == null) {
                        continue;
                    }

                    for (AbstractInsnNode node : hideInvokeMethod.instructions) {
                        if (node.getOpcode() != Opcodes.INVOKESTATIC) {
                            continue;
                        }

                        MethodInsnNode realInvoke = (MethodInsnNode) node;
                        methodNode.instructions.insertBefore(abstractInsnNode, realInvoke);
                        methodNode.instructions.remove(abstractInsnNode);
                        num++;
                    }

                }
            }
        }
        
        if(hideInvokeClassNode != null && num > 0) {
            classes.remove(hideInvokeClassNode.name);
        }
        
        System.out.println("InvokeMethodTransformer did " + num + " times!");
        
        /** String */
        ClassNode stringPoolClassNode = null;
        num = 0;
        
        for (ClassNode classNode : classes.values()) {
            for (MethodNode methodNode : classNode.methods) {
                for (AbstractInsnNode abstractInsnNode : methodNode.instructions) {
                    if(abstractInsnNode.getOpcode() != Opcodes.INVOKESTATIC) {
                        continue;
                    }
                    
                    MethodInsnNode methodInsnNode = (MethodInsnNode) abstractInsnNode;
                    stringPoolClassNode = classes.get(methodInsnNode.owner);

                    
                    if (stringPoolClassNode == null) {
                        continue;
                    }
                    
                    String encryptedString = null;
                    for(MethodNode method : stringPoolClassNode.methods) {
                        boolean flag = method.name.equals(methodInsnNode.name) && method.desc.equals(methodInsnNode.desc);
                        if(flag) {
                            encryptedString = isStringPoolMethod(method);
                        }
                    }
                    
                    if(encryptedString == null) {
                        continue;
                    }
                    
                    String decryptedString = decrypt(encryptedString);
                    methodNode.instructions.insertBefore(abstractInsnNode, new LdcInsnNode(decryptedString));
                    methodNode.instructions.remove(abstractInsnNode);
                    num++;
                }
            }
        }
        
        if(stringPoolClassNode != null && num > 0) {
            classes.remove(stringPoolClassNode.name);
        }
        
        System.out.println("StringTransfomrer did " + num + " times!");
    }
    
    private static String decrypt(String var0) throws UnsupportedEncodingException {
        var0 = URLDecoder.decode(var0, "gbk");
        byte[] var1 = var0.getBytes();

        for(int var2 = 0; var2 < var1.length; ++var2) {
           var1[var2] = (byte)(var1[var2] ^ 5);
        }

        String var3 = new String(var1, 0, var1.length);
        return var3;
     }

    /**
     * 判断是否为存放字符串的函数
     * @param methodNode
     * @return 如果是则返回第一个字符串， 如果不是则返回null
     */
    private String isStringPoolMethod(MethodNode methodNode) {
        List<Integer> validOpcodesList = Arrays.asList(
                Opcodes.ARETURN,
                Opcodes.LDC, 
                Opcodes.INVOKESTATIC);
        
        LdcInsnNode firstLdcInsnNode = null;

        for (AbstractInsnNode abstractInsnNode : methodNode.instructions) {
            if(abstractInsnNode.getOpcode() == Opcodes.LDC && firstLdcInsnNode == null) {
                firstLdcInsnNode = (LdcInsnNode) abstractInsnNode;
                continue;
            }
            
            if (!validOpcodesList.contains(abstractInsnNode.getOpcode())) {
                return null;
            }
        }
        
        if(firstLdcInsnNode == null) {
            return null;
        }

        return (String) firstLdcInsnNode.cst;
    }

    private boolean isHideInvokeMethod(MethodNode methodNode) {
        List<Integer> validOpcodesList = Arrays.asList(
                // RETURN Opcodes
                Opcodes.IRETURN, Opcodes.FRETURN, Opcodes.LRETURN, Opcodes.DRETURN, Opcodes.ARETURN, Opcodes.RETURN,

                // VarInsnNode Opcodes
                Opcodes.FLOAD, Opcodes.LLOAD, Opcodes.DLOAD, Opcodes.ALOAD,

                // MethodInsnNode Opcode
                Opcodes.INVOKESTATIC);

        for (AbstractInsnNode abstractInsnNode : methodNode.instructions) {
            if (!validOpcodesList.contains(abstractInsnNode.getOpcode())) {
                return false;
            }
        }

        return true;
    }

    private void loadInput(String inputName) {
        System.out.println("开始加载文件：" + inputName);
        try {
            ZipFile zip = new ZipFile(inputName, Charset.forName("UTF-8"));
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = null;
                try {
                    entry = entries.nextElement();
                } catch (IllegalArgumentException e) {
                    zip.close();
                    zip = new ZipFile(inputName, Charset.forName("GBK"));
                    System.out.println("编码不兼容，自动切换为GBK编码");
                }
                InputStream in = zip.getInputStream(entry);
                if (!entry.isDirectory()) {
                    if (entry.getName().endsWith(".class")) {
                        try {
                            ClassReader cr = new ClassReader(in);
                            ClassNode cn = new ClassNode();
                            cr.accept(cn, ClassReader.SKIP_FRAMES);
                            classes.put(cn.name, cn);
                        } catch (ArrayIndexOutOfBoundsException | IllegalArgumentException e) {
                            e.printStackTrace();
                            resources.put(entry.getName(), toByteArray(in));
                        }
                    } else {
                        resources.put(entry.getName(), toByteArray(in));
                    }
                } else {
                    resources.put(entry.getName(), toByteArray(in));
                }
            }
            zip.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("加载文件完成");
    }

    private byte[] toByteArray(InputStream in) {
        try {
            ByteArrayOutputStream baros = new ByteArrayOutputStream();
            final byte[] BUFFER = new byte[1024];
            while (in.available() > 0) {
                int data = in.read(BUFFER);
                baros.write(BUFFER, 0, data);
            }
            return baros.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
