package com.antivirus.Antivirus.controller;

import com.antivirus.Antivirus.service.FileMonitor;
import com.antivirus.Antivirus.service.YARAScanStrategy;
import com.antivirus.Antivirus.service.ScanFactory;
import com.antivirus.Antivirus.service.ScanStrategy;
import com.antivirus.Antivirus.service.QuickScanStrategy;
import com.antivirus.Antivirus.service.DeepScanStrategy;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.util.*;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping("/antivirus")
public class AntivirusController {

    private final FileMonitor fileMonitor;
    private final YARAScanStrategy yaraScanStrategy;

    public AntivirusController() throws Exception {
        this.fileMonitor = new FileMonitor();
        this.yaraScanStrategy = new YARAScanStrategy();
        
        fileMonitor.addObserver((filePath) -> {
            File file = new File(filePath);
            if (file.exists()) {
                System.out.println("🔎 Análisis en tiempo real con YARA: " + filePath);
                System.out.println(yaraScanStrategy.scan(file));
            } else {
                System.out.println("⚠ Archivo no encontrado: " + filePath);
            }
        });
    }

    @GetMapping("/scanSystem")
    public String scanSystem(@RequestParam String scanType) {
        try {
            QuickScanStrategy.clearDetectedThreats(); // 📌 Limpiar lista antes del escaneo
            DeepScanStrategy.clearDetectedThreats();
            
            ScanStrategy strategy = ScanFactory.getScanStrategy(scanType, null);
            File[] roots = File.listRoots();
            int scannedFiles = 0;
            int[] threatCount = {0}; // Contador de amenazas detectadas

            for (File root : roots) {
                System.out.println("🔎 Escaneando unidad: " + root.getAbsolutePath());
                scannedFiles += scanDirectoryRecursively(root, strategy, scanType, threatCount);
            }

            String message = "✅ Escaneo global completado con estrategia: " + scanType + 
                             ". Total de archivos escaneados: " + scannedFiles;

            if (threatCount[0] > 0) {
                message += ". 🚨 Amenazas detectadas: " + threatCount[0];
            } else {
                message += ". ✅ Sin amenazas detectadas.";
            }

            return message;
        } catch (Exception e) {
            return "⚠ Error durante el escaneo: " + e.getMessage();
        }
    }

    @GetMapping("/getThreats")
    public Map<String, List<String>> getThreats() {
        Map<String, List<String>> threats = new HashMap<>();
        threats.put("quick", QuickScanStrategy.getDetectedThreats().stream().sorted().toList());
        threats.put("deep", DeepScanStrategy.getDetectedThreats().stream().sorted().toList());
        return threats; // 📌 Devuelve amenazas separadas por estrategia
    }

    private int scanDirectoryRecursively(File directory, ScanStrategy strategy, String scanType, int[] threatCount) {
        File[] files = directory.listFiles((file) -> true);
        if (files == null) return 0;
    
        return Arrays.stream(files)
            .parallel()
            .mapToInt(file -> {
                if (file.isDirectory()) {
                    return scanDirectoryRecursively(file, strategy, scanType, threatCount);
                } else {
                    try {
                        System.out.println("🔎 Escaneando archivo con YARA: " + file.getAbsolutePath());
                        String result = strategy.scan(file);
                        System.out.println(result);

                        // 📌 Guardamos archivos con amenazas según la estrategia
                        if (!result.contains("✅ Sin amenazas") && result.contains("🚨")) { 
                            if ("quick".equals(scanType)) {
                                QuickScanStrategy.addDetectedThreat(file.getAbsolutePath());
                            } else if ("deep".equals(scanType)) {
                                DeepScanStrategy.addDetectedThreat(file.getAbsolutePath());
                            }
                            threatCount[0]++;
                        }

                        return 1;
                    } catch (Exception e) {
                        System.out.println("⚠ Error al escanear archivo " + file.getAbsolutePath() + ": " + e.getMessage());
                        return 0;
                    }
                }
            }).sum();
    }
}
