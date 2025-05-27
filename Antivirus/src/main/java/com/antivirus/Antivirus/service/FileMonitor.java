package com.antivirus.Antivirus.service;

import java.nio.file.*;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

public class FileMonitor {

    private final WatchService watchService;
    private final Set<Consumer<String>> observers = new HashSet<>();

    public FileMonitor() throws Exception {
        this.watchService = FileSystems.getDefault().newWatchService();
    }

    /**
     * Agrega un observador para ser notificado cuando un archivo cambie.
     */
    public void addObserver(Consumer<String> observer) {
        observers.add(observer);
    }

    /**
     * Monitorea un archivo individual y notifica a los observadores cuando se modifica.
     */
    public void watchFile(String filePath) throws Exception {
        Path path = Paths.get(filePath);

        if (!path.toFile().exists() || !path.toFile().isFile()) {
            throw new Exception("⚠ Error: El archivo no existe o no es válido.");
        }

        System.out.println("🔎 Monitoreando archivo: " + filePath);

        Path parentDir = path.getParent();
        WatchKey key = parentDir.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

        while (!Thread.interrupted()) {
            WatchKey wk;
            try {
                wk = watchService.take(); // Espera eventos
            } catch (InterruptedException e) {
                break;
            }

            for (WatchEvent<?> event : wk.pollEvents()) {
                Path changed = parentDir.resolve((Path) event.context());
                if (changed.equals(path)) {
                    System.out.println("⚠ Archivo modificado: " + filePath);
                    observers.forEach(observer -> observer.accept(filePath));
                }
            }

            if (!wk.reset()) { // Si el WatchKey ya no es válido, salir del bucle
                break;
            }
        }

        key.cancel(); // Asegurar que el WatchKey se libera correctamente
    }

    /**
     * Monitorea un directorio y detecta cambios en archivos internos.
     */
    public void watchDirectory(String directoryPath) throws Exception {
        Path path = Paths.get(directoryPath);

        if (!path.toFile().exists() || !path.toFile().isDirectory()) {
            throw new Exception("⚠ Error: El directorio no existe o no es válido.");
        }

        System.out.println("🔎 Monitoreando directorio: " + directoryPath);

        WatchKey key = path.register(
            watchService,
            StandardWatchEventKinds.ENTRY_CREATE,
            StandardWatchEventKinds.ENTRY_MODIFY,
            StandardWatchEventKinds.ENTRY_DELETE
        );

        while (!Thread.interrupted()) {
            WatchKey wk;
            try {
                wk = watchService.take(); // Espera eventos
            } catch (InterruptedException e) {
                break;
            }

            for (WatchEvent<?> event : wk.pollEvents()) {
                Path changed = path.resolve((Path) event.context());
                System.out.println("⚠ Cambio detectado: " + changed);

                if (event.kind() == StandardWatchEventKinds.ENTRY_MODIFY) {
                    observers.forEach(observer -> observer.accept(changed.toString()));
                }
            }

            if (!wk.reset()) { // Si el WatchKey ya no es válido, salir del bucle
                break;
            }
        }

        key.cancel(); // Asegurar que el WatchKey se libera correctamente
    }
    public void stopMonitoring() throws Exception {
        watchService.close();
        System.out.println("✅ Monitoreo detenido correctamente.");
    }
    
}
