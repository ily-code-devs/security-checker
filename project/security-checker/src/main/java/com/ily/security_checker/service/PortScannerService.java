package com.ily.security_checker.service;

import com.ily.security_checker.model.PortInfo;
import com.ily.security_checker.model.ScanResult;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
public class PortScannerService {

    public ScanResult scan(String target, String ports) {
        try {
            List<String> command = new ArrayList<>();
            command.add("nmap");
            command.add("-sV");
            if (ports != null && !ports.isBlank()) {
                command.add("-p");
                command.add(ports);
            }
            command.add(target);

            Process process = new ProcessBuilder(command).start();
            String output = new String(process.getInputStream().readAllBytes());
            process.waitFor();

            List<PortInfo> openPorts = parseOutput(output);

            return new ScanResult(target, "up", Instant.now(), openPorts, "Found " + openPorts.size() + " open ports");

        } catch (Exception e) {
            return new ScanResult(target, "error", Instant.now(), List.of(), "Error: " + e.getMessage());
        }
    }
    private List<PortInfo> parseOutput(String output) {
        List<PortInfo> openPorts = new ArrayList<>();
        String[] lines = output.split("\n");

        for (String line : lines) {
            line = line.trim();

            if (!line.contains("/tcp") && !line.contains("/udp")) {
                continue;
            }

            String[] parts = line.split("\\s+");
            if (parts.length < 3) {
                continue;
            }

            String[] portAndProtocol = parts[0].split("/");
            int portNumber = Integer.parseInt(portAndProtocol[0]);
            String protocol = portAndProtocol[1];
            String state = parts[1];

            if (!"open".equals(state)) {
                continue;
            }

            String serviceName = parts.length > 2 ? parts[2] : "";

            String version = "";
            if (parts.length > 3) {
                StringBuilder sb = new StringBuilder();
                for (int i = 3; i < parts.length; i++) {
                    if (i > 3) sb.append(" ");
                    sb.append(parts[i]);
                }
                version = sb.toString();
            }

            openPorts.add(new PortInfo(portNumber, protocol, state, serviceName, "", version, "", null, List.of()));
        }

        return openPorts;
    }
}
