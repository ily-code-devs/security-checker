package com.ily.security_checker.service;

import com.ily.security_checker.VulnerabilityLookupClient;
import com.ily.security_checker.model.PortInfo;
import com.ily.security_checker.model.PortReport;
import com.ily.security_checker.model.ScanResult;
import com.ily.security_checker.model.SecurityReport;
import com.ily.security_checker.model.VulnerabilityIssue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class SecurityReportService {

    private static final Logger log = LoggerFactory.getLogger(SecurityReportService.class);

    private final PortScannerService portScannerService;
    private final VulnerabilityLookupClient vulnerabilityLookupClient;

    public SecurityReportService(
            PortScannerService portScannerService,
            VulnerabilityLookupClient vulnerabilityLookupClient) {
        this.portScannerService = portScannerService;
        this.vulnerabilityLookupClient = vulnerabilityLookupClient;
    }

    public SecurityReport runFullScan(String target, String ports) {
        ScanResult scanResult = portScannerService.scan(target, ports);

        List<PortReport> portReports = new ArrayList<>();
        int totalVulnerabilities = 0;
        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;

        // Cache CPE lookups within the same scan in case multiple ports run the same software version
        Map<String, List<VulnerabilityIssue>> cpeCache = new LinkedHashMap<>();

        if (scanResult.openPorts() != null) {
            for (PortInfo portInfo : scanResult.openPorts()) {
                List<VulnerabilityIssue> vulns = List.of();
                String lookupError = null;
                String cpe = portInfo.cpe();

                if (cpe != null && !cpe.isBlank()) {
                    try {
                        if (cpeCache.containsKey(cpe)) {
                            vulns = cpeCache.get(cpe);
                        } else {
                            List<VulnerabilityIssue> fetched = vulnerabilityLookupClient.GetVulnFromCPE(cpe);
                            vulns = fetched != null ? List.copyOf(fetched) : List.of();
                            cpeCache.put(cpe, vulns);
                        }
                    } catch (Exception e) {
                        log.warn("Vulnerability lookup failed for CPE {} on port {}: {}", cpe, portInfo.port(), e.getMessage());
                        lookupError = "Could not query vulnerability database for CPE " + cpe + ": " + e.getMessage();
                    }
                }

                totalVulnerabilities += vulns.size();
                for (VulnerabilityIssue issue : vulns) {
                    String sev = issue.severity() == null ? "UNKNOWN" : issue.severity().toUpperCase();
                    switch (sev) {
                        case "CRITICAL" -> criticalCount++;
                        case "HIGH" -> highCount++;
                        case "MEDIUM", "MODERATE" -> mediumCount++;
                        case "LOW" -> lowCount++;
                        default -> {}
                    }
                }

                portReports.add(new PortReport(portInfo, vulns, lookupError));
            }
        }

        return new SecurityReport(
                scanResult.target(),
                ports == null || ports.isBlank() ? "default (top 1000)" : ports.strip(),
                scanResult.hostStatus(),
                scanResult.timestamp(),
                scanResult.message(),
                portReports.size(),
                totalVulnerabilities,
                criticalCount,
                highCount,
                mediumCount,
                lowCount,
                List.copyOf(portReports)
        );
    }

    public List<VulnerabilityIssue> lookupCpe(String cpe) {
        if (cpe == null || cpe.isBlank()) {
            throw new IllegalArgumentException("CPE string is required");
        }
        return vulnerabilityLookupClient.GetVulnFromCPE(cpe.strip());
    }
}
