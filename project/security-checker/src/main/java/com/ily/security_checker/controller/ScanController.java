package com.ily.security_checker.controller;

import com.ily.security_checker.model.SecurityReport;
import com.ily.security_checker.model.VulnerabilityIssue;
import com.ily.security_checker.service.SecurityReportService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ScanController {

    private final SecurityReportService securityReportService;

    public ScanController(SecurityReportService securityReportService) {
        this.securityReportService = securityReportService;
    }

    public record ScanRequest(String target, String ports) {}

    @PostMapping("/scan")
    public ResponseEntity<SecurityReport> runScanPost(@RequestBody ScanRequest request) {
        String target = request != null ? request.target() : null;
        String ports = request != null ? request.ports() : null;
        SecurityReport report = securityReportService.runFullScan(target, ports);
        if ("error".equalsIgnoreCase(report.hostStatus())
                && report.message() != null
                && report.message().startsWith("Invalid scan parameters:")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(report);
        }
        return ResponseEntity.ok(report);
    }

    @GetMapping("/scan")
    public ResponseEntity<SecurityReport> runScanGet(
            @RequestParam("target") String target,
            @RequestParam(value = "ports", required = false) String ports) {
        SecurityReport report = securityReportService.runFullScan(target, ports);
        if ("error".equalsIgnoreCase(report.hostStatus())
                && report.message() != null
                && report.message().startsWith("Invalid scan parameters:")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(report);
        }
        return ResponseEntity.ok(report);
    }

    @GetMapping("/vulnerabilities")
    public ResponseEntity<?> lookupVulnerabilities(@RequestParam("cpe") String cpe) {
        try {
            List<VulnerabilityIssue> issues = securityReportService.lookupCpe(cpe);
            return ResponseEntity.ok(issues);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body(Map.of("error", "Vulnerability lookup failed: " + e.getMessage()));
        }
    }
}
