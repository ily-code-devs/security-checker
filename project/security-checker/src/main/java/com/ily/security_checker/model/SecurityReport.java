package com.ily.security_checker.model;

import java.time.Instant;
import java.util.List;

public record SecurityReport(
    String target,
    String requestedPorts,
    String hostStatus,
    Instant timestamp,
    String message,
    int totalOpenPorts,
    int totalVulnerabilities,
    int criticalCount,
    int highCount,
    int mediumCount,
    int lowCount,
    List<PortReport> portReports
) {}
