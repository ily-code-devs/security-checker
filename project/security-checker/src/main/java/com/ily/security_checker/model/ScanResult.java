package com.ily.security_checker.model;

import java.time.Instant;
import java.util.List;

public record ScanResult(
    String target,
    String hostStatus,
    Instant timestamp,
    List<PortInfo> openPorts,
    String message
) {}
