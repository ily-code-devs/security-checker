package com.ily.security_checker.service;

import com.ily.security_checker.model.PortInfo;
import com.ily.security_checker.model.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class PortScannerService {

    private static final Logger log = LoggerFactory.getLogger(PortScannerService.class);

    private final long timeoutSeconds;
    private final ProcessStarter processStarter;

    @Autowired
    public PortScannerService(@Value("${scanner.timeout-seconds:120}") long timeoutSeconds) {
        this(timeoutSeconds, ProcessBuilder::start);
    }

    PortScannerService(long timeoutSeconds, ProcessStarter processStarter) {
        if (timeoutSeconds <= 0) {
            throw new IllegalArgumentException("Scanner timeout must be positive");
        }
        this.timeoutSeconds = timeoutSeconds;
        this.processStarter = processStarter;
    }

    public ScanResult scan(String target, String ports) {
        try {
            target = validateTarget(target);
            ports = validatePorts(ports);
        } catch (IllegalArgumentException e) {
            return error(target, "Invalid scan parameters: " + e.getMessage());
        }

        Path stdout = null;
        Path stderr = null;
        Process process = null;
        try {
            List<String> command = new ArrayList<>(List.of("nmap", "-sV", "-oX", "-"));
            if (target.contains(":")) {
                command.add("-6");
            }
            if (ports != null) {
                command.add("-p");
                command.add(ports);
            }
            command.add("--");
            command.add(target);

            // File redirection avoids pipe deadlocks without background reader threads.
            stdout = Files.createTempFile("nmap-", ".xml");
            stderr = Files.createTempFile("nmap-", ".stderr");
            process = processStarter.start(new ProcessBuilder(command)
                    .redirectOutput(stdout.toFile())
                    .redirectError(stderr.toFile()));
            process.getOutputStream().close();

            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                return error(target, "nmap timed out after " + timeoutSeconds + " seconds");
            }

            String diagnostics = Files.readString(stderr).strip();
            if (process.exitValue() != 0) {
                return error(target, "nmap exited with code " + process.exitValue()
                        + (diagnostics.isEmpty() ? "" : ": " + diagnostics));
            }
            if (!diagnostics.isEmpty()) {
                log.warn("nmap stderr: {}", diagnostics);
            }

            return parseOutput(target, stdout);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return error(target, "Scan interrupted");
        } catch (Exception e) {
            return error(target, "Scan failed: " + e.getMessage());
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
            deleteTemporaryFile(stdout);
            deleteTemporaryFile(stderr);
        }
    }

    private static String validateTarget(String target) {
        if (target == null || target.isBlank()) {
            throw new IllegalArgumentException("Target is required");
        }
        target = target.strip();

        if (target.contains(":")) {
            // Only numeric literals reach getByName here; validation must not perform DNS lookups.
            if (target.matches("[0-9a-fA-F:.]+")) {
                try {
                    InetAddress.getByName(target);
                    return target;
                } catch (UnknownHostException ignored) {
                    // Report the same validation error for malformed IPv6 literals.
                }
            }
            throw new IllegalArgumentException("Target must be a single IP address or DNS name; IPv6 addresses must be unbracketed and have no zone ID");
        }

        // Numeric ranges such as 192.168.1.1-10 also resemble DNS labels, but nmap expands them.
        if (target.matches("[0-9.-]+")) {
            String[] octets = target.split("\\.", -1);
            if (octets.length == 4) {
                boolean valid = true;
                for (String octet : octets) {
                    if (!octet.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(octet) > 255) {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    return target;
                }
            }
            throw new IllegalArgumentException("IPv4 address must contain four numbers between 0 and 255");
        }

        String hostname = target.endsWith(".") ? target.substring(0, target.length() - 1) : target;
        if (hostname.isEmpty() || hostname.length() > 253) {
            throw new IllegalArgumentException("DNS name must contain between 1 and 253 characters");
        }
        for (String label : hostname.split("\\.", -1)) {
            if (!label.matches("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")) {
                throw new IllegalArgumentException("Target must be a single IP address or DNS name, not a URL, option or range");
            }
        }
        return target;
    }

    private static String validatePorts(String ports) {
        if (ports == null || ports.isBlank()) {
            return null;
        }
        ports = ports.strip();
        for (String selection : ports.split(",", -1)) {
            if (!selection.matches("[0-9]{1,5}(-[0-9]{1,5})?")) {
                throw new IllegalArgumentException("Ports must be numbers or ranges separated by commas, e.g. 22,80,8000-8100");
            }
            String[] range = selection.split("-");
            int first = Integer.parseInt(range[0]);
            int last = range.length == 2 ? Integer.parseInt(range[1]) : first;
            if (first < 1 || last > 65535 || first > last) {
                throw new IllegalArgumentException("Ports must be between 1 and 65535, with ranges in ascending order");
            }
        }
        return ports;
    }

    private ScanResult parseOutput(String target, Path output) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        Element root = factory.newDocumentBuilder().parse(output.toFile()).getDocumentElement();
        if (!"nmaprun".equals(root.getTagName())) {
            throw new IOException("Expected nmap XML output");
        }
        Element finished = firstElement(root, "finished");
        if (finished != null && "error".equals(finished.getAttribute("exit"))) {
            return error(target, "nmap reported an error: " + finished.getAttribute("errormsg"));
        }

        Element host = firstElement(root, "host");
        if (host == null) {
            // Nmap normally omits down hosts and reports them only in runstats.
            Element hosts = firstElement(root, "hosts");
            if (hosts != null && Integer.parseInt(hosts.getAttribute("down")) > 0) {
                return new ScanResult(target, "down", Instant.now(), List.of(), "Host is down");
            }
            return error(target, "nmap returned no host information; check the target address");
        }

        Element status = firstElement(host, "status");
        String hostStatus = status == null ? "unknown" : status.getAttribute("state");
        List<PortInfo> openPorts = new ArrayList<>();
        NodeList ports = host.getElementsByTagName("port");
        for (int i = 0; i < ports.getLength(); i++) {
            Element port = (Element) ports.item(i);
            Element state = firstElement(port, "state");
            if (state == null || !"open".equals(state.getAttribute("state"))) {
                continue;
            }

            Element service = firstElement(port, "service");
            List<String> cpes = new ArrayList<>();
            if (service != null) {
                NodeList cpeNodes = service.getElementsByTagName("cpe");
                for (int j = 0; j < cpeNodes.getLength(); j++) {
                    String cpe = cpeNodes.item(j).getTextContent().strip();
                    if (!cpe.isEmpty()) {
                        cpes.add(cpe);
                    }
                }
            }
            // Prefer an application CPE over an OS/hardware CPE for vulnerability lookup.
            String primaryCpe = cpes.stream()
                    .filter(cpe -> cpe.startsWith("cpe:/a:") || cpe.startsWith("cpe:2.3:a:"))
                    .findFirst().orElse(cpes.isEmpty() ? null : cpes.getFirst());
            openPorts.add(new PortInfo(
                    Integer.parseInt(port.getAttribute("portid")),
                    port.getAttribute("protocol"),
                    state.getAttribute("state"),
                    attribute(service, "name"),
                    attribute(service, "product"),
                    attribute(service, "version"),
                    attribute(service, "extrainfo"),
                    primaryCpe,
                    List.copyOf(cpes)));
        }

        String message = "up".equals(hostStatus)
                ? "Found " + openPorts.size() + " open ports"
                : "Host status: " + hostStatus;
        return new ScanResult(target, hostStatus, Instant.now(), List.copyOf(openPorts), message);
    }

    private static Element firstElement(Element parent, String name) {
        return (Element) parent.getElementsByTagName(name).item(0);
    }

    private static String attribute(Element element, String name) {
        return element == null ? "" : element.getAttribute(name);
    }

    private static ScanResult error(String target, String message) {
        return new ScanResult(target, "error", Instant.now(), List.of(), message);
    }

    private static void deleteTemporaryFile(Path path) {
        if (path != null) {
            try {
                Files.deleteIfExists(path);
            } catch (IOException e) {
                log.warn("Could not delete nmap temporary file {}", path, e);
            }
        }
    }

    @FunctionalInterface
    interface ProcessStarter {
        Process start(ProcessBuilder builder) throws IOException;
    }
}
