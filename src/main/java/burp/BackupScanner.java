package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class BackupScanner implements BurpExtension {
    private MontoyaApi api;
    private final Set<String> scannedHosts = ConcurrentHashMap.newKeySet();
    private final DefaultListModel<String> hostListModel = new DefaultListModel<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(15);
    private final List<ScanResult> results = new CopyOnWriteArrayList<>();
    
    private JCheckBox chkEnabled;
    private DefaultTableModel tableModel;
    private JLabel lblStatus, lblReqCount, lblFoundCount;
    private JTextArea txtPrefixes, txtSuffixes, txtWhitelist;
    private JTextField txtDomainLevel;
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    
    private final AtomicInteger totalRequests = new AtomicInteger(0);
    private final AtomicInteger foundCount = new AtomicInteger(0);

    private static class ScanResult {
        HttpRequest request;
        HttpResponse response;
        ScanResult(HttpRequest req, HttpResponse resp) { this.request = req; this.response = resp; }
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Backup Scanner");
        setupUI();
        loadConfig();

        api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
                HttpRequest req = interceptedResponse.initiatingRequest();
                if (chkEnabled.isSelected() && req.method().equalsIgnoreCase("GET")) {
                    String host = req.httpService().host();
                    if (isInWhitelist(host) && scannedHosts.add(host)) {
                        SwingUtilities.invokeLater(() -> hostListModel.addElement(host));
                        executor.submit(() -> startScan(req));
                    }
                }
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }
            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
                return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
            }
        });
    }

    private void startScan(HttpRequest baseReq) {
        String host = baseReq.httpService().host();
        Set<String> payloads = new HashSet<>(getLines(txtPrefixes));
        Set<String> suffixes = getLines(txtSuffixes);
        String[] parts = host.split("\\.");
        int depth = 2;
        try { depth = Integer.parseInt(txtDomainLevel.getText().trim()); } catch (Exception ignored) {}
        
        for (int i = 0; i < Math.min(depth, parts.length); i++) payloads.add(parts[i]);
        payloads.add(host);
        payloads.add(host.replace(".", "_"));

        SwingUtilities.invokeLater(() -> lblStatus.setText("Running: " + host));
        for (String pre : payloads) {
            for (String suf : suffixes) {
                if (!chkEnabled.isSelected()) return;
                try {
                    String path = URLEncoder.encode("/" + pre.trim() + suf.trim(), StandardCharsets.UTF_8)
                            .replace("%2F", "/").replace("+", "%20");
                    checkPath(baseReq.withPath(path));
                } catch (Exception ignored) {}
            }
        }
        SwingUtilities.invokeLater(() -> lblStatus.setText("Idle"));
    }

    private void checkPath(HttpRequest req) {
        try {
            HttpResponse resp = api.http().sendRequest(req).response();
            totalRequests.incrementAndGet();
            if (resp != null && resp.statusCode() == 200 && resp.body().length() > 0) {
                foundCount.incrementAndGet();
                addResult(req, resp);
            }
        } catch (Exception ignored) {}
        updateStats();
    }

    private void setupUI() {
        JTabbedPane tabs = new JTabbedPane();
        JPanel mon = new JPanel(new BorderLayout());
        
        JPanel statusBar = new JPanel(new GridBagLayout());
        statusBar.setBackground(new Color(45, 45, 48));
        statusBar.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(0, 0, 0, 15);
        
        chkEnabled = new JCheckBox("Active", true);
        chkEnabled.setForeground(Color.WHITE);
        chkEnabled.setOpaque(false);
        lblReqCount = new JLabel("Requests: 0");
        lblReqCount.setForeground(Color.LIGHT_GRAY);
        lblFoundCount = new JLabel("Found: 0");
        lblFoundCount.setForeground(Color.ORANGE);
        lblFoundCount.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        lblStatus = new JLabel("Idle");
        lblStatus.setForeground(Color.GREEN);

        gbc.gridx = 0; statusBar.add(chkEnabled, gbc);
        gbc.gridx = 1; statusBar.add(lblReqCount, gbc);
        gbc.gridx = 2; statusBar.add(lblFoundCount, gbc);
        gbc.weightx = 1.0; gbc.anchor = GridBagConstraints.EAST;
        gbc.gridx = 3; statusBar.add(lblStatus, gbc);
        mon.add(statusBar, BorderLayout.NORTH);

        tableModel = new DefaultTableModel(new String[]{"Time", "Host", "Path", "Size", "Type"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable table = new JTable(tableModel);
        
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();

        JTabbedPane msgTabs = new JTabbedPane();
        msgTabs.addTab("Request", requestEditor.uiComponent());
        msgTabs.addTab("Response", responseEditor.uiComponent());

        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        horizontalSplit.setDividerLocation(200);

        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        verticalSplit.setTopComponent(new JScrollPane(table));
        verticalSplit.setBottomComponent(msgTabs);
        verticalSplit.setDividerLocation(300);

        JList<String> hostList = new JList<>(hostListModel);
        horizontalSplit.setLeftComponent(new JScrollPane(hostList));
        horizontalSplit.setRightComponent(verticalSplit);

        mon.add(horizontalSplit, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1 && !e.getValueIsAdjusting()) {
                ScanResult res = results.get(tableModel.getRowCount() - 1 - row);
                requestEditor.setRequest(res.request);
                responseEditor.setResponse(res.response);
            }
        });

        JPanel cfgPanel = new JPanel(new BorderLayout());
        JPanel editors = new JPanel(new GridLayout(1, 3, 5, 0));
        txtPrefixes = new JTextArea("www\nroot\nbackup\nweb");
        txtSuffixes = new JTextArea(".zip\n.rar\n.tar.gz\n.7z\n.bak");
        txtWhitelist = new JTextArea("");
        editors.add(createBox("Prefixes", txtPrefixes));
        editors.add(createBox("Suffixes", txtSuffixes));
        editors.add(createBox("Whitelist", txtWhitelist));

        JPanel footer = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        txtDomainLevel = new JTextField("2", 3);
        JButton btnApply = new JButton("Save & Apply Config");
        btnApply.addActionListener(e -> saveConfig());
        footer.add(new JLabel("Subdomain Depth:")); footer.add(txtDomainLevel); footer.add(btnApply);
        cfgPanel.add(editors, BorderLayout.CENTER);
        cfgPanel.add(footer, BorderLayout.SOUTH);

        tabs.addTab("Monitor", mon);
        tabs.addTab("Config", cfgPanel);
        api.userInterface().registerSuiteTab("BackupScanner", tabs);
    }

    private JPanel createBox(String t, JTextArea a) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder(t));
        p.add(new JScrollPane(a));
        return p;
    }

    private boolean isInWhitelist(String h) {
        String w = txtWhitelist.getText().trim();
        return w.isEmpty() || Arrays.stream(w.split("\n")).map(String::trim).anyMatch(h::contains);
    }

    private void addResult(HttpRequest req, HttpResponse resp) {
        results.add(new ScanResult(req, resp));
        String time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        SwingUtilities.invokeLater(() -> {
            tableModel.insertRow(0, new Object[]{time, req.httpService().host(), req.path(), resp.body().length(), resp.headerValue("Content-Type")});
            lblFoundCount.setText("Found: " + foundCount.get());
        });
    }

    private void updateStats() {
        if (totalRequests.get() % 5 == 0) SwingUtilities.invokeLater(() -> lblReqCount.setText("Requests: " + totalRequests.get()));
    }

    private Set<String> getLines(JTextArea a) {
        return new HashSet<>(Arrays.asList(a.getText().split("\\n")));
    }

    private void loadConfig() {
        try {
            Path d = getJarDir();
            if (Files.exists(d.resolve("backup.txt"))) txtPrefixes.setText(Files.readString(d.resolve("backup.txt")));
            if (Files.exists(d.resolve("ext.txt"))) txtSuffixes.setText(Files.readString(d.resolve("ext.txt")));
        } catch (Exception ignored) {}
    }

    private void saveConfig() {
        try {
            Path d = getJarDir();
            Files.writeString(d.resolve("backup.txt"), txtPrefixes.getText());
            Files.writeString(d.resolve("ext.txt"), txtSuffixes.getText());
            JOptionPane.showMessageDialog(null, "Config Saved");
        } catch (Exception ignored) {}
    }

    private Path getJarDir() {
        String f = api.extension().filename();
        return f != null ? Paths.get(f).getParent() : Paths.get(".");
    }
}