package com.acme.orders;

import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.Statement;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
    private final Connection conn;
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/{id}")
    public String getOrder(@PathVariable String id) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'").toString();
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public String create(@RequestBody String body) throws Exception {
        var ps = conn.prepareStatement("INSERT INTO orders (payload) VALUES (?)");
        ps.setString(1, body);
        return "ok";
    }

    @RequestMapping(value = "/export", method = RequestMethod.POST)
    public String export(@RequestParam String cmd) throws Exception {
        Runtime.getRuntime().exec("tar czf /tmp/out.tgz " + cmd);
        return "started";
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) {
        return restTemplate.getForObject(url, String.class);
    }

    @PostMapping("/import")
    public Object importBlob(java.io.InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    @PostMapping("/xml")
    public String parseXml(@RequestBody String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().toString();
    }

    @KafkaListener(topics = "order.created")
    public void onCreated(String message) {
        System.out.println(message);
    }

    @Scheduled(cron = "0 0 * * * *")
    public void nightly() {
        System.out.println("nightly");
    }
}
