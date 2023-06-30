package com.mjh.adapter.signing.health;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("myHealthCheckService")
@RequestMapping({"/adapter"})
public class HealthCheckService {
    Logger logger = LoggerFactory.getLogger(HealthCheckService.class);

    static final long thresholdDefault = 95L;

    static long maxMemory = Runtime.getRuntime().maxMemory();

    static long totalMemory = Runtime.getRuntime().totalMemory();

    static long freeMemory = Runtime.getRuntime().freeMemory();

    static long usedMemory = totalMemory - freeMemory;

    static long percentageMemory = usedMemory / maxMemory * 100L;

    @GetMapping({"/serverhealth"})
    public ResponseEntity<String> index() {
        String bodyResponse =  "ALLOK - {maxMemory|totalMemory|freeMemory|usedMemory|percentageMemory} : " + maxMemory + "|" + totalMemory + "|" + freeMemory + "|" + usedMemory + "|" + percentageMemory;
        return new ResponseEntity<>(bodyResponse, HttpStatus.OK);
    }

    @GetMapping({"/readiness"})
    public ResponseEntity<String> readiness() {
        return new ResponseEntity<>("ALLOK", HttpStatus.OK);
    }

    @GetMapping({"/liveness"})
    public ResponseEntity<String> liveness() {
        if (calculateMemory(95L)) {
            this.logger.debug("STATMEM :" + percentageMemory);
            return new ResponseEntity<>("KO", HttpStatus.NOT_FOUND);
        }
        this.logger.debug("STATMEM :" + percentageMemory);
        return new ResponseEntity<>("ALLOK", HttpStatus.OK);
    }

    @GetMapping({"/liveness/{threshold}"})
    public ResponseEntity<String> livenessWithParam(@PathVariable("threshold") long threshold) {
        if (threshold < 60L)
            threshold = 95L;
        if (calculateMemory(threshold)) {
            this.logger.debug("STATMEM :" + percentageMemory);
            return new ResponseEntity<>("KO", HttpStatus.NOT_FOUND);
        }
        this.logger.debug("STATMEM :" + percentageMemory);
        return new ResponseEntity<>("ALLOK", HttpStatus.OK);
    }

    private boolean calculateMemory(long threshold) {
        maxMemory = Runtime.getRuntime().maxMemory();
        totalMemory = Runtime.getRuntime().totalMemory();
        freeMemory = Runtime.getRuntime().freeMemory();
        usedMemory = totalMemory - freeMemory;
        percentageMemory = usedMemory / maxMemory * 100L;
        return (percentageMemory > threshold);
    }
}
