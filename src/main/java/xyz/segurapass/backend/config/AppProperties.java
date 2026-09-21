package xyz.segurapass.backend.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AppProperties {

    @Getter
    @Value("${app.credentials-limit}")
    private int credentialsLimit;

}
