package xyz.segurapass.backend.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JacksonJsonSerializer;
import xyz.segurapass.api.email.EmailReq;

import java.util.HashMap;
import java.util.Map;

import static xyz.segurapass.backend.config.EmailClient.EMAIL_TOPIC;

@Configuration
@ConditionalOnProperty(
        name = "app.email.active",
        havingValue = "true"
)
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Bean
    public ProducerFactory<String, EmailReq> emailProducerFactory() {
        Map<String, Object> props = new HashMap<>();

        props.put(
                ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,
                bootstrapServers
        );

        props.put(
                ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG,
                StringSerializer.class
        );

        props.put(
                ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG,
                JacksonJsonSerializer.class
        );

        return new DefaultKafkaProducerFactory<>(props);
    }

    @Bean
    public KafkaTemplate<String, EmailReq> emailKafkaTemplate(
            ProducerFactory<String, EmailReq> emailProducerFactory
    ) {
        return new KafkaTemplate<>(emailProducerFactory);
    }

    @Bean
    public NewTopic emailTopic() {
        return TopicBuilder
                .name(EMAIL_TOPIC)
                .partitions(1)
                .replicas(1)
                .build();
    }
}