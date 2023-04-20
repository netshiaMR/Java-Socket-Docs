import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringApplicationRunListener;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.io.Resource;

public class TSLCertLoader implements SpringApplicationRunListener {

    private static final String KEYSTORE_TYPE = "JKS";
    private static final String KEYSTORE_PASSWORD = "keystorePassword";
    private static final String TRUSTSTORE_PASSWORD = "truststorePassword";

    @Value("${keystone.path}")
    private String keystonePath;

    @Value("${truststore.path}")
    private String truststorePath;

    public TSLCertLoader(SpringApplication application, String[] args) {}

    @Override
    public void started(ApplicationStartedEvent event) {
        ConfigurableApplicationContext context = event.getApplicationContext();
        try {
            Resource keystoneResource = context.getResource(keystonePath);
            Resource truststoreResource = context.getResource(truststorePath);

            KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            try (InputStream keystoreInputStream = keystoneResource.getInputStream()) {
                keystore.load(keystoreInputStream, KEYSTORE_PASSWORD.toCharArray());
            }

            KeyStore truststore = KeyStore.getInstance(KEYSTORE_TYPE);
            try (InputStream truststoreInputStream = truststoreResource.getInputStream()) {
                truststore.load(truststoreInputStream, TRUSTSTORE_PASSWORD.toCharArray());
            }

            TSLCertManager.setKeystore(keystore);
            TSLCertManager.setTruststore(truststore);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load Keystone and truststore certificates", e);
        }
    }

    @Override
    public void starting() {}
    @Override
    public void environmentPrepared() {}
    @Override
    public void contextPrepared() {}
    @Override
    public void contextLoaded() {}
    @Override
    public void finished(ConfigurableApplicationContext context, Throwable exception) {}

}
