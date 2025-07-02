package it.pleaseopen.authenticator.filterip;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class FilterIPConditionalAuthenticatorFactory implements ConditionalAuthenticatorFactory {
    @Override
    public String getDisplayType() {
        return "Condition - IP in a range";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public ConditionalAuthenticator getSingleton() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Check if IP is in range";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {



        ProviderConfigProperty providerConfigProperty = new ProviderConfigProperty();
        providerConfigProperty.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        providerConfigProperty.setDefaultValue("192.168.1.1-192.168.1.2");
        providerConfigProperty.setName("Allowed IPs");
        providerConfigProperty.setLabel("List of IP address allowed");
        providerConfigProperty.setHelpText("Each IP listed will be allowed, all other results to an authentication failed");
        List<ProviderConfigProperty> providerConfigProperties = new ArrayList<>();
        providerConfigProperties.add(providerConfigProperty);
        return providerConfigProperties;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return new FilterIPConditionalAuthenticator(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "POIT-cond-auth-IP-range";
    }
}
