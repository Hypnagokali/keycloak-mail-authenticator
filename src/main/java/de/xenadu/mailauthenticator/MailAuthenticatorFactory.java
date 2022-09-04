package de.xenadu.mailauthenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public class MailAuthenticatorFactory implements AuthenticatorFactory {
    @Override
    public String getDisplayType() {
        return "E-Mail Authentication";
    }

    @Override
    public String getReferenceCategory() {
        return "otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Validates an OTP via Mail";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Arrays.asList(
                getLengthProperty(),
                getTimeToLiveProperty(),
                getSimulationProperty()
        );
    }

    private ProviderConfigProperty getSimulationProperty() {
        return new ProviderConfigProperty("simulation",
                "Simulation Mode",
                "In Simulation Mode, the Mail will not be sent. Just writes a log-entry",
                ProviderConfigProperty.BOOLEAN_TYPE,
                true);
    }


    private ProviderConfigProperty getTimeToLiveProperty() {
        return new ProviderConfigProperty("ttl",
                "Time to live",
                "Defines the time in seconds until the code is invalid",
                ProviderConfigProperty.STRING_TYPE,
                300);
    }

    private ProviderConfigProperty getLengthProperty() {
        return new ProviderConfigProperty("length",
                "Length of Code",
                "Define the length of OTP send by mail",
                ProviderConfigProperty.STRING_TYPE,
                6);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new MailAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "email-authenticator";
    }
}
