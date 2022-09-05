package de.xenadu.mailauthenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.Locale;

public class MailAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        System.out.println("authenticate() executed");
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();

        String email = user.getEmail();

        if (email == null) {
            System.out.println("Email is null!!");
            return;
        }
        // mobileNumber of course has to be further validated on proper format, country code, ...

        int length = Integer.parseInt(config.getConfig().get("length"));
        int ttl = Integer.parseInt(config.getConfig().get("ttl"));

        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote("code", code);
        authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

        try {
            Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
            Locale locale = session.getContext().resolveLocale(user);
            String mailAuthText = "Eingabe E-Mail"; // theme.getMessages(locale).getProperty("smsAuthText");
            String smsText = String.format(mailAuthText, code, Math.floorDiv(ttl, 60));

//            SmsServiceFactory.get(config.getConfig()).send(email, smsText);

            context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm("TempCode"));
        } catch (Exception e) {
//            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
//                    context.form().setError("E-Mail not send", e.getMessage())
//                            .createErrorPage();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        System.out.println("action() executed");
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getEmail() != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }
}
