package it.pleaseopen.authenticator.filterip;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

public class FilterIPConditionalAuthenticator implements ConditionalAuthenticator {

    private static final Logger LOG = Logger.getLogger(FilterIPConditionalAuthenticator.class);

    private final KeycloakSession session;

    public FilterIPConditionalAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public boolean matchCondition(AuthenticationFlowContext authenticationFlowContext) {
        String ipSource = authenticationFlowContext.getConnection().getRemoteAddr();
        AuthenticatorConfigModel authenticatorConfig = authenticationFlowContext.getAuthenticatorConfig();
        authenticatorConfig.getConfig();
        List<String> allowedRanges = Arrays.asList(authenticatorConfig.getConfig().get("Allowed IPs").split("##"));

        for(String range: allowedRanges){
            if(range.contains("-")){
                try {
                    long ipLo = ipToLong(InetAddress.getByName(range.split("-")[0]));
                    long ipHi = ipToLong(InetAddress.getByName(range.split("-")[1]));
                    long ipToTest = ipToLong(InetAddress.getByName(ipSource));
                    if(ipToTest >= ipLo && ipToTest <= ipHi){
                        return true;
                    }
                } catch (UnknownHostException e) {
                    LOG.error("unable to decode ip address", e);
                }
            }else{
                try{
                    long ipToTest = ipToLong(InetAddress.getByName(ipSource));
                    if(ipToTest == ipToLong(InetAddress.getByName(range))){
                        return true;
                    }
                } catch (UnknownHostException e) {
                    LOG.error("unable to decode ip address", e);
                }
            }

        }
        return false;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {

    }

    private long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result <<= 8;
            result |= octet & 0xff;
        }
        return result;
    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }
}

