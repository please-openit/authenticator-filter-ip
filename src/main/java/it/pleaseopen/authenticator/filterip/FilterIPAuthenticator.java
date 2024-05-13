package it.pleaseopen.authenticator.filterip;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

public class FilterIPAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(FilterIPAuthenticator.class);

    private final KeycloakSession session;

    public FilterIPAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Because we are behind a reverse proxy
        String ipSource = context.getHttpRequest().getHttpHeaders().getHeaderString("X-Forwarded-For");
        // if we are in direct, without a proxy
        if(ipSource == null){
            ipSource = context.getConnection().getRemoteAddr();
        }

        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        authenticatorConfig.getConfig();
        List<String> allowedRanges = Arrays.asList(authenticatorConfig.getConfig().get("Allowed IPs").split("##"));

        for(String range: allowedRanges){
            if(range.contains("-")){
                try {
                    long ipLo = ipToLong(InetAddress.getByName(range.split("-")[0]));
                    long ipHi = ipToLong(InetAddress.getByName(range.split("-")[1]));
                    long ipToTest = ipToLong(InetAddress.getByName(ipSource));
                    if(ipToTest >= ipLo && ipToTest <= ipHi){
                        context.success();
                    }
                } catch (UnknownHostException e) {
                    LOG.error("unable to decode ip address", e);
                    context.failure(AuthenticationFlowError.ACCESS_DENIED);
                }
            }else{
                try{
                    long ipToTest = ipToLong(InetAddress.getByName(ipSource));
                    if(ipToTest == ipToLong(InetAddress.getByName(range))){
                        context.success();
                    }
                } catch (UnknownHostException e) {
                    LOG.error("unable to decode ip address", e);
                    context.failure(AuthenticationFlowError.ACCESS_DENIED);
                }
            }
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
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
