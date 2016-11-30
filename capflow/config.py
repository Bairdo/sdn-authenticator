# Mac address of authentication server
AUTH_SERVER_MAC = "08:00:27:00:03:02"
# IP address of authentication server
AUTH_SERVER_IP = "10.0.0.3"
# Switch port authentication server is facing
AUTH_SERVER_PORT = 1

CTL_REST_IP = "10.0.10.2"
CTL_REST_PORT = "8080"
CTL_MAC = "08:00:27:00:02:02"

GATEWAY_MAC = "08:00:27:00:04:02"
GATEWAY_PORT = 2
# L2 src-dst pairs which are whitelisted and does not need to go through auth
WHITELIST = [
             (AUTH_SERVER_MAC, CTL_MAC),
             (CTL_MAC, AUTH_SERVER_MAC),
             (GATEWAY_MAC, "00:1d:a2:80:60:64"),
             ("00:1d:a2:80:60:64", GATEWAY_MAC),
             ]
