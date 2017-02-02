# Mac address of authentication server
AUTH_SERVER_MAC = "00:71:00:ff:28:e6"
# IP address of authentication server
AUTH_SERVER_IP = "10.0.0.4"
# Switch port authentication server is facing
AUTH_SERVER_PORT = 2

CTL_REST_IP = "10.0.10.2"
CTL_REST_PORT = "8080"
CTL_MAC = "08:00:27:00:02:02"

GATEWAY_MAC = "f4:f2:6d:70:95:6d"
GATEWAY_PORT = 1
# L2 src-dst pairs which are whitelisted and does not need to go through auth
WHITELIST = [
             (AUTH_SERVER_MAC, CTL_MAC),
             (CTL_MAC, AUTH_SERVER_MAC),
             (GATEWAY_MAC, "00:1d:a2:80:60:64"),
             ("00:1d:a2:80:60:64", GATEWAY_MAC),
             ]
