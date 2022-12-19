# esto ~ Block malicious authorization attempt's IP addresses

Esto is a Finnish word which means (block). This is a small tokio based async application that is able to follow a number of resources
with user defined matching conditions. This app parses the IP address from the matching line and later block / unblock the IP address
based on criterias like
 * How long has passed since latest attempts?
 * How long IP has been blockec?
 * How many attemps has been recored for the IP address?

Application will persist blocked IPs and the state will be restored in application startup. It runs as a systemd service and logs to journald.
