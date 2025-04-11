$wslIP = (wsl hostname -I).trim()
$port = 8080

# Remove any existing port forwarding
netsh interface portproxy delete v4tov4 listenport=$port listenaddress=0.0.0.0

# Add new port forwarding rule
netsh interface portproxy add v4tov4 listenport=$port listenaddress=0.0.0.0 connectport=$port connectaddress=$wslIP