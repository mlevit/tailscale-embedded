# ESP-IDF example

A tailnet node on an ESP32-P4. It brings the network up with ESP-IDF's `example_connect()` (Ethernet by default,
Wi-Fi if you choose it), sets the clock, starts tailscale-embedded and logs the netmap.

```sh
cd examples/esp-idf
idf.py menuconfig   # "tailscale-embedded example": control URL, hostname, auth key; "Example Connection Configuration"
idf.py build flash monitor
```

With no auth key, the log prints a URL: open it to add the node to your tailnet. Once the node is running, ping it
from another node: `tailscale ping --icmp <hostname>`. lwIP answers from behind the tunnel.

`sdkconfig.defaults` sets what tailscale-embedded needs: PSRAM, the firmware running from PSRAM, the mbedTLS options,
TLS 1.2, lwIP's sizes and a 1.5 MB app partition. The auth key lands in `sdkconfig` and in the image, so `sdkconfig`
and `build/` are gitignored.
