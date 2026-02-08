# Tcpreplay Sample Captures

## Overview

Tcpreplay Suite can read nearly any packet capture file. If you prefer to get up and running quickly, we have provided some sample captures. They are specially designed to test IP Flow/NetFlow, but they are also useful for testing performance of switches and network adapters.

---

### smallFlows.pcap

This is a synthetic capture which is a combination of several captures containing a few different applications. It is designed to create a large number of flows utilizing various protocols at a relatively low network traffic rate. If you want to have many flows in a small file and are not concerned about how realistic the combination of flows is, select this capture.

- **Size:** 9.4 MB
- **Packets:** 14,261
- **Flows:** 1,209
- **Average packet size:** 646 bytes
- **Duration:** 5 minutes
- **Number Applications:** 28

### bigFlows.pcap

This is a capture of real network traffic on a busy private network’s access point to the Internet. The capture is much larger and has a smaller average packet size than the previous capture. It also has many more flows and different applications. If the large size of this file isn’t a problem, you may want to select it for your tests.

- **Size:** 368 MB
- **Packets:** 791,615
- **Flows:** 40,686
- **Average packet size:** 449 bytes
- **Duration:** 5 minutes
- **Number Applications:** 132

### test.pcap

This is a small capture that is included in the source tarball and is used to test accuracy of `tcpreplay` results during `sudo make test`. It is also good for demonstrating `tcpprep` capabilities.

- **Size:** 0.07 MB
- **Packets:** 141
- **Flows:** 37
- **Average packet size:** 445 bytes
- **Duration:** 3 seconds
- **Number Applications:** 1

---

## Contributions

If you have other good examples of pcap files that work well with Tcpreplay please contact the maintainer.
