# dtrace-to-pcap

A small utility to convert DECT traces captured using `dtrace` on a Fritz!Box (https://www.boxmatrix.info/wiki/Property:dtrace_(avmcmd)) into a format that can be loaded into Wireshark for analysis.

![The main Wireshark package UI with 14 packets, all with Protocol DECT-DLC. They show a typical DECT flow including MM-LOCATE-REQUEST, MM-AUTH-REQ, MM-AUTH-REPLY, etc.](./assets/wireshark-result.png)

## Usage

### Creating a capture file

You can create a `dtrace` capture using your Fritz!Box at `http://fritz.box/html/capture.html`.
No additional arguments need to be specified.
The resulting `fritzbox_<timestamp>_dtrace.txt` file can then be converted to a `.pcap` file using this utility.

### Using this utility

- Install the requirements using `pip install -r requirements.txt` or `uv sync`.
- Run `python3 dtrace-to-pcap.py <your_dtrace.txt> -o out.pcap`

### Loading the resulting data in Wireshark 

Load the `.pcap` file as usual or launch `dtrace-to-pcap.py` with the `--open-in-wireshhark` flag.

I am abusing the Mitel DECT-over-Ethernet packet type to put DECT packets into the `.pcap` file.
Since I have not added the full TCP flow below it, we need to tell Wireshark that it should use the Mitel-DECToE dissector to decode it.

Right-click one of the packets in Wireshark (they will be shown as Ethernet II) > Decode as... > Select Current: Mitel-DECToE > Save

![The Wireshark "Decode As..." UI showing Field=Ethertype, Value=0x6559, Type=Integer (base 16), Default=(none), Current=Mite-DECToE](./assets/wireshark-decode-as.png)
