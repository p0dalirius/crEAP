# crEAP

<p align="center">
  crEAP is a python script that will identify WPA Enterprise mode EAP types and if insecure protocols are in use, will attempt to harvest usernames and/or handshakes. 
  <br>
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/crEAP">
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <br>
</p>


## Features

 - [x] Analyze packets from a PCAP capture file (option `--read`).
 - [x] Sniff packet in live mode on a specific interface.

## Usage

```
$ ./crEAP.py -h
usage: crEAP.py [-h] [--debug] [--no-colors] [-l LOGFILE] [-r PCAP] [-i INTERFACE] [-c CHANNEL]

Description message

optional arguments:
  -h, --help            show this help message and exit
  --debug               Debug mode.
  --no-colors           No colors mode.
  -l LOGFILE, --logfile LOGFILE
                        Log file to save output to.
  -r PCAP, --read PCAP  [OPTIONAL] Read from PCAP file, else live capture is default.
  -i INTERFACE, --interface INTERFACE
                        [OPTIONAL] Wireless interface to capture.
  -c CHANNEL, --channel CHANNEL
                        [OPTIONAL] Wireless channel to monitor. 2.4/5GHZ spectrums supported so long as your
                        adapter supports it. The ALFA AWUS051NHv2 is recommended for dual band support.

```

## Credits

This tool was initially developped in 2015 by [@Snizz](https://github.com/Snizz) and [@Shellntel](https://github.com/Shellntel). I refactored the code and ported it to python3 in October 2021.

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## References
 - https://www.shellntel.com/blog/2015/9/23/assessing-enterprise-wireless-networks
 - https://en.wikipedia.org/wiki/Extensible_Authentication_Protocol
