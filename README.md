NRF24_Sniffer
=============

Sniffer for Nordic NRF24L01+ modules

The wireless 2.4GHz Nordic Semiconductor nRF24L01+ chip (or nRF24 for short), does not support promiscuous mode,
which in theory makes it impossible to capture network traffic between different nodes on a network.

This project contains a wireless sniffer for nRF24L01+ wireless modules meeting following requirements:
* Based on commodity, cheap hardware
* Traffic capturing for network with known parameters (channel, baudrate, base address)
* Analysis using Wireshark network protocol analyzer
* Possibility to analyze protocols which use the nRF24 for transport in their network

For a full description of this project see:
* http://yveaux.blogspot.nl/2014/07/nrf24l01-sniffer-part-1.html
* http://yveaux.blogspot.nl/2014/07/nrf24l01-sniffer-part-2.html
* http://yveaux.blogspot.nl/2014/07/nrf24l01-sniffer-part-3.html
