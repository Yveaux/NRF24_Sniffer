Connect the Arduino Hardware, run this tool in command line, e.g:
./Nrf24Sniff -c70 -r2 -l5 -p3 -a0xb086f30000 -C2 -v

Use ./Nrf24Sniff -h to see a help page which explains the command line interface.

Command to connect Wireshark on Linux:
./wireshark -k -i /tmp/wireshark

Command to connect Wireshark on Windows:
wireshark -k -i \\.\pipe\wireshark
