## wifuzz
### why?
wanted my own wireless fuzzer

### what's inside?
[scapy](https://scapy.net/) for packet generation / sending<br>
[netifaces](https://pypi.org/project/netifaces/) to automatically get a wifi interface if none supplied<br>
[mac_vendor_lookup](https://pypi.org/project/mac-vendor-lookup/) for ...<br>
[terminaltables](https://pypi.org/project/terminaltables/) to make stuff look fancy<br>
[progressbar2](https://pypi.org/project/progressbar2/) for fanciness<br>
[pybt](https://github.com/nbdy/pybt) for bluetooth stuff<br>

### how to ...
#### ... get started
```shell script
sudo apt install aircrack-ng
pip3 install wifuzz # or git+https://github.com/nbdy/wifuzz
```
#### ... to use it
```shell script
usage: ./wifuzz.py {arguments}
	{arguments}		{example/hint}
	-h	--help		this
	-t	--target	fe:ed:de:ad:be:ef
		--targets	de:ad:be:ef:b0:ff,c0:33:b3:ff:ee:33
	-s	--scan		scan for mac addresses/targets
	-w	--wifi		use wifi
	-b	--bt		use bluetooth
	-i	--interface	call supply after -w/-b
	-a	--adb		use adb
	-d	--device	adb transport id
		--devices	tid1,tid2,tid5
	-m	--mac-lookup	lookup macs
ex:
sudo ./wifuzz.py -m -s -w
```
### notes
#### interfaces are found automatically
though the first available is always used<br>
ex: wlan0; hci0
