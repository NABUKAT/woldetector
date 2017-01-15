# woldetector

woldetector is a WoL packet detection tool for running Raspberry Pi.

## Requirement
	$ apt-get install libpcap0.8 libpcap0.8-dev

## Usage

	$ sudo woldetector [network interface] [unix command]

For example...

	$ sudo woldetector eth0 "service kodi stop && service kodi start" &

Cron setting

	@reboot su -c "/usr/bin/woldetector eth0 'service kodi stop && service kodi start'"


## Install

	$ gcc woldetector.c -o woldetector -lpcap

Ignore some warning..