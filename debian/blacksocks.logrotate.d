/var/log/blacksocks/*log {
	daily
	rotate 5
	compress
	delaycompress
	missingok
	notifempty
	create 0640 blacksocks adm
	sharedscripts
	postrotate
		/etc/init.d/blacksocks reload > /dev/null
	endscript
}
