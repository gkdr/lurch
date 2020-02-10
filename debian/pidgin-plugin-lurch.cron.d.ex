#
# Regular cron jobs for the purple-lurch package
#
0 4	* * *	root	[ -x /usr/bin/purple-lurch_maintenance ] && /usr/bin/pidgin-plugin-lurch_maintenance
