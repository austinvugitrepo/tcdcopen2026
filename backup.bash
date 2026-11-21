#!/bin/bash

tar -cvzf sshbackup.tar.gz /etc/ssh
tar -cvzf homebackup.tar.gz /home
tar -cvzf logbackup.tar.gz /var/log
tar -cvzf spoolbackup.tar.gz /var/spool
tar -cvzf rootbackup.tar.gz /root
mkdir auth
cp /etc/{passwd,shadow,group,gshadow,sudoers} auth/
mkdir ftp
cp /etc/{ftpusers,vsftpd.conf} ftpstuff/


