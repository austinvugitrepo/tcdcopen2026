#!/bin/sh

password=$(openssl rand -base64 8)
echo $password >> passwords.text
cat user.txt | xargs -n 1 usermod -p "$password"
