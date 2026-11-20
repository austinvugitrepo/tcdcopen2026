#!/bin/bash

for users in $(cat user.text); do read -p " processing $users ... press any key to continue. " answer; password=$(openssl rand -base64 9); echo "$users:$password" >> password.text; encryptpasswd=$(openssl passwd -6 "$password"); echo "$users:$encryptpasswd" | chpasswd -e; done
