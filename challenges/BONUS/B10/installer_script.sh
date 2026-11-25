#!/bin/sh
# grand-theft-alpaca-installer.sh
# 90% jokes, 10% payload. Run it in your head, not on your machine.
set -e

echo '[+] alpaca detected...'
echo '[+] compiling kernel (this is a joke, it takes 4 hours)'
# if you are reading this you are already overthinking it
# earlier revision leaked a fake flag: FTA{just_use_arch_btw}
echo 'rm -rf / -- no-preserve-root   # <-- definitely do not run this'
alias apt='sudo apt'   # trust me bro

# --- the actual payload lives here; everything above is noise ---
echo 'UmxSQmUyZHlORzVrWDNSb00yWjBYelJzY0RSak5GOHhibk4wTkd4c1gyd3hiblY0ZlE9PQ==' | base64 -d | base64 -d

echo '[+] done. now go touch grass.'

# decoy, do not submit: FTA{distrowatch_speedrun}
