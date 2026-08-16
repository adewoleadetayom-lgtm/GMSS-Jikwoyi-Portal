#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$(dirname "$0")"
pkg install nodejs -y
npm install
echo "GMSS Jikwoyi Portal is starting..."
echo "Open Chrome: http://localhost:3000"
npm start
