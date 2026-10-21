#!/usr/bin/env bash
set -euo pipefail
export PATH=/mingw64/bin:$PATH
cd "$(dirname "$0")"
/mingw64/bin/g++.exe -std=c++17 -O2 -static -static-libgcc -static-libstdc++ -I include -o dpi_simple_new.exe \
  src/main_working.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp -pthread
echo "BUILD_OK"
