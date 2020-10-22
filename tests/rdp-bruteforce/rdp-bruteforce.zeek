# @TEST-EXEC: zeek -C -r $TRACES/RDP-bruteforce.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

