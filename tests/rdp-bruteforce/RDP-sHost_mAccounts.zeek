# @TEST-EXEC: zeek -C -r $TRACES/RDP-sHost_mAccounts.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

