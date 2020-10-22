# @TEST-EXEC: zeek -C -r $TRACES/RDP-sHost_sAccount_mPasswords.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

