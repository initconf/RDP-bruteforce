module RDP;

export {

        redef enum Notice::Type += {
	    HotAccount, 
            PasswordGuessing, 	
            BruteforceScan,
            ScanSummary,
        };

        global rdp_scanners_account = /a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z/ &redef ;
        redef  rdp_scanners_account +=   /A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z/ ;
        redef  rdp_scanners_account +=   /NCRACK_USER|hello|root/; 

	global rdp_scanner: set[addr] ; 


	### cheat-sheet 
	# RemoteIP - R
	# Host - H
	# Account - A 
	# Passwords - P 
	# Many - m 
	# Single - s 
	
	# R-> sH-sA-mP  - same host, same account, many passwords 
	# R-> sH-mA-(s|m)P - same host, many accounts (single|many)passwords 
	# R-> mH-sA-(s|m)P 
	# R-> mH-mA-(s|m)P 

	# remote IP - same host same account many passwords  - R-> sH-sA-mP  
	global expire_sHost_sAccount_mPasswords: function (t: table[addr, string] of count, v: any): interval ; 
	global sHost_sAccount_mPasswords: table [addr, string] of count &create_expire=2 hrs &expire_func=expire_sHost_sAccount_mPasswords; 

	# remote IP -> same host many account (single|many) passwords - R-> sH-mA-(s|m)P 
	global expire_sHost_mAccounts: function (t: table[addr] of set[string], v: addr): interval ; 
	global sHost_mAccounts: table [addr] of set[string] &create_expire=1 day &expire_func=expire_sHost_mAccounts; 

	# remote IP -> many host (same|many) account (single|many) passwords - R-> mH-(s|m)A-(s|m)P 
	global expire_mHost_smAccounts: function (t: table[addr] of set[addr, string], v: addr): interval ; 
	global mHost_smAccounts: table [addr] of set[addr, string] &create_expire=1 day &expire_func=expire_mHost_smAccounts; 

	type r: record {
		a : set[addr] ; 
		s : set[string] ; 
	} ; 

	global expire_summary: function(t: table[addr] of r, a:addr): interval ; 
	global summary: table[addr] of r &create_expire=1 hrs &expire_func=expire_summary ; 
	
	global check_rdp_bruteforce: function(c: conn_id, cookie: string); 

        global rdp_threshold = 5 &redef ;
	global threshold_mHost_smAccounts = 3 &redef ; 

	global RDP::rdp_new: event( c: conn_id, cookie: string);
        global RDP::rdp_add: event( c: conn_id, cookie: string); 

}

#@if ( Cluster::is_enabled() )
#@load base/frameworks/cluster
#redef Cluster::manager2worker_events += /RDP::rdp_add/;
#redef Cluster::worker2manager_events += /RDP::rdp_new/;
#@endif

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init()
        {
        Broker::auto_publish(Cluster::worker_topic, RDP::rdp_add) ; 
        }
@else
event zeek_init()
        {
        Broker::auto_publish(Cluster::manager_topic, RDP::rdp_new) ; 
        }
@endif

@endif



#event rdp_connect_request(c: connection, cookie: string) &priority=5

event log_rdp(rec: RDP::Info)
{
        #print fmt ("%s", rec);

	if (! rec?$cookie)
		return ; 

	### we ignore success authentications
	### since such repeated auths can result in 
	### false positives for sUser_sHost_mPasswords 

	if ( rec?$result && rec$result == "Success")
		return ; 

	if (rec$id$orig_h in rdp_scanner ) 
		return ;

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER) 
	event RDP::rdp_new(rec$id, rec$cookie); 
@elseif ( ! Cluster::is_enabled() )
	log_reporter(fmt("running local check_rdp_bruteforce %s, %s to manager:", rec$id, rec$cookie),0); 
        check_rdp_bruteforce(rec$id, rec$cookie);
@endif 
}



@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) 
event RDP::rdp_new(c: conn_id, cookie: string) 
{
	log_reporter(fmt("received %s, %s to manager:", c, cookie),0); 
	check_rdp_bruteforce(c, cookie); 

} 
@endif 


@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )

event RDP::rdp_add (c: conn_id, cookie: string) 
{
	add rdp_scanner[c$orig_h] ; 

	log_reporter(fmt("WORKERS Got: c: %s, cookie: %s", c, cookie),0); 
} 
@endif 

function expire_summary(t: table[addr] of r, a:addr): interval
{

	print fmt ("expire_summary: addr: %s, T: %s", a, t[a]); 
	return 0 secs ; 
} 


hook Notice::policy(n: Notice::Info)
{
  if ( n$note == RDP::HotAccount)
  {
    add n$actions[Notice::ACTION_DROP];
  } 
  if ( n$note == RDP::BruteforceScan)
  {
    add n$actions[Notice::ACTION_DROP];
  } 
}


function expire_sHost_sAccount_mPasswords(t: table[addr, string] of count, v: any): interval
{

	return 0 secs ;

	local ip :addr ;
	local account : string ; 
	[ip, account] = v ; 
		
	#print fmt ("%s, %s %s", ip, account, t[ip, account]); 

	NOTICE([$note=RDP::ScanSummary, $src=ip, 
	$msg=fmt("%s bruteforcing password Account: %s on %s uniq hosts",
       	ip, account, t[ip, account] )]);

	return 0 secs; 
} 

function expire_sHost_mAccounts(t : table [addr] of set[string], v: any): interval 
{
	#print fmt ("expire_sHost_mAccounts T: %s, v: %s", t, v); 

	local account_list: string = "" ;

	local scan_addr = v ; 

       	for (a in sHost_mAccounts[scan_addr])
       	{
       		account_list += fmt ("%s ", a );
	}

       	NOTICE([$note=RDP::ScanSummary, $src=scan_addr,
       	$msg=fmt("%s bruteforced RDP using %s accounts: %s",
	scan_addr, |sHost_mAccounts[scan_addr]|, account_list)]);

	return 0 secs ; 
} 

function expire_mHost_smAccounts ( t: table [addr] of set[addr, string], v: any): interval 
{
	print fmt ("expire: expire_mHost_smAccounts T: %s, v: %s", t, v);
	
	local scan_addr = v ; 
	local account_list: string = "" ;

       	for (a in sHost_mAccounts[scan_addr])
       	{
       		account_list += fmt ("%s ", a );
	}

	NOTICE([$note=RDP::ScanSummary, $src=scan_addr,
       	$msg=fmt("%s bruteforced RDP using Account: %s times, %s",
       	scan_addr, |mHost_smAccounts[scan_addr]|, account_list)]);

        return 0 secs ;
} 




function check_rdp_bruteforce(c: conn_id, cookie: string)  
{ 

        local orig=c$orig_h ;
        local resp=c$resp_h ;


	if (orig !in summary)
	{ 
		local aa: set[addr]=set() ; 
		local ss: set[string]=set() ;
		local rec: r ;
		add aa [resp] ; 
		add ss [cookie] ; 
		rec$a = aa ;
		rec$s = ss ; 
		summary[orig] = rec ; 
	} 
	add summary[orig]$a[resp]; 
	add summary[orig]$s[cookie]; 

	print fmt ("SUMMARY: %s", summary[orig]); 
	
	### Case I: if these are Hot accounts, block them instantly 
        if (cookie == rdp_scanners_account)
        {
		NOTICE([$note=RDP::HotAccount, $src=c$orig_h,
		$msg=fmt("I: %s bruteforced %s on  RDP (%s) using HotAccount: \"%s\" ",
		c$orig_h, c$resp_h, c$resp_p, cookie)]);

		### send to workers a new scanner:
		event RDP::rdp_add(c, cookie); 
	} 


	### Case II: Same host same account many password 
	if ( [orig,cookie] !in sHost_sAccount_mPasswords)
	{ 
		sHost_sAccount_mPasswords[orig,cookie] = 0  ; 
	} 
		
	sHost_sAccount_mPasswords[orig,cookie] += 1  ; 

	if (sHost_sAccount_mPasswords[orig,cookie] == rdp_threshold) 
	{ 
		NOTICE([$note=RDP::PasswordGuessing, $src=c$orig_h, 
		$msg=fmt("%s is bruteforce guessing password on %s:%s using Account: %s",
			c$orig_h, c$resp_h, c$resp_p, cookie)]);

		### send to workers a new scanner:
                event RDP::rdp_add(c, cookie); 
	} 
	 
	### Case III: Same src IP, hitting many accounts 
        if ( orig !in sHost_mAccounts)
        {
            sHost_mAccounts[orig] = set();
            add sHost_mAccounts[orig] [cookie] ;
        }

        add sHost_mAccounts[orig] [cookie] ;

        if (|sHost_mAccounts[orig]| == rdp_threshold )
        {
            local account_list: string = "" ;

            for (a in sHost_mAccounts[orig])
            {
                    account_list += fmt ("%s ", a );
            }

            NOTICE([$note=RDP::BruteforceScan, $src=c$orig_h,
            $msg=fmt("II: %s bruteforced %s on  RDP (%s) using Account: \"%s\" ",
            c$orig_h, c$resp_h, c$resp_p, account_list)]);

	    ### send to workers a new scanner:
	    event RDP::rdp_add(c, cookie); 
        }

	### Case IV: Password Bruteforce : Same Src, same account many many times 
	if (orig !in mHost_smAccounts)
	{
		mHost_smAccounts[orig]=set(); 
	}
	
	if ( [resp,cookie] !in mHost_smAccounts[orig])
       	{
	    add mHost_smAccounts[orig] [resp,cookie] ; 
	} 
       		
	if (|mHost_smAccounts[orig]| == threshold_mHost_smAccounts) 
	{ 	

		local hosts_set: set[addr] ; 
		local user_set: set[string] ; 

		for ([hosts,accts] in mHost_smAccounts[orig])
		{
			add hosts_set[hosts]; 
			add user_set[accts] ; 
		} 
	    NOTICE([$note=RDP::BruteforceScan, $src=c$orig_h,
	    $msg=fmt("%s bruteforced %s hosts using %s account(s)",
	    c$orig_h, |hosts_set|, |user_set|)]);

	   ### send to workers a new scanner:
	   event RDP::rdp_add(c, cookie); 
       	}
}

event zeek_done()
{
#	print fmt ("%s", sHost_mAccounts); 
}
