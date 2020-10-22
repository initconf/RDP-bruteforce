module RDP;

export {

	global hot_rdp_accounts = { "NCRACK_USER", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
						"k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
						"u", "v", "w","x", "y", "z",
				  }; 

	redef enum Notice::Type += {
		RDPHotAccount, 
	}; 
}


event log_rdp(rec: Info) 
{

	if (rec$cookie in hot_rdp_accounts)
	{  

	 	NOTICE([$note=RDPHotAccount, $id=rec$id, 
                                        $msg=fmt("Possible RDP login involving a %s with an interesting username.", rec$cookie)]);
	} 
} 
