module RDP;

export {
	global log_reporter: function (msg: string, debug: count);
} 

function log_reporter(msg: string, debug: count)
{
        if (debug <= 2) {
                @if ( ! Cluster::is_enabled())
                        print fmt("%s", msg);
                @endif
                event reporter_info(network_time(), msg, peer_description);

	}
}

