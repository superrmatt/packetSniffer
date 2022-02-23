use Net::Pcap;
use NetPacket;
use DBI;
use DBD::mysql;

use strict;
use warnings;
use Data::Dumper;


#index variable used to determine how many packets the program will scan.
my $i;
$i = 626918;

#this can easily be changed to while(true) for continuous run until interupted by a kill command.
while ($i < 10000000){

	my $err = '';
	my $pcap_t;

	my $dev;
	$dev = pcap_lookupdev(\$err);
	$err = '';

	$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 10, \$err);
	if($err ne ''){
		print "error = ", $err, "\n\n";
		return 0;
	}

	Net::Pcap::loop($pcap_t, 0, \&getPayload, 1);

	Net::Pcap::close($pcap_t);

	print "Done.\n";

	#parses payload into a human readable format.
	sub parsePayload{
	   my($payload, $text) = @_;
   	   my $data = unpack("H*",$payload);
	   print "Data: $data\n\n--------------------------------------------------------------------------\n\n";
	}


	# you guessed it, get payload. Grabs the packet from cyberspace.
	sub getPayload{
	   my ($userdata, $header, $packet) = @_;

	   my $ether_data = NetPacket::Ethernet::strip($packet);

	   my $ip = NetPacket::IP->decode($ether_data);
   

		print "Dumper = \n";
		print Dumper $ip, "\n\n\n";
		print "-------------------------\n\n\n";

		#FYI, there are probably a few more variables I am missing here which are assocaited with a network packet header.
		my $num;
		my $ver;
		my $proto;
		my $dest_ip;
		my $chksum;
		my $src_ip;
		my $hlen;
		my $ttl;
		my $foffset;
		my $options;
		my $len;
		my $tos;
		my $id;
		my $flags;

		#assign packet header vars to our vars.
		$ver = $ip->{'ver'};
		$proto = $ip->{'proto'};
		$dest_ip =$ip->{'dest_ip'};
		$chksum = $ip->{'cksum'};
		$src_ip = $ip->{'src_ip'};
		$hlen = $ip->{'hlen'};
		$ttl = $ip->{'ttl'};
		$foffset = $ip->{'foffset'};
		$options = $ip->{'options'};
		$len = $ip->{'len'};
		$tos = $ip->{'tos'};
		$id = $ip->{'id'};
		$flags = $ip->{'flags'};
   
		my $connection;
		my $query;
		my $result;

		#open connection to a DB and insert all of the values. Make sure the DB mirrors these values, or change them as you see fit.
		$connection = DBI->connect(<DBNAME example to right> -> "DBI:mysql:<name>:127.0.0.1", <username>, <password>);
		$query = $connection->prepare("insert into packets values ($i, $ver, $proto, '$dest_ip', $chksum, '$src_ip', $hlen, $ttl, $foffset, '$options', $len, $tos, $id, $flags);");
		$result = $query->execute();
  	 

		$i = $i + 1;
	}
}

