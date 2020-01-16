#protocol number 179, unassigned
#protocl 0 = IPV6 hop by hop
#	not sure what it is, every piece of data is 0
# 	checksum = 0 
# 	header = 0
# 	options = null
# 	len is 65535, very long?
# 	parent undefined
# 	src/dest ip both = 0.0.0.0
# 	netpacket::IP

use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::ICMP;
use NetPacket::IGMP;
use DBI;
use DBD::mysql;

use strict;
use warnings;
use Data::Dumper;


my $i;
$i = 626918;

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

	sub parsePayload{
	   my($payload, $text) = @_;
   	   my $data = unpack("H*",$payload);
	   print "Data: $data\n\n--------------------------------------------------------------------------\n\n";
	}



	sub getPayload{
	   my ($userdata, $header, $packet) = @_;

	   my $ether_data = NetPacket::Ethernet::strip($packet);

	   my $ip = NetPacket::IP->decode($ether_data);
   

	print "Dumper = \n";
	print Dumper $ip, "\n\n\n";
	print "-------------------------\n\n\n";
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

	$connection = DBI->connect("DBI:mysql:real_IDS:127.0.0.1", "root", "password");
	$query = $connection->prepare("insert into packets values ($i, $ver, $proto, '$dest_ip', $chksum, '$src_ip', $hlen, $ttl, $foffset, '$options', $len, $tos, $id, $flags);");
	$result = $query->execute();
   

	$i = $i + 1;
	}
}

