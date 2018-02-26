use strict;
use warnings;

sub usage {
	print "Usage: portscan.pl [Target Address(es)] [Target Port(s)] ";
	exit(1);
}


sub parseInputAsRange {	
	my @addresses = split(/-/, shift);
	
	my @lower = split(/\./, $addresses[0]);
	my @upper = split(/\./, $addresses[1]);
	
	return ([@lower], [@upper]);
}


sub parseInputAsCIDR {
	my @data = split(/\//, shift);
	
	my @lower = split(/\./, $data[0]);
	my $mask = $data[1];
	if ( !($mask % 8 == 0) || ($mask < 0) || ($mask > 32) ) {
		return ();
	}
	
	my @upper = @lower;
	my $index = (32 - $mask)/8 ;
	while ($index > 0) {
		$upper[-($index)] = 255;
		$index -= 1;
	}
	
	return ([@lower], [@upper]);
}


sub parseInputAsAddress {
	my @components = split(/\./, shift);
	return ([@components], [@components]);
}


sub scanTargets {
	my $addr_ref = shift;
	my @addresses = @$addr_ref;
	
	my $lower_bound_ref = $addresses[0];
	my $upper_bound_ref = $addresses[1];
	my @lower_bound = @$lower_bound_ref;
	my @upper_bound = @$upper_bound_ref;
	
	for my $a ($lower_bound[0] .. $upper_bound[0]) {
		for my $b ($lower_bound[1] .. $upper_bound[1]) {
			for my $c ($lower_bound[2] .. $upper_bound[2]) {
				for my $d ($lower_bound[3] .. $upper_bound[3]) {
					print "$a.$b.$c.$d\n";
				}
			}
		}
	}
}


if (scalar(@ARGV) == 2) {
	my  @target = ();
	
	if ($ARGV[0] =~ (/^([0-9]{1,3}.){3}[0-9]{1,3}-([0-9]{1,3}.){3}[0-9]{1,3}$/)) {
		@target = parseInputAsRange($ARGV[0]);
	}
	elsif ($ARGV[0] =~ (/^([0-9]{1,3}.){3}[0-9]{1,3}\/[0-9]{1,2}$/)) {
		@target = parseInputAsCIDR($ARGV[0]);
	}
	elsif ($ARGV[0] =~ (/^([0-9]{1,3}.){3}[0-9]{1,3}$/)) {
		@target = parseInputAsAddress($ARGV[0]);
	}
	else { usage(); }
	
	
	if (!@target) { usage(); }

	scanTargets(\@target);
}

else {
	usage();
}


