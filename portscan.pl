use strict;
use warnings;
use Math::Complex;

sub usage {
	print "Usage: portscan.pl [Target Address(es)] [Target Port(s)] ";
	exit(1);
}


sub parseInputAsRange {	
	my @addresses = split(/-/, shift);
	
	my @lower = split(/\./, $addresses[0]);
	my @upper = split(/\./, $addresses[1]);
	
	return (@lower, @upper);
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
	
	return (@lower, @upper);
}


sub parseInputAsAddress {
	my @components = split(/\./, shift);
	return (@components, @components);
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
	
	print join(", ", @target);
}
else {
	usage();
}


