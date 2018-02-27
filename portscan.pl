use strict;
use warnings;

sub usage {
	print "Usage: portscan.pl [Target Address(es)] [Target Port(s)] ";
	exit(1);
}


sub parseInputAsRange {	
	# Split across the range and designate them as the lower and upper bound.
	my @addresses = split(/-/, shift);
	
	my @lower = split(/\./, $addresses[0]);
	my @upper = split(/\./, $addresses[1]);
	
	return ([@lower], [@upper]);
}


sub parseInputAsCIDR {
	# Split apart the address and mask
	my @data = split(/\//, shift);
	
	# Split the address into components
	my @lower = split(/\./, $data[0]);
	my $mask = $data[1];

	# If this isn't a good mask just bail
	if ( !($mask % 8 == 0) || ($mask < 0) || ($mask > 32) ) {
		return ();
	}
	
	# Copy the lower bound and replace components with 255 as necessary to define the upper bound
	my @upper = @lower;
	my $index = (32 - $mask)/8 ;
	while ($index > 0) {
		$upper[-($index)] = 255;
		$index -= 1;
	}
	
	return ([@lower], [@upper]);
}


sub parseInputAsAddress {
	# This is the easy one.
	my @components = split(/\./, shift);
	return ([@components], [@components]);
}


sub parsePorts {
	# Split on commas
	my @ports = split(/,/, shift);

	my @compiledPorts = ();
	
	foreach my $port (@ports) {
		#If "a" port contains a dash split it and turn it into a range
		if ($port =~ /-/) {
			my @range = split(/-/, $port);
			
			for my $i ($range[0] .. $range[1]) {
				push @compiledPorts, $i;
			}
		}
		else {
			push @compiledPorts, $port;
		}
	}
	
	return @compiledPorts;
}


sub scanTargets {
	# perl auto-expands arrays unless you pass them as a reference (lol)
	my $ports_ref = shift;
	my @ports = @$ports_ref;
	
	my $addr_ref = shift;
	my @addresses = @$addr_ref;
	
	my $lower_bound_ref = $addresses[0];
	my $upper_bound_ref = $addresses[1];
	my @lower_bound = @$lower_bound_ref;
	my @upper_bound = @$upper_bound_ref;
	
	# Loop through the entire address ranges
	for my $a ($lower_bound[0] .. $upper_bound[0]) {
		for my $b ($lower_bound[1] .. $upper_bound[1]) {
			for my $c ($lower_bound[2] .. $upper_bound[2]) {
				for my $d ($lower_bound[3] .. $upper_bound[3]) {
					# Create this IP and scan it
					my $target = "$a.$b.$c.$d";
					scanPorts($target, \@ports);
				}
			}
		}
	}
}


sub scanPorts {
	my $target = shift;
	
	my $ports_ref = shift;
	my @ports = @$ports_ref;
	
	for my $port (@ports) {
		# Echos from the /dev/tcp "device" for each port. If it errors, the port is closed. Has to be piped through
		# bash since /dev/tcp/ is a feature of bash.
		my $result = system("echo \"(echo </dev/tcp/$target/$port)\" | /bin/bash >/dev/null 2>/dev/null") >> 8;
		if($result == 0) {
			print("$port is open.\n");
		}
	}
}



# Entry Point
# ###################################
if (scalar(@ARGV) == 2) {
	my  @target = ();
	my  @ports = ();
	
	# Check for *.*.*.* - *.*.*.* format
	if ($ARGV[0] =~ (/^([0-9]{1,3}.){3}[0-9]{1,3}-([0-9]{1,3}.){3}[0-9]{1,3}$/)) {
		@target = parseInputAsRange($ARGV[0]);
	}
	# Check for *.*.*.*/** format
	elsif ($ARGV[0] =~ (/^([0-9]{1,3}.){3}[0-9]{1,3}\/[0-9]{1,2}$/)) {
		@target = parseInputAsCIDR($ARGV[0]);
	}
	# Check for *.*.*.* format
	elsif ($ARGV[0] =~ (/^([0-9]{1,3}.){3}[0-9]{1,3}$/)) {
		@target = parseInputAsAddress($ARGV[0]);
	}
	else { usage(); }
	
	# Make sure this is a valid list of ports and get all of them
	if ($ARGV[1] =~ (/^( *[0-9]{1,4}(-[0-9]{1,4})?,)*( *[0-9]{1,4}(-[0-9]{1,4})?)$/)) {
		@ports = parsePorts($ARGV[1]);
	}
	else { usage(); }
	
	# If whatever target parsing method we used returned an empty array something went wrong.
	if (!@target) { usage(); }

	# Scan these ports and targets
	scanTargets(\@ports, \@target);
}
else {
	usage();
}


