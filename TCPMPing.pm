package Smokeping::probes::TCPMPing;

=head1 301 Moved Permanently

This is a Smokeping probe module. Please use the command 

C<smokeping -man Smokeping::probes::TCPMPing>

to view the documentation or the command

C<smokeping -makepod Smokeping::probes::TCPMPing>

to generate the POD document.

=cut

use strict;
use base qw(Smokeping::probes::basevars);
use IPC::Open3;
use Symbol;
use Carp;

sub pod_hash {
      return {
              name => <<DOC,
Smokeping::probes::TCPMPing - TCPMPing Probe for SmokePing
DOC
              description => <<DOC,
Integrates TCPMPing as a probe into smokeping. The variable B<binary> must
point to your copy of the TCPMPing program. If it is not installed on
your system yet, you can get it from https://github.com/liqi0816/TCPMping.

The (optional) port option lets you configure the port for the pings sent.
DOC
                authors => <<'DOC',
goodlq11 <goodlq11@gmail.com>
DOC
        }
}

sub new($$$)
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = $class->SUPER::new(@_);

    # no need for this if we run as a cgi
    unless ( $ENV{SERVER_SOFTWARE} ) {
        my $return = `$self->{properties}{binary} 127.0.0.1 -c 1 2>&1`;
        croak "ERROR: TCPMPing must have CAP_NET_RAW or it will not work\n"
            if $return =~m/Operation not permitted/;
    };

    return $self;
}

sub ProbeDesc($){
    my $self = shift;
    return "TCP Pings";
}

sub ping ($){
    my $self = shift;
    # do NOT call superclass ... the ping method MUST be overridden

    # increment the internal 'rounds' counter
    $self->increment_rounds_count;

    my %upd;
    my $inh = gensym;
    my $outh = gensym;
    my $errh = gensym;

    # pinging nothing is pointless
    return unless @{$self->targets};

    # options except for -c
    my @params = ();
    push @params, "-l" if defined $self->{properties}{loose};
    push @params, "-r", $self->{properties}{throttle} if defined $self->{properties}{throttle};
    push @params, "-s", $self->{properties}{source} if defined $self->{properties}{source};
    push @params, "-t", $self->{properties}{timeout} if defined $self->{properties}{timeout};

    # remotes
    my @remotes = ();
    foreach my $remote (@{$self->targets}) {
        if ($remote->{vars}{port}) {
            push @remotes, "$remote->{addr}:$remote->{vars}{port}";
        }
        else {
            push @remotes, $remote->{addr};
        }
    }

    # execute command
    my @cmd = ($self->{properties}{binary}, '-c', $self->pings, @params, @remotes);
    $self->do_debug("Executing @cmd");
    my $pid = open3($inh, $outh, $errh, @cmd);

    # collect output
    $self->{rtts}={};
    while (<$outh>){
        chomp;
        $self->do_debug("Got TCPMping output: '$_'");

        # parse output
        next unless /^\S+\s+:\s+[-\d\.]/; # filter out error messages from fping
        my @times = split /\s+/;
        my $remote = shift @times;
        next unless ':' eq shift @times; # drop the colon

        @times = map { sprintf "%.10e", $_ / 1000 } sort {$a <=> $b} grep /^\d/, @times;
        map { $self->{rtts}{$_} = [@times] } @{$self->{addrlookup}{$remote}} ;
    }

    waitpid $pid, 0;
    my $rc = $?;
    carp join(" ", @cmd) . " returned with exit code $rc. run with debug enabled to get more information" unless $rc == 0;
    
    close $inh;
    close $outh;
    close $errh;
}

sub probevars {
	my $class = shift;
	return $class->_makevars($class->SUPER::probevars, {
		_mandatory => [ 'binary' ],
		binary => { 
			_example => '/usr/bin/tcpmping',
			_sub => sub { 
				my ($val) = @_;
                return undef 
                    if $ENV{SERVER_SOFTWARE}; # don't check for fping presence in cgi mode
				return "ERROR: TCPMPing 'binary' does not point to an executable"
            		unless -f $val and -x _;

				my $return = `$val 127.0.0.1 -c 1 2>&1`;
				return "ERROR: TCPMPing must have CAP_NET_RAW or it will not work\n"
                    if $return =~m/Operation not permitted/;
                
				return undef;
			},
			_doc => "The location of your tcpmping binary.",
		},
		loose => {
			_re => '(true|false)',
			_example => 'false',
			_doc => "(default=false) Accept non-TCP response packets",
		},
        throttle => {
			_re => '(\d*\.)?\d+',
			_example => 0.3,
			_doc => "(default=0.3) Wait <throttle> seconds between sending each packet",
        },
		source => {
			_example => '0.0.0.0',
			_doc => "(default=0.0.0.0) Source IP address to use",
		},
        timeout => {
			_re => '(\d*\.)?\d+',
			_example => 1.5,
			_doc => "(default=1.5) Time to wait for a response, in seconds",
        },
	});
}

sub targetvars {
	my $class = shift;
	return $class->_makevars($class->SUPER::targetvars, {
		port => {
			_doc => "The TCP port the probe should measure.",
			_example => '80',
			_sub => sub {
				my $val = shift;

				return "ERROR: TCPMPing port must be between 0 and 65535"
					if $val and ( $val < 0 or $val > 65535 ); 

				return undef;
			},
		},
	});
}

1;
