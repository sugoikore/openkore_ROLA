package LatamChecksum;

use strict;
use Plugins;
use Globals;
use Misc;
use AI;
use utf8;
use Network::Send ();
use Log           qw(message warning error debug);
use IO::Socket::INET;
use Time::HiRes qw(usleep);

my $counter = 0;
my $enabled = 0;
my $current_seed = 0;  # Para armazenar a seed atual (64 bits)

# TCP checksum server configuration
my $TIMEOUT = 1000;

# CSV logging configuration
my $csv_logging_enabled = 0;  # Disabled by default
my $csv_file_handle;
my $csv_filename = "checksum_data.csv";

Plugins::register( "LatamChecksum", "Latam checksum for xKore 0", \&unload );

my $hooks = Plugins::addHooks(
	['start3',                \&checkServer, undef],
);
my $base_hooks;

sub checkServer {
	my $master = $masterServers{ $config{master} };
	if ( grep { $master->{serverType} eq $_ } qw(ROla) ) {
		$base_hooks = Plugins::addHooks(
			[ 'serverDisconnect/fail',    \&serverDisconnect, undef ],
			[ 'serverDisconnect/success', \&serverDisconnect, undef ],
			[ 'Network::serverSend/pre',  \&serverSendPre,    undef ],
			[ 'Network::clientSend',      \&clientSend,       undef ]  # Hook para xKore 3
		);
		
		# Initialize CSV logging if enabled
		initCSVLogging();
	}
}

sub unload {
	Plugins::delHooks( $base_hooks );
	Plugins::delHooks( $hooks ) if ( $hooks );
	closeCSVLogging();
}

sub initCSVLogging {
	# Check if CSV logging is enabled in config
	if ( $config{checksum_csv_log} && $config{checksum_csv_log} == 1 ) {
		$csv_logging_enabled = 1;
		
		# Open CSV file for writing (append mode)
		if ( open($csv_file_handle, '>>', $csv_filename) ) {
			# Write header if file is empty
			if ( -z $csv_filename ) {
				print $csv_file_handle "timestamp,counter,seed_high,seed_low,packet_hex,packet_length,checksum\n";
			}
			warning "LatamChecksum: CSV logging enabled - writing to $csv_filename\n";
		} else {
			error "LatamChecksum: Failed to open CSV file $csv_filename: $!\n";
			$csv_logging_enabled = 0;
		}
	}
}

sub closeCSVLogging {
	if ( $csv_file_handle ) {
		close($csv_file_handle);
		warning "LatamChecksum: CSV logging closed\n";
	}
}

sub logToCSV {
	my ( $counter, $seed_high, $seed_low, $packet_data, $checksum ) = @_;
	
	return unless $csv_logging_enabled && $csv_file_handle;
	
	my $timestamp = time();
	my $packet_hex = as_hex($packet_data);
	my $packet_length = length($packet_data);
	
	# Write CSV line: timestamp,counter,seed_high,seed_low,packet_hex,packet_length,checksum
	print $csv_file_handle "$timestamp,$counter,$seed_high,$seed_low,$packet_hex,$packet_length,$checksum\n";
	
	# Flush to ensure data is written
	$csv_file_handle->flush();
}

sub as_hex {
    my ($s) = @_;
    return join ' ', map { sprintf '%02X', $_ } unpack('C*', $s // '');
}

sub calc_checksum {
	my ( $data ) = @_;
	
	# Create socket connection
	my $socket = IO::Socket::INET->new(
		PeerHost => $config{ip_socket} || '172.65.175.33',
		PeerPort => $config{port_socket} || 2349,
		Proto    => 'tcp',
		Timeout  => $TIMEOUT
	);
	
	unless ($socket) {
		error "LatamChecksum: Failed to connect to checksum server at " . 
			  ($config{ip_socket} || '172.65.175.33') . ":" . 
			  ($config{port_socket} || 2349) . "!\n";
		return 0; # Return 0 as fallback checksum
	}

	# Send data to server with current counter value
	my $seed_high = ($current_seed >> 32) & 0xFFFFFFFF;
	my $seed_low  = $current_seed & 0xFFFFFFFF;

	my $packet = $data . pack("NNN", $counter, $seed_high, $seed_low);
	
	unless (print $socket $packet) {
		error "LatamChecksum: Failed to send data to checksum server - $!\n";
		$socket->close();
		return 0;
	}
	
	# Read checksum response - agora estrutura completa
	my $response;
	my $bytes_read = sysread($socket, $response, 17); # 1 + 8 + 4 + 4 = 17 bytes
	$socket->close();
	unless (defined $bytes_read && $bytes_read == 17) {
		error "LatamChecksum: Failed to read complete response from server\n";
		return 0;
	}
	# Desempacota: 1 byte checksum + seed_high + seed_low + counter
	my ($checksum, $resp_seed_high, $resp_seed_low, $server_counter) = unpack("C N N N", $response);

	$current_seed = ($resp_seed_high << 32) | $resp_seed_low;
	my $data_hex = as_hex($data);
	warning "LatamChecksum: Counter=$counter, Checksum=$checksum, Seed=$current_seed, Data=$data_hex (len=" . length($data) . ")\n";
	
	# Log to CSV if enabled
	logToCSV($counter, $resp_seed_high, $resp_seed_low, $data, $checksum);
	
	return $checksum;
}

sub serverDisconnect {
	warning "Checksum disabled on server disconnect.\n";
	$enabled = 0;
	$counter = 0;
	$current_seed = 0;  # Reset da seed
}

# Hook para pacotes enviados ao servidor (xKore normal)
sub serverSendPre {
	my ( $self, $args ) = @_;
	my $msg       = $args->{msg};
	my $messageID = uc( unpack( "H2", substr( $$msg, 1, 1 ) ) ) . uc( unpack( "H2", substr( $$msg, 0, 1 ) ) );

	# Skip se estiver usando xKore 3
	if ( ref($::net) eq 'Network::XKore2' || ref($::net) eq 'Network::XKore3' ) {
		return;
	}

	processPacket($msg, $messageID);
}

# Hook para pacotes enviados pelo cliente (xKore 3)
sub clientSend {
	my ( $self, $args ) = @_;
	my $msg = $args->{msg};
	my $messageID = uc( unpack( "H2", substr( $$msg, 1, 1 ) ) ) . uc( unpack( "H2", substr( $$msg, 0, 1 ) ) );

	# Apenas processa se estiver usando xKore 3
	if ( ref($::net) eq 'Network::XKore3' ) {
		processPacket($msg, $messageID);
	}
}

sub processPacket {
	my ($msg, $messageID) = @_;

	if ( $counter == 0 ) {
		# Primeiro pacote após login no mapa ou primeiro pacote específico
		if ( $messageID eq '0B1C' ) {
			warning "Checksum enabled on first packet (0B1C).\n";
			$enabled = 1;
		}

		if ( $messageID eq $messageSender->{packet_lut}{map_login} ) {
			warning "Checksum enabled on map login.\n";
			$enabled = 1;
			$messageSender->sendPing() if $messageSender;
		}
	}

	# Adiciona checksum apenas se estiver conectado e enabled
	if ( $::net && $::net->getState() >= 4 && $enabled ) {
		my $checksum = calc_checksum( $$msg );
		$$msg .= pack( "C", $checksum );
		debug "LatamChecksum: Added checksum $checksum to packet $messageID\n" if $config{debug_checksum};
	}

    $counter = ($counter + 1) & 0xFFF;
}



1;
