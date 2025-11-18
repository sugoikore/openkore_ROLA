#!/usr/bin/env perl
use strict;
use warnings;
use FindBin qw($RealBin);
use lib "$RealBin";
use lib "$RealBin/..";
use Time::HiRes qw(time sleep);
use IO::Socket::INET;
use IO::Select;
use Getopt::Long qw(GetOptions);
use List::Util qw(sum min max);

my %opts = (
	host                  => '127.0.0.1',
	port                  => 24390,
	unique_accounts       => 1,
	interval_between_req  => 1,
	requests_per_account  => 1,
	timeout               => 5,
	packet_hex            => '00010203040506070809',
	packet_file           => undef,
);

GetOptions(
	'host=s'                 => \$opts{host},
	'port=i'                 => \$opts{port},
	'accounts=i'             => \$opts{unique_accounts},
	'interval=f'             => \$opts{interval_between_req},
	'requests-per-account=i' => \$opts{requests_per_account},
	'timeout=f'              => \$opts{timeout},
	'packet-hex=s'           => \$opts{packet_hex},
	'packet-file=s'          => \$opts{packet_file},
) or usage();

$opts{unique_accounts}      = int($opts{unique_accounts});
$opts{requests_per_account} = int($opts{requests_per_account});
die "accounts must be >= 1\n"             if $opts{unique_accounts} < 1;
die "requests-per-account must be >= 1\n" if $opts{requests_per_account} < 1;
die "interval must be >= 0\n"             if $opts{interval_between_req} < 0;
die "timeout must be > 0\n"               if $opts{timeout} <= 0;

my $packet_payload = load_packet_payload(\%opts);
die "packet payload não pode ser vazio\n" unless length $packet_payload;

my $total_requests = $opts{unique_accounts} * $opts{requests_per_account};
my @response_times;
my $failures = 0;
my $request_id = 0;

print <<"INTRO";
=== Poseidon stress-test ===
Destino: $opts{host}:$opts{port}
Contas simuladas: $opts{unique_accounts}
Requests por conta: $opts{requests_per_account}
Intervalo entre requests: $opts{interval_between_req}s
Timeout por resposta: $opts{timeout}s
Falha = resposta demorando mais de 5 segundos
==============================================
INTRO

for my $round (1 .. $opts{requests_per_account}) {
	for my $account (1 .. $opts{unique_accounts}) {
		$request_id++;
		my $label = sprintf("acc%02d-r%02d", $account, $round);
		my $socket = IO::Socket::INET->new(
			PeerHost => $opts{host},
			PeerPort => $opts{port},
			Proto    => 'tcp',
			Timeout  => 1,
		);

		if (!$socket) {
			print_result($label, 'ERRO', undef, "falha ao conectar: $!");
			$failures++;
			sleep($opts{interval_between_req}) if $request_id < $total_requests;
			next;
		}

		my $request_packet = build_poseidon_query($packet_payload);

		my $bytes = eval { $socket->send($request_packet) };
		if (!$bytes) {
			print_result($label, 'ERRO', undef, "envio falhou: $@");
			$failures++;
			$socket->close();
			sleep($opts{interval_between_req}) if $request_id < $total_requests;
			next;
		}

		my $start_time = time;
		my $reply = read_poseidon_reply($socket, $opts{timeout});
		my $elapsed = time - $start_time;
		$socket->close();

		if (!$reply || $elapsed > $opts{timeout} || $reply->{id} ne 'Poseidon Reply') {
			$failures++;
			my $reason = !$reply                     ? 'sem resposta'
			           : $elapsed > $opts{timeout}   ? 'timeout'
			           : $reply->{id} ne 'Poseidon Reply' ? "reply inválido ($reply->{id})"
			           : 'erro desconhecido';
			print_result($label, 'FALHA', $elapsed, $reason);
		} else {
			push @response_times, $elapsed;
			print_result($label, 'OK', $elapsed);
		}

		sleep($opts{interval_between_req}) if $request_id < $total_requests;
	}
}

print "\n=== Resumo ===\n";
my $successes = scalar @response_times;
printf "Requests executados: %d\n", $total_requests;
printf "Sucessos: %d\n", $successes;
printf "Falhas (>5s): %d\n", $failures;

if ($successes) {
	my ($min_time, $max_time) = (min(@response_times), max(@response_times));
	my $avg_time = sum(@response_times) / $successes;
	printf "Tempo mínimo: %.3fs\n", $min_time;
	printf "Tempo médio : %.3fs\n", $avg_time;
	printf "Tempo máximo: %.3fs\n", $max_time;
} else {
	print "Nenhuma resposta com sucesso para calcular métricas.\n";
}

exit 0;

sub usage {
	print <<"USAGE";
Uso: $0 [opções]
  --host <ip>                Host onde o poseidon.pl está ouvindo (default 127.0.0.1)
  --port <porta>             Porta configurada para o QueryServer (default 24390)
  --accounts <n>             Quantidade de contas simuladas (default 1)
  --interval <segundos>      Tempo entre cada request (default 1s)
  --requests-per-account <n> Requests enviados por conta (default 1)
  --timeout <segundos>       Tempo máximo esperado por resposta (default 5s)
  --packet-hex <hex>         Pacote GameGuard em hex (default 00010203040506070809)
  --packet-file <arquivo>    Le o pacote direto de um arquivo binário
USAGE
	exit 1;
}

sub load_packet_payload {
	my ($opts) = @_;
	if ($opts->{packet_file}) {
		open my $fh, '<:raw', $opts->{packet_file}
			or die "não foi possível abrir $opts->{packet_file}: $!";
		local $/;
		my $data = <$fh>;
		close $fh;
		return $data // '';
	}

	my $hex = uc $opts->{packet_hex} // '';
	$hex =~ s/[^0-9A-F]//g;
	die "packet-hex deve conter apenas caracteres hexadecimais\n" if length($hex) % 2 == 1;
	return pack('H*', $hex);
}

sub build_poseidon_query {
	my ($packet) = @_;
	my $message_id = 'Poseidon Query';
	my $options    = 0; # mapa chave/valor
	my $map_body   = serialize_map_entry('packet', $packet);

	my $header = pack('N C C a*', 0, $options, length($message_id), $message_id);
	my $message = $header . $map_body;
	substr($message, 0, 4, pack('N', length($message)));
	return $message;
}

sub serialize_map_entry {
	my ($key, $value) = @_;
	my $value_data = defined $value ? $value : '';
	my $value_len  = length($value_data);
	die "valor maior que 16MB não suportado\n" if $value_len > 0xFFFFFF;
	my $len_bytes = pack('C3', ($value_len >> 16) & 0xFF, ($value_len >> 8) & 0xFF, $value_len & 0xFF);
	return pack('C a* C a3 a*', length($key), $key, 0, $len_bytes, $value_data);
}

sub read_poseidon_reply {
	my ($socket, $timeout) = @_;
	my $select = IO::Select->new($socket);
	my $buffer = '';
	my $message_len;
	my $deadline = time + $timeout;

	while (1) {
		my $remaining = $deadline - time;
		return undef if $remaining <= 0;

		my @ready = $select->can_read($remaining);
		return undef unless @ready;

		my $chunk = '';
		my $read = sysread($socket, $chunk, 4096);
		return undef if !defined $read || $read == 0;

		$buffer .= $chunk;
		if (!defined $message_len && length($buffer) >= 4) {
			$message_len = unpack('N', substr($buffer, 0, 4));
		}

		last if defined $message_len && length($buffer) >= $message_len;
	}

	return undef unless defined $message_len && length($buffer) >= $message_len;
	my $options = unpack('C', substr($buffer, 4, 1));
	my $id_len  = unpack('C', substr($buffer, 5, 1));
	my $id      = substr($buffer, 6, $id_len);
	my $payload = substr($buffer, 6 + $id_len, $message_len - (6 + $id_len));

	return {
		options => $options,
		id      => $id,
		payload => $payload,
		raw     => substr($buffer, 0, $message_len),
	};
}

sub print_result {
	my ($label, $status, $elapsed, $extra) = @_;
	my $elapsed_text = defined $elapsed ? sprintf('%.3fs', $elapsed) : '--';
	$extra = $extra ? " ($extra)" : '';
	print sprintf("[%s] %s - %s%s\n", scalar(localtime), $label, "$status $elapsed_text", $extra);
}
