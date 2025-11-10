###########################################################
# Poseidon server - OpenKore communication channel
#
# This program is free software; you can redistribute it and/or 
# modify it under the terms of the GNU General Public License 
# as published by the Free Software Foundation; either version 2 
# of the License, or (at your option) any later version.
#
# Copyright (c) 2005-2006 OpenKore Development Team
###########################################################
package Poseidon::QueryServer;

use strict;
use Scalar::Util;
use Base::Server;
use Bus::MessageParser;
use Bus::Messages qw(serialize);
use Poseidon::RagnarokServer;
use Poseidon::Config;
use base qw(Base::Server);
use Plugins;
use Misc;
use Utils qw (getFormattedDateShort);

my $CLASS = "Poseidon::QueryServer";


# struct Request {
#     Bytes packet;
#     Base::Server::Client client;
# }

##
# Poseidon::QueryServer->new(String port, String host, Poseidon::RagnarokServer ROServer)
# port: The port to start this server on.
# host: The host to bind this server to.
# ROServer: The RagnarokServer object to send GameGuard queries to.
# Require: defined($port) && defined($ROServer)
#
# Create a new Poseidon::QueryServer object.
sub new {
	my ($class, $port, $host, $roServer) = @_;
	my $self = $class->SUPER::new($port, $host);

	# Invariant: server isa 'Poseidon::RagnarokServer'
	$self->{"$CLASS server"} = $roServer;

	# Array<Request> queue
	#
	# The GameGuard query packets queue.
	#
	# Invariant: defined(queue)
	$self->{"$CLASS queue"} = [];

	return $self;
}

##
# void $QueryServer->process(Base::Server::Client client, String ID, Hash* args)
#
# Push an OpenKore GameGuard query to the queue.
sub process {
	my ($self, $client, $ID, $args) = @_;

	if ($ID ne "Poseidon Query") {
		$client->close();
		return;
	}
	
	if ($args->{username}) {
		print "[PoseidonServer]-> Received query from bot client (" . $args->{username} . ")\n";
	} else {
		print "[PoseidonServer]-> Received query from bot client " . $client->getIndex() . "\n";
	}

	my %request = (
		packet => $args->{packet},
		client => $client,
		username => $args->{username},
		qstate => 'received',
		req_time => time
	);

	# perform client authentication here
	Plugins::callHook('Poseidon/server_authenticate', {
		args_hash => $args,
	});
	
	if (!$args->{username}) {
		print "Username is needed \n";
		return $args->{auth_failed};
	}

	# note: the authentication plugin must set auth_failed to true if it doesn't
	# want the Poseidon server to respond to the query
	return if ($args->{auth_failed});

	Scalar::Util::weaken($request{client});
	push @{$self->{"$CLASS queue"}}, \%request;
#	my $packet = substr($ipcArgs->{packet}, 0, 18);
}


##################################################


sub onClientNew {
	my ($self, $client, $index) = @_;
	$client->{"$CLASS parser"} = new Bus::MessageParser();
	print "[PoseidonServer]-> New Bot Client Connected : " . $client->getIndex() . "\n";
}

sub onClientExit {
	my ($self, $client, $index) = @_;
	print "[PoseidonServer]-> Bot Client Disconnected : " . $client->getIndex() . "\n";
}

sub onClientData
{
	my ($self, $client, $msg) = @_;
	my ($ID, $args);

	my $parser = $client->{"$CLASS parser"};
	
	$parser->add($msg);
	
	while ($args = $parser->readNext(\$ID))
	{
		$self->process($client, $ID, $args);
	}
}

sub iterate {
	my ($self) = @_;
	my ($server, $queue);

	$self->SUPER::iterate();
	$server = $self->{"$CLASS server"};
	$queue = $self->{"$CLASS queue"};

	# Check for responses from RO clients
	my $clients = $server->clients();
	for (my $i = 0; $i < @{$clients}; $i++) {
		if ($clients->[$i] && $clients->[$i]{query_state} eq 'replied') {
			# Find the matching request in queue
			for (my $j = 0; $j < @{$queue}; $j++) {
				if ($queue->[$j]{username} && 
				    $clients->[$i]{boundUsername} && 
				    $queue->[$j]{username} eq $clients->[$i]{boundUsername} &&
				    $queue->[$j]{qstate} eq 'sent') {
					
					# Send response to the bot client
					if ($queue->[$j]{client}) {
						my $response = $server->readClientResponse($clients->[$i]);
						next unless defined $response;

						my ($data, %args);
						$args{packet} = $response;
						visualDump($args{packet}) if ($config{debug});
						$data = serialize("Poseidon Reply", \%args);
						$queue->[$j]{client}->send($data);
						$queue->[$j]{client}->close();
						print "[PoseidonServer]-> Sent result to bot client (" . $queue->[$j]{username} . ")\n";
					}
					
					# Clean up
					splice(@{$queue}, $j, 1);
					last;
				}
			}
		}
	}

	# Send pending queries to RO clients
	for (my $i = 0; $i < @{$queue}; $i++) {
		if ($queue->[$i]{qstate} eq 'received') {
			print "[PoseidonServer]-> Querying Ragnarok Online client for (" . $queue->[$i]{username} . ") [" . getFormattedDateShort(time, 1) . "]...\n";
			my $client_index = $server->query({
				packet => $queue->[$i]{packet},
				username => $queue->[$i]{username}
			});
			
			if ($client_index >= 0) {
				$queue->[$i]{qstate} = 'sent';
				$queue->[$i]{client_index} = $client_index;
			}
		}
	}
	
	# Clean up timed out requests
	for (my $i = @{$queue} - 1; $i >= 0; $i--) {
		if ($queue->[$i]{req_time} && (time > ($queue->[$i]{req_time} + 60))) {
			print "[PoseidonServer]-> Request timeout for (" . $queue->[$i]{username} . ")\n";
			splice(@{$queue}, $i, 1);
		}
	}
}

1;
