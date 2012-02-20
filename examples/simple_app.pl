#!/usr/bin/env perl
use Mojolicious::Lite;
use lib '../lib';

my $secure_routes = plugin 'UserManager';
$secure_routes->get( '/messages', sub { shift->render_text('My messages here!') });

get '/' => sub { shift->redirect_to('auth_create_form') };

app->start;
      