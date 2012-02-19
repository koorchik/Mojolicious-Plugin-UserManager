#!/usr/bin/env perl
use Mojolicious::Lite;
use lib qw{lib ../Hash-Storage/lib};


my $secure_routes = plugin 'UserManager';

$secure_routes->get( '/messages', sub {
    my $self = shift;
    $self->render_text('My messages here!');
});

get '/' => sub {
    my $self = shift;
    $self->redirect_to('auth_create_form');
};

app->start;
      