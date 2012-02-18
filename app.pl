#!/usr/bin/env perl
use Mojolicious::Lite;
use lib qw{lib ../Hash-Storage/lib};
use Validate::Tiny qw/:all/;
use Hash::Storage;
use Hash::Storage::Serializator::JSON;
use Hash::Storage::Driver::OneFile;

my $st = Hash::Storage->new(
    driver =>  Hash::Storage::Driver::OneFile->new(
        serializator => Hash::Storage::Serializator::JSON->new(),
        file         => '/tmp/t.json'
    )
);

my $secure_routes = plugin 'UserManager', {
    storage          => $st,
    captcha          => 0,        # not yet implemented
    email_confirm    => 1,        # default 1
    admin_confirm    => 'ivo.welch@gmail.com', ## not yet implemented
    password_crypter => sub { $_[0] }, # default MD5 crypter with constant
    
    fields => [
        { name => 'user_id',      label => 'User ID' },
        { name => 'email',        label => 'Email' },
        { name => 'password',     label => 'Password' },
        { name => 'is_active',    label => 'Is Active',    check => sub {} },
        { name => 'first_name',   label => 'First Name',   check => sub {} },
        { name => 'last_name',    label => 'Last Name',    check => sub {} },
        { name => 'access_level', label => 'Access Level', check => sub {} },
    ]
};


$secure_routes->get( '/messages', sub {
    my $self = shift;
    $self->render_text('My messages here!');
});

get '/' => sub {
    my $self = shift;
    $self->redirect_to('auth_create_form');
};

app->start;
      