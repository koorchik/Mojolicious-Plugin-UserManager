#!/usr/bin/env perl
use Mojolicious::Lite;
use Validate::Tiny qw/:all/;
use Hash::Storage;
use lib '../lib';

plugin 'CSRFProtect';
plugin 'mail';
plugin  'recaptcha' => { 
    public_key  => '',
    private_key => '',
    lang        => 'en'
};

my $st = Hash::Storage->new( 
    driver => [ 'OneFile' => { 
        serializer => 'JSON', 
        file       => '/tmp/test.json'
    }]
);

my $secure_routes = plugin 'UserManager', {
    storage          => $st,                     # Own storage
    captcha          => 0,                       # Enables captcha for registration ( requires Mojolicious::Plugin::Recaptcha)
    email_confirm    => 1,                       # Send confirmation email (requires Mojolicious::Plugin::Mail)
    admin_confirm    => 'koorchik@gmail.com',    # Admin email (requires Mojolicious::Plugin::Mail)
    password_crypter => sub { $_[0] },           # Save Plain passwords (default MD5)
    site_url         => 'http://localhost:3000',
    
    fields => [
        { name => 'user_id',      label => 'User ID' },
        { name => 'email',        label => 'Email' },
        { name => 'password',     label => 'Password',    check => [ is_required, sub { length($_[0]) < 8 ? "Minimum password length - 8 " : undef; } ]},
        { name => 'first_name',   label => 'First Name',  check => [ is_required, is_like(qr/^\w+$/) ] },
        { name => 'last_name',    label => 'Last Name',   check => [ is_required, is_like(qr/^\w+$/) ] },
    ]
};


get '/' => sub {
    my $self = shift;
    $self->redirect_to('auth_create_form');
};

$secure_routes->get( '/messages', sub {
    my $self = shift;
    $self->render_text('My messages here!');
});

app->start;
      
