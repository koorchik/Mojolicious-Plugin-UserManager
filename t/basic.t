use Mojo::Base -strict;

use Test::More tests => 3;

use Mojolicious::Lite;
use Test::Mojo;

my $secure_routes = plugin 'UserManager', {
    collection       => Collection::Storable->new(),
    storage          => Hash::Storage::OneFile->new( 
                            serializer => Hash::Storage::Serializer::JSON->new(),
                            file       => 'test.json'
                        ),
    captcha          => 0,        # not yet implemented
    email_confirm    => 1,        # default 1
    admin_confirm    => 'ivo.welch@gmail.com', ## not yet implemented
    password_crypter => sub { }   # default MD5 crypter with constant
    
    fields => [
        { field => '_uid',         label => 'User ID',      validator => sub {} },
        { field => '_email',       label => 'Email',        validator => sub {} },
        { field => '_password',    label => 'Password',     validator => sub {} },
        { field => '_is_active',   label => 'Is Active',    validator => sub {} },
        { field => 'first_name',   label => 'First Name',   validator => sub {} },
        { field => 'last_name',    label => 'Last Name',    validator => sub {} },
        { field => 'access_level', label => 'Access Level', validator => sub {} },
    ]
};


$secure_routes->get( '/messages', sub {
    my $self = shift;
    $self->render_text('My messages here!');
});

$secure_routes->get('/photos')->to('photos#list')->name('photos_list');



my $t = Test::Mojo->new;
$t->get_ok('/')->status_is(200)->content_is('Hello Mojo!');


