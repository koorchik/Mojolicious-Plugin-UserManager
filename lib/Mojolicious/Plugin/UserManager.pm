package Mojolicious::Plugin::UserManager;
use Mojo::Base 'Mojolicious::Plugin';
has 'config';
has 'storage';

use v5.10;
use strict;
use warnings;

use Carp qw/croak/;
use Digest::MD5 qw/md5_hex/;
use Validate::Tiny qw/:all/;
use Email::Valid;
use Hash::Storage;
use File::Basename qw/dirname/;
use File::Spec::Functions qw/rel2abs catdir/;

our $VERSION = '0.01';

sub register {
    my ( $self, $app, $conf ) = @_;
    $self->config($conf);
    $self->_apply_conf_defaults($app);
    $self->storage($conf->{storage});
    
    
     # Append "templates" and "public" directories
    my $base = catdir(dirname(__FILE__), 'UserManager');
    push @{$app->renderer->paths}, catdir($base, 'templates');
    push @{$app->static->paths},   catdir($base, 'public');
    
    
    # Register "all_fields_schema" helper 
    $app->helper( all_fields_schema => sub { $conf->{fields} });

    # Register "schema_for_field" helper    
    $app->helper( schema_for_field => sub {
        my ($c, $field_name) = @_;
        my ($field_schema) = grep {$_->{name} eq $field_name} @{$conf->{fields}};
        return $field_schema;
    } );
    
    
    # Register "um_storage" helper    
    $app->helper( um_storage => sub {
        return $self->storage();
    } );
    
    
    # Register "um_config" helper    
    $app->helper( um_config => sub {
        return $self->config();
    } );
    
    # Register "schema_for_field" helper    
    $app->helper( html_for_field => sub {
        my ($c, $field_name) = @_;
        my ($field_schema) = grep {$_->{name} eq $field_name} @{$conf->{fields}};
        
        
        my $name  = $field_schema->{name};
        my $value = $c->flash($name) // '';
        my $type  = $field_schema->{type} || 'text';
        my $tag_options = $field_schema->{tag_options} || []; 
        
        my @options;
        given($type) {
            when ('select') {
                my $select_options = $tag_options->[0] || [];
                my @completed_options;
                foreach my $opt ( @$select_options ) {
                    if ( ref($opt) eq 'ARRAY' && @$opt == 2 && $opt->[1] eq $value ) {
                        push @completed_options, [@$opt, 'selected' => 'selected'];
                    } elsif (! ref($opt) && $opt eq $value ) {
                        push @completed_options, [$opt => $opt, 'selected' => 'selected'];
                    } else {
                        push @completed_options, $opt;
                    }
                }
                @options = ( \@completed_options );
            }
            default {
                @options = (value => $value, @$tag_options );
            }
        } 
         
        
        my $tag_helper = ( $field_schema->{type} || 'text') . '_field';
        return $c->$tag_helper( $name, @options );
    } );

    # Register "user_data" helper    
    $app->helper( user_data => sub {
        my $c = shift;
        my $user_id = $c->session('user_id');
        return unless $user_id;

        my $u_data;
        if ($c->stash('um.user_data')) {
            $u_data = $c->stash('um.user_data');
        } else {
            $u_data = $self->storage->get($user_id);
            delete $u_data->{password};
            $c->stash('um.user_data' => $u_data);
        }

        return @_ ? $u_data->{$_[0]} : $u_data; 
    } );
    
    my $namespace = 'Mojolicious::Plugin::UserManager::Controller';
    
    # Guest routes
    my $r = $app->routes;
    $r->get('/login') ->to( 'sessions#create_form', namespace  => $namespace )->name('auth_create_form');
    $r->post('/login')->to( 'sessions#create',      namespace  => $namespace )->name('auth_create');
    $r->any('/logout')->to( 'sessions#delete',      namespace  => $namespace )->name('auth_delete');

    $r->get('/registration') ->to( 'users#create_form', namespace => $namespace )->name('user_create_form');
    $r->post('/registration')->to( 'users#create',      namespace => $namespace )->name('user_create');
    
    $r->get('/activate/:activation_code')->to( 'users#activate', namespace => $namespace )->name('user_create');
    
    # Authenticated routes
    my $auth_r = $r->bridge('/users/:user_id')->to(
        controller => 'sessions', 
        action     => 'check',
        namespace  => 'Mojolicious::Plugin::UserManager::Controller'
    );
    
    $auth_r->get('/edit')->to( 'users#update_form', namespace => $namespace )->name('user_update_form');
    $auth_r->post('/')   ->to( 'users#update',      namespace => $namespace )->name('user_update');
    
    # Always return authenticated routes root from plugin 
    return $auth_r;
}

##################### Controller related methods ####################

########################### INTERNAL METHODS ##############################

sub _apply_conf_defaults {
    my ( $self, $app ) = @_;
    my $conf = $self->config();
    
    $conf->{captcha}          //= 0;
    $conf->{email_confirm}    //= 0;
    $conf->{admin_confirm}    //= '';
    $conf->{password_crypter} //= sub { md5_hex( $_[0] ) };
    $conf->{fields}           //= [];
    $conf->{site_url}         //= 'http://localhost:3000/';

    $conf->{storage} //= Hash::Storage->new(driver => [ 
        'OneFile' => {
            serializer => 'JSON',
            file       => 'user_manager.json'    
        }]
    );

    my %fields;
    foreach ( @{ $conf->{fields} } ) {
        croak "Field [$_->{name}] duplication" if $fields{ $_->{name} };
        $fields{ $_->{name} }++;
    }

    $self->_merge_field_schema( {
        name  => 'email',
        label => 'Email',
        check => [ is_required(), 
            sub { Email::Valid->address($_[0]) ? undef : 'Invalid email' }
        ]
    });
    
    $self->_merge_field_schema( {
        name  => 'password',
        label => 'Password',
        type  => 'password',
        check => is_required
    });
    
    $self->_merge_field_schema({
        name  => 'user_id',
        label => 'Login',
        check => [is_required, is_like(qr/^\w+$/)]
    });
    
}

sub _merge_field_schema {
    my ($self, $def_schema) = @_;
    my $conf = $self->config();
    my ( $field_schema ) = grep { $def_schema->{name} eq $_->{name} } @{ $conf->{fields} };

    if ( $field_schema ) {
        %$field_schema = (%$def_schema, %$field_schema);
    } else {
        unshift @{ $conf->{fields} }, $def_schema;
    }
    
}


1;
__END__

=head1 NAME

Mojolicious::Plugin::UserManager - User Manager for Mojolicious applications

=head1 SYNOPSIS

    # Mojolicious::Lite

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

    # Only authenticated users can this
    $secure_routes->get( '/messages', sub {
        my $self = shift;
        $self->render_text('My messages here!');
    });

=head1 DESCRIPTION

Mojolicious::Plugin::UserManager - User Manager for Mojolicious applications.

=head1 HELPERS

=head2 user_data

Use this helper in your controllers/templates to access user_data

    <h1>"Welcome, <%= user_data("user_id") %> </h1>
    
=head2 schema_for_field

You can access field schema by name in your controller/templates

	<%= schema_for_field('user_id')->{label} %>: <%= user_data("user_id") %>

=head2 all_fields_schema

Returns arrayref with fields schema (in the same format as "fields" config option)

      <% for my $field ( @{ all_fields_schema() } ) { %>
           <%= $field->{label} %>: <input type='text' name='<%= $field->{name} %>'" />
      <% } %>

=head1 ROUTES

Plugin add several routes. You can use them by names in your application.

=head2 auth_create_form

Show authentication(Login) form. For example, if you want redirect user to login screen - $self->redirect_to('auth_create_form');

=head2 auth_delete 

Delete user authentication(Logout)

=head2 user_create_form

Show user create form (Registration form)

=head2 user_update_form, user_id => $user_id

Show user update form (User settings form)

=head1 OPTIONS

=head2 storage

Hash::Storage object (optional)

=head2 captcha (default 0)

Enables CAPTCHA for registration. 

Requires Mojolicious::Plugin::Recaptcha (do not forget to config it)

=head2 email_confirm (default 0)

Send email to user for activation.

Requires Mojolicious::Plugin::Mail (do not forget to config it)

=head2 admin_confirm (default '')

Option contains admin email. After each user registration admin will receive a link for user activation.

Requires Mojolicious::Plugin::Mail (do not forget to config it)

=head2 password_crypter

Reference to a password encrypting subroutine
Default is md5 crypter:

    sub {
        my $pass = shift;
        my $crypted_pass = md5_hex($pass);
        return $crypted_pass; 
    }

=head2 site_url (default 'http://localhost:3000')

site_url is needed only for activation urls

=head2 fields

fields - array of fields schemas
    {
    	name  - Internal field name to store in DB
        check - Field validation callback. Takes field value and returns undef on success and error message on error. You can use Validate::Tiny helpers.
        label - Name that will be shown to user
    }

=head1 METHODS

L<Mojolicious::Plugin::UserManager> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 C<register>

  $plugin->register;

Register plugin in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicio.us>.

=cut
