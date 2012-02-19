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
use File::Spec::Functions qw/rel2abs/;

our $VERSION = '0.01';

sub register {
    my ( $self, $app, $conf ) = @_;
    $self->config($conf);
    $self->_apply_conf_defaults($app);
    $self->storage($conf->{storage});
    
    # Register "all_fields_schema" helper 
    $app->helper( all_fields_schema => sub { $conf->{fields} });

    # Register "schema_for_field" helper    
    $app->helper( schema_for_field => sub {
        my ($c, $field_name) = @_;
        my ($field_schema) = grep {$_->{name} eq $field_name} @{$conf->{fields}};
        return $field_schema;
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
    
    # Guest routes
    my $r = $app->routes;
    $r->get('/login')->to(cb => sub { 
         $self->_render_template( $_[0], 'auth_create_form' ); 
    } )->name('auth_create_form');
    
    $r->post('/login')->to(cb => sub {
        $self->_auth_create($_[0])
    })->name('auth_create');
    
    $r->any('/logout')->to(cb => sub {
        $self->_auth_delete($_[0])
    })->name('auth_delete');

    $r->get('/registration')->to(cb=>sub {
        $self->_render_template( $_[0], 'user_create_form' );
    })->name('user_create_form');
    
    $r->post('/registration')->to(cb=>sub {
        $self->_user_create($_[0])
    })->name('user_create');
    
    $r->get('/activate/:activation_code')->to(cb=>sub {
        $self->_user_activate($_[0])
    })->name('user_create');
    
    # Authenticated routes
    my $auth_r = $r->bridge('/users/:user_id')->to(cb => sub { $self->_check_user_session($_[0]) });
    
    $auth_r->get('/edit')->to(cb => sub {
        $self->_render_template( $_[0], 'user_update_form' );
    })->name('user_update_form');
    
    $auth_r->post('/')->to(cb => sub {
        $self->_user_update($_[0])
    })->name('user_update');
    
    # Always return authenticated routes root from plugin 
    return $auth_r;
}

##################### Controller related methods ####################
sub _user_create {
    my ($self, $c) = @_;
    my $result = $self->_validate_fields($c);
    my $conf   = $self->config;
    my $u_data = $result->data;
    
    
    if ( $result->success ) {
        # Check that user does not exists
        if ( $self->storage->get($u_data->{user_id}) ) {
            $c->flash(%$u_data, error => 'Such user already exists' );
            $c->redirect_to('user_create_form');    
            return;
        }
        
        # Crypt password
        $u_data->{password} = $conf->{password_crypter}->($u_data->{password});
        
        # Send confirmation emails
        if ( $conf->{email_confirm} || $conf->{admin_confirm} ) {
            my $activation_code = md5_hex( time + rand(time) );
            my $activation_url  = "$conf->{site_url}/activate/$activation_code"; 
            $u_data->{_is_active} = 0;
            $u_data->{_activation_code} = $activation_code;

            # Send email to admin 
            if ( $conf->{admin_confirm} ) {
                say "To activate [$u_data->{user_id}] go to $activation_url";
                $c->mail( 
                    to      => $conf->{admin_confirm},
                    subject => "User [ $u_data->{user_id} ] activation",
                    data    => "To activate [$u_data->{user_id}] go to $activation_url",
                );
            }
            
            # Send email to user
            if ( $conf->{email_confirm} && $u_data->{email} ) {
                say "To activate [$u_data->{user_id}] go to $activation_url";
                $c->mail( 
                    to      => $u_data->{email},
                    subject => "User [ $u_data->{user_id} ] activation",
                    data    => "To activate [$u_data->{user_id}] go to $activation_url",
                );
            }
        } else {
            $u_data->{_is_active} = 1;
        }
        
        # Save user
        $self->storage->set($u_data->{user_id}, $u_data);
        
        # Redirect to login form
        $c->flash( notice => 'Registration completed' );
        $c->redirect_to('auth_create_form');
    } else {
        my $errors_hash = $result->error;
        my ($field) = keys %$errors_hash;   
        $c->flash( %$u_data, error => qq#Field "$field" $errors_hash->{$field}# );
        $c->redirect_to('user_create_form');
    }
}

sub _user_update {
    my ($self, $c) = @_;
    my $result = $self->_validate_fields($c, [qw/password user_id/]);
    my $conf   = $self->config;
    my $u_data = $result->data;
    
    if ( $result->success ) {
        # Crypt password
        my $new_pass = $c->param('password'); 
        if ( $new_pass ) {
            $u_data->{password} = $conf->{password_crypter}->($new_pass);
        } else {
            delete $u_data->{password};
        }
    
        # Save user
        $self->storage->set( $c->stash('user_id'), $u_data );
        
        $c->flash( notice => 'Saved' );
    } else {
        my $errors_hash = $result->error;
        my ($field) = keys %$errors_hash;   
        $c->flash( %$u_data, error => qq#Field "$field" $errors_hash->{$field}# );
    }
    $c->redirect_to('user_update_form');
}

sub _user_activate {
    my ($self, $c) = @_;
    my $act_code = $c->param('activation_code');
    return $c->render_text("Wrong activation code") unless $act_code =~ /^[0-9a-f]{32}$/i;
    
    my $users = $self->storage->list();
    my ($u_data) = grep { $_->{_activation_code} && $_->{_activation_code} eq $act_code } @$users;
    
    if ( $u_data ) {
        $self->storage->set($u_data->{user_id}, {_is_active => 1});
        $c->render_text("User [$u_data->{user_id} activated]");
    } else {
        $c->render_text("Wrong activation code");
    }
}


sub _validate_fields {
    my ($self, $c, $skip) = @_;

    my $schema = $self->config->{fields};
    my @fields = map { $_->{name} ~~ $skip ? () : $_->{name} } @$schema;
    my @checks = map { $_->{name}, $_->{check} } @$schema;
    my %input  = map { $_ , $c->param($_) } @fields;

    return Validate::Tiny->new( \%input, { fields => \@fields, checks => \@checks } );
}


sub _auth_create {
    my ($self, $c) = @_;
    my $user_id  = $c->param('user_id');
    my $pass     = $c->param('password');
    
    if ( $self->_check_user_password( $user_id, $pass ) ) {
        # Check that user is activated
        my $u_data = $self->storage->get($user_id);
        unless ( $u_data->{_is_active} ) {
            $c->flash( error => 'User was not activated!' );
            $c->redirect_to('auth_create_form');
            return;
        }
        
        $c->session( 'user_id' => $user_id );
        $c->redirect_to('user_update_form', user_id => $user_id);
    } else {
        $c->flash(error=>'Wrong user or password!');
        $c->redirect_to('auth_create_form');
    }
}

sub _auth_delete {
    my ($self, $c) = @_;
    $c->session( user_id => '' )->redirect_to('auth_create_form');
}

sub _check_user_session {
    my ($self, $c) = @_;
    $c->stash( 'user_id' => '' );
    my $user_id = $c->session('user_id');

    if ( $user_id ) {
        $c->stash( 'user_id' => $user_id );
        return 1;
    } else {
        $c->redirect_to('auth_create_form');
        return 0;
    }
}

sub _render_template {
    my $self     = shift;
    my $c        = shift;
    my $template = shift;

    # Read templates  in memory
    state $templates;
    unless ($templates) {
        my $plugin_root = rel2abs(dirname(__FILE__).'/../..');
        my $h = Mojo::Home->new;
        $h->parse($h->parse($plugin_root)->rel_dir('Mojolicious/Plugin/UserManager/templates'));

        $templates = {
            auth_create_form => $h->slurp_rel_file('auth_create_form.html.ep'),
            user_create_form => $h->slurp_rel_file('user_create_form.html.ep'),
            user_update_form => $h->slurp_rel_file('user_update_form.html.ep'),
        };
    }
    
    # Render template
    $c->render(
        inline => $templates->{$template},
        @_
    );
}

sub _check_user_password {
    my ( $self, $user_id, $password ) = @_;
    return 0 unless $user_id && $password; 

    my $user_data = $self->storage->get($user_id);
    my $conf      = $self->config;

    return 0 unless $user_data && exists $user_data->{password};
    return 1 if ( $conf->{password_crypter}->($password) eq $user_data->{password} );
    return 0
}

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

    $self->_merge_field_schema({
        name  => 'user_id',
        label => 'User ID',
        check => [is_required, is_like(qr/^\w+$/)]
    });
    
    $self->_merge_field_schema( {
        name  => 'email',
        label => 'Email',
        check => [ is_required, 
            sub { Email::Valid->address($_[0]) ? undef : 'Invalid email' }
        ]
    });
    
    $self->_merge_field_schema( {
        name  => 'password',
        label => 'Password',
        check => is_required
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

Mojolicious::Plugin::UserManager - Mojolicious Plugin

=head1 SYNOPSIS

  # Mojolicious
  $self->plugin('UserManager');

  # Mojolicious::Lite
  plugin 'UserManager';

=head1 DESCRIPTION

L<Mojolicious::Plugin::UserManager> is a L<Mojolicious> plugin.

=head1 METHODS

L<Mojolicious::Plugin::UserManager> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 C<register>

  $plugin->register;

Register plugin in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicio.us>.

=cut
