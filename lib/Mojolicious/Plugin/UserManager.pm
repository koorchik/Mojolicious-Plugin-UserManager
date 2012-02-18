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

our $VERSION = '0.01';

use DDP;
sub register {
    my ( $self, $app, $conf ) = @_;
    $self->config($conf);
    $self->storage($conf->{storage});
    $self->_apply_conf_defaults();
    
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

        my $udata;
        if ($c->stash('um.user_data')) {
           $udata = $c->stash('um.user_data');
        } else {
            $udata = $self->storage->get($user_id);
            $c->stash('um.user_data' => $udata);
        }

        return @_ ? $udata->{$_[0]} : $udata; 
    } );
    
    ### Add routes ###
    # Guest routes
    my $r = $app->routes;
    
    # Authenticated routes
    my $auth_r = $r->bridge('/users/:user_id')->to(cb => sub { $self->_check_user_session($_[0]) });
    
    # Athentications routes
    $r->get('/login')->to(cb => sub { 
         $self->_render_template( $_[0], 'auth_create_form' ); 
    } )->name('auth_create_form');
    
    $r->post('/login')->to(cb => sub {
        $self->_auth_create($_[0])
    })->name('auth_create');
    
    $r->any('/logout')->to(cb => sub {
        $self->_auth_delete($_[0])
    })->name('auth_delete');
    
    # Users routes
    $r->get('/registration')->to(cb=>sub {
        $self->_render_template( $_[0], 'user_create_form' );
    })->name('user_create_form');
    
    $r->post('/registration')->to(cb=>sub {
        $self->_user_create($_[0])
    })->name('user_create');
    
    $auth_r->get('/users/:user_id/edit')->to(cb => sub {
        $self->_user_update_form($_[0])
    })->name('user_update_form');
    
    $auth_r->post('/users/:user_id')->to(cb => sub {
        $self->_user_update($_[0])
    })->name('user_update');
    
    return $auth_r;
}

##################### Controller related methods ####################

sub _user_create {
    my ($self, $c) = @_;
    my $result    = $self->_validate_fields($c);
    my $conf      = $self->config;
    my $user_data = $result->data;
    
    if ( $result->success ) {
        $c->flash( notice => 'User was successfully created' );
        $user_data->{password} = $conf->{password_crypter}->($user_data->{password});
        $self->storage->set($user_data->{user_id}, $user_data);

        $c->redirect_to('auth_create_form');
    } else {
        my $errors_hash = $result->error;
        my ($field) = keys %$errors_hash;   
        p %$user_data;
        $c->flash( %$user_data, error => qq#Field "$field" $errors_hash->{$field}# );
        $c->redirect_to('user_create_form');
    }
}

sub _validate_fields {
    my ($self, $c) = @_;

    my $schema = $self->config->{fields};
    my @fields = map { $_->{name} } @$schema;
    my @checks = map { $_->{name}, $_->{check} } @$schema;
    my %input  = map { $_ , $c->param($_) } @fields;

    return Validate::Tiny->new( \%input, { fields => \@fields, checks => \@checks } );
}


sub _auth_create {
    my ($self, $c) = @_;
    my $user_id  = $c->param('user_id');
    my $pass     = $c->param('password');
    
    if ( $self->_check_user_password( $user_id, $pass ) ) {
        $c->session( 'user_id' => $user_id )->redirect_to('user_update_form')
    } else {
        $c->flash(error=>'Wrong user or password!')->redirect_to('auth_create_form');
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
        my $h = Mojo::Home->new;
        $h->parse($h->parse('./lib/')->rel_dir('Mojolicious/Plugin/UserManager/templates'));
    #   $H->parse($H->parse($H->mojo_lib_dir)->rel_dir('Mojolicious/Plugin/UserManage/templates'));
    
        $templates = {
            auth_create_form => $h->slurp_rel_file('auth_create_form.html.ep'),
            user_create_form => $h->slurp_rel_file('user_create_form.html.ep'),
            user_udpate_form => $h->slurp_rel_file('user_udpate_form.html.ep'),
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

    my $user_data = $self->storage->get($user_id);
    my $conf      = $self->config;

    return 0 unless $user_data && exists $user_data->{password};
    return 1 if ( $conf->{password_crypter}->($password) eq $user_data->{password} );
    return 0
}

########################### INTERNAL METHODS ##############################

sub _apply_conf_defaults {
    my ( $self ) = @_;
    my $conf = $self->config();
    
    $conf->{captcha}          //= 1;
    $conf->{email_confirm}    //= 0;
    $conf->{admin_confirm}    //= '';
    $conf->{password_crypter} //= sub { md5_hex( $_[0] ) };
    $conf->{fields}           //= [];

    $conf->{storage} //= Hash::Storage::OneFile->new(
        serializer => Hash::Storage::Serializer::JSON->new(),
        file       => 'test.json'
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
    
    $self->_merge_field_schema( {
        name  => 'is_active',
        label => 'Is Active',
        check => sub {},
        hidden => 1
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
