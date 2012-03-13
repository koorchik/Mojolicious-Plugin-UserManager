package Mojolicious::Plugin::UserManager::Controller::Sessions;
use Mojo::Base 'Mojolicious::Controller';

use v5.10;
use strict;
use warnings;

use File::Basename qw/dirname/;
use File::Spec::Functions qw/rel2abs/;

sub create_form {
    my ( $self, $template ) = @_;
    
    my $user_id = $self->session('user_id');
    
    if ( $user_id && $self->session('user_type') eq $self->stash('user_type') ) {
        $self->redirect_to( $self->um_config->{home_url}, user_id => $user_id );
        return;
    }
    
    $self->render( 'sessions/create_form', layout => $self->um_config->{layout} );
}

sub create {
    my ($self)  = @_;
    my $user_id = $self->param('user_id');
    my $pass    = $self->param('password');

    if ( $self->_check_user_password( $user_id, $pass ) ) {

        # Check that user is activated
        my $u_data = $self->um_storage->get($user_id);
        unless ( $u_data->{_is_active} ) {
            $self->flash( um_error => 'User is not active!' );
            $self->redirect_to('auth_create_form');
            return;
        }

        my $user_type = $self->stash('user_type');
        die "Cannot work without user_type" unless $user_type;
        
        $self->session( 'user_id' => $user_id, 'user_type' => $user_type );
        $self->redirect_to( $self->um_config->{home_url}, user_id => $user_id );
    } else {
        $self->flash( um_error => 'Wrong user or password!' );
        $self->redirect_to('auth_create_form');
    }
}

sub delete {
    my ($self) = @_;
    $self->session( user_id => '' )->redirect_to('auth_create_form');
}

sub check {
    my ($self) = @_;
    $self->stash( 'user_id' => '' );
    my $user_id   = $self->session('user_id');

    if ( $user_id && $self->session('user_type') eq $self->stash('user_type') ) {
        $self->stash( 'user_id' => $user_id );
        return 1;
    } else {
        $self->redirect_to('auth_create_form');
        return 0;
    }
}

sub _check_user_password {
    my ( $self, $user_id, $password ) = @_;
    return 0 unless $user_id && $password;

    my $config  = $self->um_config;
    my $storage = $self->um_storage;

    my $user_data = $storage->get($user_id);

    return 0 unless $user_data && exists $user_data->{password};
    return 1 if ( $config->{password_crypter}->($password) eq $user_data->{password} );
    return 0;
}

1;
