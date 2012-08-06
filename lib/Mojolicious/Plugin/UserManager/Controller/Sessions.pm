package Mojolicious::Plugin::UserManager::Controller::Sessions;
use Mojo::Base 'Mojolicious::Controller';

use v5.10;
use strict;
use warnings;

use File::Basename qw/dirname/;
use File::Spec::Functions qw/rel2abs/;
use Data::Dumper;

sub _get_ip {
    my $self = shift;
    return $self->req->headers->header('x-real-ip') || "No IP";
}

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
        unless ( $u_data->{_is_activated_by_user} ) {
            $self->flash( um_error => 'User is not active!' );
            $self->redirect_to('auth_create_form');
            return;
        }

        # Check that user is activated by admin
        unless ( $u_data->{_is_activated_by_admin} ) {
            $self->flash( um_error => 'User must be activated by administrator!' );
            $self->redirect_to('auth_create_form');
            return;
        }

        my $user_type = $self->stash('user_type');
        die "Cannot work without user_type" unless $user_type;
        
        $self->_update_expires();
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


sub _update_expires {
    # TODO remove dupication with UserManager::_session_update_expires
    my $self = shift;
    return unless $self->um_config->{session_expiration};
    $self->session( 'lifetime' => ( time + $self->um_config->{session_expiration} ) );
}

sub _check_user_password {
    my ( $self, $user_id, $password ) = @_;
    my $log = $self->app->log;

    unless ($user_id) {
        $log->debug("AUTH FAILED: No user_id");
        return 0;
    }

    unless ($password) {
        $log->debug("AUTH FAILED: user_id=[$user_id]. Empty password.");
        return 0;
    }

    local $Data::Dumper::Indent = 0; 
    $log->debug("AUTH DEBUG: Login attempt user_id=[$user_id]" . Dumper($self->session) );

    my $config  = $self->um_config;
    my $storage = $self->um_storage;

    $log->debug("AUTH DEBUG: Getting data for user_id=[$user_id]");
    
    my $user_data = eval { $storage->get($user_id) };

    unless( $user_data && exists $user_data->{password} ) {
        $log->debug("AUTH FAILED: No data for user_id=[$user_id]");
        return 0;     
    }
    
    if ( $config->{plain_auth} && $password eq $user_data->{password} ) {
        $log->debug("AUTH SUCCESS: Plain password login for user_id=[$user_id]");
        return 1; 
    }

    if ( $config->{password_crypter}->($password, $user_data) eq $user_data->{password} ) {
        $log->debug("AUTH SUCCESS: Crypted password login for user_id=[$user_id]");
        return 1; 
    }
    
    $log->debug("AUTH FAILED: Wrong password for user_id=[$user_id]");
    return 0;
}

1;
