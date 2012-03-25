package Mojolicious::Plugin::UserManager::Controller::Users;

use v5.10;
use strict;
use warnings;

use Mojo::Base 'Mojolicious::Controller';
use Validate::Tiny;
use Digest::MD5 qw/md5_hex/;

sub create_form {
    my $self = shift;
    my $user_id = $self->session('user_id');
    
    if ( $user_id && $self->session('user_type') eq $self->stash('user_type') ) {
        $self->redirect_to( $self->um_config->{home_url}, user_id => $user_id );
        return;
    }
    
    $self->stash( captcha => $self->um_config->{captcha} );
    $self->render( 'users/create_form', layout => $self->um_config->{layout} );
}

sub update_form {
    my $self = shift;
    $self->render( 'users/update_form', layout => $self->um_config->{layout} );
}

sub create {
    my ($self) = @_;
    my $conf = $self->um_config;

    my $result = $self->_validate_fields();
    my $u_data = $result->data;
    delete $u_data->{password2};

    if ( $result->success ) {

        # Check captcha
        if ( $conf->{captcha} && !$self->recaptcha ) {
            $self->flash( %$u_data, um_error => 'Wrong CAPTCHA code' );
            $self->redirect_to('user_create_form');
            return;
        }

        # Check that user does not exists
        if ( $self->um_storage->get( $u_data->{user_id} ) ) {
            $self->flash( %$u_data, um_error => 'Such user already exists' );
            $self->redirect_to('user_create_form');
            return;
        }

        # Crypt password
        $u_data->{password} = $conf->{password_crypter}->( $u_data->{password} );

        # Send confirmation emails
        if ( $conf->{email_confirm} || $conf->{admin_confirm} ) {
            my $activation_code = md5_hex( time + rand(time) );
            my $user_type = $self->stash('user_type');
            my $activation_url  = "$conf->{site_url}/$user_type/activate/$activation_code";
            $u_data->{_is_active}       = 0;
            $u_data->{_activation_code} = $activation_code;

            # Send email to admin
            if ( $conf->{admin_confirm} ) {
                say "To activate [$u_data->{user_id}] go to $activation_url";
                $self->mail(
                    to      => $conf->{admin_confirm},
                    subject => "User [ $u_data->{user_id} ] activation",
                    data    => "To activate [$u_data->{user_id}] go to $activation_url",
                );
            }

            # Send email to user
            if ( $conf->{email_confirm} && $u_data->{email} ) {
                $self->app->log->debug( "To activate [$u_data->{user_id}] go to $activation_url" );
                $self->mail(
                    to      => $u_data->{email},
                    subject => "User [ $u_data->{user_id} ] activation",
                    data    => "To activate [$u_data->{user_id}] go to $activation_url",
                );
            }
        } else {
            $u_data->{_is_active} = 1;
        }

        # Save user
        $self->um_storage->set( $u_data->{user_id}, $u_data );

        
        # Call on_registration callback
        my $on_reg_cb = ref( $self->um_config->{on_registration} ) eq 'CODE' ? $self->um_config->{on_registration} : '';
        $on_reg_cb->($self, $u_data) if $on_reg_cb; 
        

        # Redirect to login form
        $self->flash( um_notice => 'Registration completed' );
        $self->redirect_to('auth_create_form');
    } else {
        my $errors_hash = $result->error;
        my ($field) = keys %$errors_hash;

        my $label = $self->schema_for_field($field)->{label};

        $self->flash( %$u_data, um_error => qq#$label: $errors_hash->{$field}# );
        $self->redirect_to('user_create_form');
    }
}

sub update {
    my ($self) = @_;
    my $conf = $self->um_config;

    my $result = $self->_validate_fields( [qw/password password2 user_id/] );
    my $u_data = $result->data;

    # Check passwords
    my $is_password_error;
    if ( my $pass = $self->param('password') ) {
        if ( $pass ne $self->param('password2') ) {
            $self->flash( %$u_data, um_error => qq#Passwords do no coincide# );
            return $self->redirect_to('user_update_form');    
        }
    }

    if ( $result->success ) {

        # Crypt password
        my $new_pass = $self->param('password');
        if ($new_pass) {
            $u_data->{password} = $conf->{password_crypter}->($new_pass);
        } else {
            delete $u_data->{password};
        }

        # Save user
        $self->um_storage->set( $self->stash('user_id'), $u_data );

        $self->flash( um_notice => 'Saved' );
    } else {
        my $errors_hash = $result->error;
        my ($field)     = keys %$errors_hash;
        my $label       = $self->schema_for_field($field)->{label};
        $self->flash( %$u_data, um_error => qq#$label: $errors_hash->{$field}# );
    }
    $self->redirect_to('user_update_form');
}

sub activate {
    my ($self) = @_;
    my $act_code = $self->param('activation_code');
    return $self->render_text("Wrong activation code") unless $act_code =~ /^[0-9a-f]{32}$/i;

    my $users = $self->um_storage->list();
    my ($u_data) = grep { $_->{_activation_code} && $_->{_activation_code} eq $act_code } @$users;

    if ($u_data) {
        $self->um_storage->set( $u_data->{user_id}, { _is_active => 1 } );
        $self->render_text("User [$u_data->{user_id}] activated");
    } else {
        $self->render_text("Wrong activation code");
    }
}


sub _validate_fields {
    my ( $self, $skip ) = @_;

    my $schema = $self->um_config->{fields};
    my @fields = map { $_->{name} ~~ $skip ? () : $_->{name} } @$schema;
    my @checks = map { $_->{name} => $_->{check} } grep { $_->{check} } @$schema;
    my %input  = map { $_, ($self->param($_)//'') } @fields;

    return Validate::Tiny->new( \%input, { fields => \@fields, checks => \@checks } );
}

1;