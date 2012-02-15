package Mojolicious::Plugin::UserManager;
use Mojo::Base 'Mojolicious::Plugin';

use Carp qw/croak/;
use Digest::MD5 qw/md5_hex/;

our $VERSION = '0.01';

sub register {
    my ( $self, $app, $conf ) = @_;
    $self->_apply_conf_defaults($conf);
    my $r = $app->routes;
    my $auth_r = $r->bridge('/users/:user_id')->to(cb => sub { $self->_check_user_session($self) });
    
    $r->get('/login')->to('show login screen');
    $r->post('/login')->to('submit login and password');
    $r->post('/users')->to('register new user');
    
    $auth_r->get('/users/:user_id')->to('get user profile');
    $auth_r->post('/users/:user_id')->to('update user profile');
    $auth_r->post('/logout')->to('logout user');
    
    $app->helper( user_data => sub {} );
}

sub _check_user_session {
    my $self = shift;
    $c->stash( 'user_id' => '' );
    my $user_id = $c->session('user_id');

    if ( $user_id ) {
        $self->stash( 'user_id' => $user_id );
        return 1;
    } else {
        $self->redirect_to('sessions_create_form');
        return 0;
    }
}


sub _create_user_session {
    my ($self) = @_;

    my $user_id  = $self->param('user_id');
    my $password = $self->param('password');
    my $user     = BKE::User->authenticate( $email, $password );

    if ($user) {
        $self->session(
            user_id       => $user->user_id,
        )->redirect_to('users_show');
    } else {
        $self->flash( error => $self->l('Wrong password or user does not exist!') )
            ->redirect_to('sessions_create_form');
    }
}

sub _delete_user_session {
    my $self = shift;

    if ( $self->is_valid_csrftoken() ) {
        $self->session( user_id => '', email => '', companies_ids => '' )->redirect_to('sessions_create_form');
    } else {
        $self->render_error();
    }
}

sub _apply_conf_defaults {
    my ( $self, $conf ) = @_;

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

    if ( !$fields{_uid} ) {
        unshift @{ $conf->{fields} }, {
            name      => '_uid',
            label     => 'User ID',
            validator => sub { }
        };
    }

    if ( !$fields{_email} ) {
        unshift @{ $conf->{fields} }, {
            name      => '_email',
            label     => 'Email',
            validator => sub { }
        };
    }

    if ( !$fields{_password} ) {
        unshift @{ $conf->{fields} }, {
            name      => '_password',
            label     => 'Password',
            validator => sub { }
        };

    }

    if ( !$fields{_is_active} ) {
        unshift @{ $conf->{fields} }, {
            name      => '_is_active',
            label     => 'Is Active',
            validator => sub { }
        };
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
