#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Mojolicious::Plugin::UserManager' ) || print "Bail out!\n";
}

diag( "Testing Mojolicious::Plugin::UserManager $Mojolicious::Plugin::UserManager::VERSION, Perl $], $^X" );
