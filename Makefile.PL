use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME         => 'Mojolicious::Plugin::UserManager',
  VERSION_FROM => 'lib/Mojolicious/Plugin/UserManager.pm',
  AUTHOR       => 'A Good Programmer <nospam@cpan.org>',
  PREREQ_PM    => {
      'Mojolicious'    => '2.0',
      'Email::Valid'   => 0,
      'Validate::Tiny' => 0.08,
  },
  test         => {TESTS => 't/*.t'}
);
