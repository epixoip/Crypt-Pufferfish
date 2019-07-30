use strict;
use warnings FATAL => "all";

use ExtUtils::MakeMaker;

my %options = %{{
    NAME          => "Crypt::Pufferfish",
    LIBS          => "-lcrypto",
    OPTIMIZE      => " -O4",
    INC           => "",
    AUTHOR        => "Jeremi M Gosney <jgosney\@terahash.com>",
    ABSTRACT      => "Crypt::Pufferfish - an adaptive, cache-hard password hashing scheme",
    VERSION_FROM  => "lib/Crypt/Pufferfish.pm",
    PREREQ_PM     => {
        "Crypt::URandom" => 0,
        "MIME::Base64"   => 0
    },
    META_MERGE => {
        resources => {
            homepage   => "https://github.com/epixoip/Crypt-Pufferfish",
            repository => "https://github.com/epixoip/Crypt-Pufferfish",
            bugtracker => "https://github.com/epixoip/Crypt-Pufferfish/issues"
        }
    }
}};

WriteMakefile(%options);

# Remove the Makefile dependency. Causes problems on a few systems.
sub MY::makefile { '' }
