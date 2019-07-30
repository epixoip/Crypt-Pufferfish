# Crypt::Pufferfish - an adaptive, cache-hard password hashing scheme
#
# Copyright 2019, Jeremi M Gosney. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

package Crypt::Pufferfish;

require Exporter;
*import = \&Exporter::import;

require DynaLoader;

our $VERSION = "0.01";

$Crypt::Pufferfish::VERSION = $VERSION;

DynaLoader::bootstrap Crypt::Pufferfish $Crypt::Pufferfish::VERSION;

@Crypt::Pufferfish::ISA = qw( Exporter DynaLoader );

%Crypt::Pufferfish::EXPORT_TAGS = (
    'all' => [ "new", "hash", "checkpass" ]
);

@Crypt::Pufferfish::EXPORT_OK = ( @{$EXPORT_TAGS{'all'}} );

@Crypt::Pufferfish::EXPORT = ( @{$EXPORT_TAGS{'all'}} );


use MIME::Base64 qw(encode_base64 decode_base64);
use Crypt::URandom qw(urandom);

my $PF_SALT_SZ = 16;

my $PF_TCOST_ABSURD = 19;
my $PF_TCOST_DEFAULT = 6;
my $PF_TCOST_MAX = 63;

my $PF_MCOST_ABSURD = 13;
my $PF_MCOST_MIN = 7;
my $PF_MCOST_MAX = 53;


sub log2_cache_size {
    # Most all Intel CPUs made in the past decade have 256K of L2 cache
    my $cache_sz = 256;

    # TODO: How to find L2 cache size on other OS
    if ($^O eq "linux") {
        open my $fh, "<", "/sys/devices/system/cpu/cpu0/cache/index2/size";

        my $cache_sz = do { local $/; <$fh> };

        close $fh;

        $cache_sz =~ s/\D//g;
    }

    return log($cache_sz) / log(2);
}

sub new {
    my ($class, $args) = @_;

    my $self = {
        salt     => $args->{salt},
        pepper   => $args->{pepper} || "",
        cost_t   => $args->{cost_t} || $PF_TCOST_DEFAULT,
        cost_m   => $args->{cost_m} || log2_cache_size(),
        silent   => $args->{ignore_absurd} || 0
    };

    if ($self->{salt_sz} > $PF_SALT_SZ) {
        print STDERR "Warning: 'salt_sz' of ".$self->{salt_sz}." is greater than the maximum value ".$PF_SALT_SZ."\n";
        $self->{salt_sz} = $PF_SALT_SZ;
    }

    if ($self->{cost_t} > $PF_TCOST_MAX) {
        print STDERR "Warning: 'cost_t' of ".$self->{cost_t}." is greater than the maximum value ".$PF_TCOST_MAX."\n";
        $self->{cost_t} = $PF_TCOST_MAX;
    }

    if ($self->{cost_m} > $PF_MCOST_MAX) {
        print STDERR "Warning: 'cost_m' of ".$self->{cost_m}." is greater than the maximum value ".$PF_MCOST_MAX."\n";
        $self->{cost_m} = $PF_MCOST_MAX;
    }


    if ($self->{cost_t} > $PF_TCOST_ABSURD && $self->{silent} == 0) {
        print STDERR "Warning: 'cost_t' of ".$self->{cost_t}." is absurdly large!\n";
    }

    if ($self->{cost_m} > $PF_MCOST_ABSURD && $self->{silent} == 0) {
        print STDERR "Warning: 'cost_m' of ".$self->{cost_m}." is absurdly large!\n";
    }

    if ($self->{cost_m} < $PF_MCOST_MIN && $self->{silent} == 0) {
        print STDERR "Warning: 'cost_m' of ".$self->{cost_m}." loses GPU resistance!!\n"
    }

    return bless $self, $class;
}

sub hash {
    my ($self, $pass) = @_;

    if (length($self->{salt}) == 0) {
        $self->{salt} = ${PF_mksalt(urandom($PF_SALT_SZ), $self->{cost_t}, $self->{cost_m})};

        if (length($self->{salt}) == 0) {
            die "Error: Unable to create salt string";
        }
    }

    my $hash = ${PF_hash($self->{salt}, $self->{pepper}.$pass)};

    if (length($hash) == 0) {
        die "Error: Invalid salt value";
    }

    return $hash;
}

sub check {
    my ($self, $valid, $pass) = @_;

    return ${PF_checkpass($valid, $self->{pepper}.$pass)};
}

sub dl_load_flags {0} # Prevent DynaLoader from complaining and croaking

1;

