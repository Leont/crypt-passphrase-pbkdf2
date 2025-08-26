package Crypt::Passphrase::PBKDF2;

use strict;
use warnings;

use Crypt::Passphrase 0.010 -encoder;

use Carp 'croak';
use PBKDF2::Tiny qw/derive verify/;
use MIME::Base64 qw/encode_base64 decode_base64/;

my %param_for_type =(
	sha1   => 'SHA-1',
	sha224 => 'SHA-224',
	sha256 => 'SHA-256',
	sha384 => 'SHA-384',
	sha512 => 'SHA-512',
);

sub new {
	my ($class, %args) = @_;
	my $type = $args{type} || 'sha256';
	croak "Hash type $type not supported" unless exists $param_for_type{$type};
	return bless {
		salt_size  => $args{salt_size} || 16,
		iterations => $args{iterations} || 100_000,
		type       => $type,
	}, $class;
}

sub ab64_encode {
	my $input = shift;
	return encode_base64($input, '') =~ tr/+=/./dr;
}

sub ab64_decode {
	my $input = shift;
	return decode_base64($input =~ tr/./+/r);
}

sub hash_password {
	my ($self, $password) = @_;
	my $salt = $self->random_bytes($self->{salt_size});
	my $hash = derive($param_for_type{ $self->{type} }, $password, $salt, $self->{iterations});
	return join '$', "\$pbkdf2-$self->{type}", $self->{iterations}, ab64_encode($salt), ab64_encode($hash);
}

my $decode_regex = qr/ \A \$ pbkdf2- (\w+) \$ (\d+) \$ ([^\$]+) \$ ([^\$]*) \z /x;

sub needs_rehash {
	my ($self, $hash) = @_;
	my ($type, $iterations, $salt64, $hash64) = $hash =~ $decode_regex or return 1;
	return 1 if $type ne $self->{type} or $iterations != $self->{iterations};
	return 1 if length ab64_decode($salt64) != $self->{salt_size};
	return;
}

sub crypt_subtypes {
	return map { "pbkdf2-$_" } keys %param_for_type;
}

sub verify_password {
	my ($class, $password, $hash) = @_;

	my ($type, $iterations, $salt64, $hash64) = $hash =~ $decode_regex or return 0;
	return 0 unless exists $param_for_type{$type};
	return verify(ab64_decode($hash64), $param_for_type{$type}, $password, ab64_decode($salt64), $iterations);
}

1;

# ABSTRACT: A PBKDF2 encoder for Crypt::Passphrase

=head1 DESCRIPTION

This class implements a PBKDF2 encoder for Crypt::Passphrase. It allows for any SHA-1 or SHA-2 hash, and any number of iterations.

=method new(%args)

This creates a new PBKDF2 encoder, it takes named parameters that are all optional. Note that some defaults are likely to change at some point in the future, as computers get progressively more powerful and cryptoanalysis gets more advanced.

=over 4

=item * type

This can be any of C<sha1>, C<sha224>, C<sha256> (default), C<sha384> or C<sha512>.

=item * iterations

This will be the iteration count, defaulting to C<100000>.

=item * salt_size

The size of the salt. This defaults to 16 bytes, which should be more than enough for any use-case.

=back

=method hash_password($password)

This hashes the passwords with pbkdf2 according to the specified settings and a random salt (and will thus return a different result each time).

=method needs_rehash($hash)

This returns true if the hash uses a different cipher, or if any of the parameters is lower that desired by the encoder.

=method crypt_types()

This class supports the following crypt types: C<pbkdf2-sha1>, C<pbkdf2-sha224>, C<pbkdf2-sha225>, C<pbkdf2-sha384> and C<pbkdf2-512>.

=method verify_password($password, $hash)

This will check if a password matches a pbkdf2 hash.
