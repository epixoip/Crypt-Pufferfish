# Crypt::Pufferfish

## Description

This Perl module implements the Pufferfish V2 PHF, which is an adaptive cache-hard password hashing function designed to be a modern replacement for bcrypt.

## Synopsis

```perl
use Crypt::Pufferfish;

my $password = "Password1";

my $pf = new Crypt::Pufferfish({
    cost_t => 7,
    pepper => "Z9XFbwDajyqQArk8"
});

my $hash = $pf->hash($password);

print $hash . "\n";

if ($pf->check($hash, $password)) {
    print "Authentication successful!\n";
}
```

## Methods

### new (%opts)

Initializes a new object, with an optional hash containing key-value pairs to define optional parameters as follows:

#### cost\_t => _val_
The log2 iteration count, or the number of times the function loops over itself. The default value is "6" (2^6, or 64 iterations.) You may wish to increase this value slightly depending on the speed of your CPU, but you should benchmark your application at various `cost_t` values in order to determine the highest value that still enables you to meet your target runtime, or your required number of peak simultaneous authentication attempts per second. For applications where Pufferfish is being employed during an interactive login process, you will likely want to target a runtime ≤ 1000ms in order to strike a balance between security and good UX. 

#### cost\_m => _val_
The total log2 size of the s-boxes in kibibytes (thousands of binary bytes.) For example, a value of "8" would be 2^8 kibibytes (or 256 KiB.) Pufferfish is a cache-hard algorithm, and thus needs to run in on-chip cache (preferably L2 cache, but L3 cache may be used where longer runtimes are desirable.) To retain GPU resistance, this parameter should *never* be set lower than "7". Ideally, this value should be equal to the per-core L2 cache size of your specific CPU:

```
+----------------------------------+
| Per-core L2 cache | cost_m value |
|-------------------|--------------|
| 128 KiB           | 7            |
| 256 KiB           | 8            |
| 512 KiB           | 9            |
| 1 MiB             | 10           |
| 2 MiB             | 11           |
| 4 MiB             | 12           |
+----------------------------------+
```

On Linux systems, the optimal value is automatically selected by default, and probably should not be changed. For other operating systems, the default value of "8" is used, as most Intel CPUs made in the past decade have 256 KiB of L2 cache. You really should only change the default if you are NOT using Linux AND have an AMD CPU, a non-x86 CPU, a really old (pre-2008) Intel CPU, or a really new (2018-) Intel CPU.

You may also set a slightly higher value in order to push out into L3 cache if you are targeting runtimes . However, you are _strongly encouraged_ to keep Pufferfish in L2 cache unless you are specifically targeting runtimes > 1000ms. That said, you are _strongly discouraged_ from pushing out beyond L3 cache. While Pufferfish does technically support `cost_m` values up to 53 (8 EiB), it is a _cache-hard_ algorithm, not a _memory-hard_ algorithm, and thus should not be run from off-chip memory unless you _really_ know what you are doing and are prepared to wait a _very_ long time.

#### pepper => _val_
A global, site-specific secret to be hashed alongside the password. For more information, see: https://en.wikipedia.org/wiki/Pepper%5F(cryptography)

#### salt => _val_
A static salt string, as encoded by the `PF_mksalt` function. This should only be used for testing purposes. The `cost_t` and `cost_m` options are ignored when this option is supplied.

#### ignore\_absurd => _1_
This binary flag suppresses warnings that are printed when absurd `cost_t` and `cost_m` values are supplied. You should only set this flag if you absolutely know what you are doing.


### hash (_$password_)

Creates a Pufferfish V2 hash of the supplied password value. The return value is a scalar containing the complete encoded hash string.

### check (_$hash_, _$password_)

Compares the supplied password against a valid encoded hash string, such as from a database, in constant time. The return value is "1" if the password matches, and "0" if the password does not match.

