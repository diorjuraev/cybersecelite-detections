#!/usr/bin/env perl
# Offline regression check for the PHP2Shell Splunk pack.
#
# Reads each regex straight out of the shipped .spl files (so the test cannot
# drift from the searches), undoes SPL string escaping, and runs it with Perl's
# regex engine against log fixtures. Perl and Splunk's PCRE agree on every
# construct used here: (?is), \b, \s, named groups, lazy quantifiers.
#
# This checks the regex and the classification logic, not SPL execution.
# Run the makeresults tests in README.md inside Splunk for that.
#
# Usage: perl tests/check_regex.pl   (from the pack directory)
use strict;
use warnings;
use File::Basename qw(dirname);

my $root = dirname(dirname(__FILE__));
my ($pass, $fail) = (0, 0);

sub spl_unescape {
    my ($s) = @_;
    $s =~ s/\\(["\\])/$1/g;    # SPL strings only treat \" and \\ specially
    return $s;
}

sub rex_from {
    my ($file) = @_;
    open my $fh, '<', "$root/$file" or die "cannot read $file: $!";
    while (my $line = <$fh>) {
        return spl_unescape($1) if $line =~ /^\|\s*rex\s+field=\S+\s+"((?:[^"\\]|\\.)*)"/;
    }
    die "no rex line in $file\n";
}

sub check {
    my ($name, $ok, $detail) = @_;
    if ($ok) { $pass++; print "ok   $name\n" }
    else     { $fail++; print "FAIL $name  " . ($detail // "") . "\n" }
}

sub run_cases {
    my ($label, $re, @cases) = @_;
    for my $c (@cases) {
        my ($id, $raw, $want) = @$c;
        my %got;
        if ($raw =~ $re) { %got = %+ }
        if (!defined $want) {
            check("$label/$id no match", !%got, 'unexpected match: ' . join(',', map {"$_=$got{$_}"} sort keys %got));
            next;
        }
        my @bad = grep { ($got{$_} // '<undef>') ne ($want->{$_} // '<undef>') } (keys %$want, keys %got);
        check("$label/$id match", %got && !@bad,
              join(' ', map { "$_: want=" . ($want->{$_} // '<undef>') . ' got=' . ($got{$_} // '<undef>') } @bad));
    }
}

# --- Primary: request-startup OOM ------------------------------------------
my $oom = rex_from('cse-det-php2shell-request-startup-oom-splunk-v1.spl');
my $oom_re = qr/$oom/;
run_cases('oom', $oom_re,
    ['apache-mod_php',
     '[Wed Oct 21 14:02:11.123456 2026] [php:error] [pid 2211] [client 203.0.113.5:51234] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0',
     {php_memory_limit_bytes => 134217728, php_attempted_allocation_bytes => 20480}],
    ['php-error_log',
     '[21-Oct-2026 14:02:11 UTC] PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted (tried to allocate 65536 bytes) in Unknown on line 0',
     {php_memory_limit_bytes => 16777216, php_attempted_allocation_bytes => 65536}],
    ['fpm-catch_workers_output',
     '[21-Oct-2026 14:02:11] WARNING: [pool www] child 4412 said into stderr: "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0"',
     {php_memory_limit_bytes => 134217728, php_attempted_allocation_bytes => 4096}],
    ['apache-referer-suffix',
     '[php:error] [pid 9] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0, referer: https://example.test/upload',
     {php_memory_limit_bytes => 134217728, php_attempted_allocation_bytes => 4096}],
    ['unpatched-system-oom (memory_limit=-1 mitigation)',
     'PHP Fatal error:  Out of memory (allocated 2097152 bytes) (tried to allocate 1073741824 bytes) in Unknown on line 0',
     {php_allocated_bytes => 2097152, php_attempted_allocation_bytes => 1073741824}],
    ['debug-build',
     'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted at /src/php/Zend/zend_alloc.c:1049 (tried to allocate 4096 bytes) in Unknown on line 0',
     {php_memory_limit_bytes => 134217728, php_attempted_allocation_bytes => 4096}],
    ['in-script-oom',
     'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in /var/www/html/index.php on line 42',
     undef],
    ['pre-init-warning-not-oom',
     'PHP Warning:  Unknown: Input variables exceeded 1000. To increase the limit change max_input_vars in php.ini. in Unknown on line 0',
     undef],
    ['patched-hard-limit-is-separate',
     'Hard memory limit of 201326592 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0',
     undef],
    ['file-named-Unknown',
     'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in /var/www/Unknown.php on line 0',
     undef],
    ['bare-out-of-memory',
     'Out of memory',
     undef],
);

# --- Patched-runtime hard limit ---------------------------------------------
my $hard = rex_from('cse-hunt-php2shell-patched-hard-limit-splunk-v1.spl');
my $hard_re = qr/$hard/;
run_cases('hard', $hard_re,
    ['request-startup',
     'Hard memory limit of 201326592 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0',
     {php_hard_limit_bytes => 201326592, php_attempted_allocation_bytes => 4096, php_error_file => 'Unknown', php_error_line => 0}],
    ['fpm-in-script',
     '[21-Oct-2026 14:02:11] WARNING: [pool www] child 77 said into stderr: "Hard memory limit of 201326592 bytes exhausted (tried to allocate 8192 bytes) in /var/www/html/import.php on line 88"',
     {php_hard_limit_bytes => 201326592, php_attempted_allocation_bytes => 8192, php_error_file => '/var/www/html/import.php', php_error_line => 88}],
    ['soft-limit-is-not-hard',
     'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0',
     undef],
);

# --- Endpoint hunt: child-shell classification ------------------------------
# Mirrors the eval/case() order in the .spl: original_file_name, then
# process_exec, then process_name; basename + lowercase first.
my $hunt = do { local $/; open my $fh, '<', "$root/cse-hunt-php2shell-web-worker-child-shell-splunk-v1.spl" or die $!; <$fh> };
my ($shell) = $hunt =~ /match\(original_l, "((?:[^"\\]|\\.)*)"\)/ or die "no shell regex in hunt\n";
my $shell_re = qr/@{[ spl_unescape($shell) ]}/;
my @dupes = $hunt =~ /match\((?:exec_l|name_l), "((?:[^"\\]|\\.)*)"\)/g;
check('hunt/shell regex identical in all three case() arms', (@dupes == 2 && !grep({ $_ ne $shell } @dupes)), 'arms differ');

sub base { my $v = lc(shift // 'unknown'); $v =~ s{^.*[/\\]}{}; $v }
sub classify {
    my (%p) = @_;
    for my $f (qw(original_file_name process_exec process_name)) {
        my $v = base($p{$f});
        return $v if $v =~ $shell_re;
    }
    return undef;
}
my @hunt_cases = (
    [1, {original_file_name => 'bash', process_exec => '/usr/bin/bash', process_name => 'bash'}, 'bash'],
    [2, {process_exec => 'C:\\Windows\\System32\\cmd.exe', process_name => 'cmd.exe'}, 'cmd.exe'],
    [3, {process_exec => '/usr/bin/convert', process_name => 'convert'}, undef],
    [4, {process_exec => '/usr/bin/php8.3', process_name => 'php8.3'}, undef],
    [5, {process_name => 'pwsh'}, 'pwsh'],
    [6, {original_file_name => 'PowerShell.EXE', process_name => 'svchost.exe'}, 'powershell.exe'],
    [7, {process_exec => '/bin/sh', process_name => 'sh'}, 'sh'],
    [8, {process_exec => '/usr/bin/bashful', process_name => 'bashful'}, undef],
    [9, {process_exec => '/usr/sbin/sendmail', process_name => 'sendmail'}, undef],
);
for my $c (@hunt_cases) {
    my ($id, $p, $want) = @$c;
    my $got = classify(%$p);
    check("hunt/case $id", ($got // '<undef>') eq ($want // '<undef>'), 'want=' . ($want // '<undef>') . ' got=' . ($got // '<undef>'));
}

# --- README synthetic tests must use the shipped regexes ---------------------
# The makeresults tests in README.md are what a Splunk user copy-pastes; if
# their rex/match strings drift from the .spl files they test nothing.
my $readme = do { local $/; open my $fh, '<', "$root/README.md" or die $!; <$fh> };
my @readme_rex = $readme =~ /^\|\s*rex\s+field=_raw\s+"((?:[^"\\]|\\.)*)"/mg;
check('readme/has 2 rex tests', @readme_rex == 2, 'found ' . scalar(@readme_rex));
my %shipped = map { $_ => 1 } ($oom, $hard);
for my $i (0 .. $#readme_rex) {
    check("readme/rex test $i matches a shipped .spl regex", $shipped{ spl_unescape($readme_rex[$i]) }, 'drifted from .spl');
}
my @readme_shell = $readme =~ /match\((?:original_l|exec_l|name_l), "((?:[^"\\]|\\.)*)"\)/g;
check('readme/companion test uses shipped shell regex', (@readme_shell == 3 && !grep({ $_ ne $shell } @readme_shell)), 'drifted from .spl');

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
