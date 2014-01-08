package CSP;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require AutoLoader;
use IO::File;
use Term::Prompt;
use POSIX qw(strftime);

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw();
@EXPORT_OK = qw($_openssl);
$VERSION = '0.26';


# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

$CSP::_openssl='openssl';

sub message
  {
    sprintf "[CSP][%-8s] %s",$_[0]->{name},$_[1];
  }

sub die
  {
    die CSP::message(@_)."\n";
  }

sub warn
  {
    warn CSP::message(@_)."\n";
  }

sub new
  {
    my $self = shift;
    my $class = ref $self || $self;
    my $dir = shift;
    my $name = shift;

    my $me = bless { dir=>$dir,name=>$name },$class;

    open ALIASES,"$dir/etc/aliases.txt";
    while (<ALIASES>) 
      {
	chomp;
	next unless /\s*([^:]+)\s*:\s*([^:]+)\s*/;
	$me->{aname}->{lc($1)} = $2;
	$me->{alias}->{lc($2)} = $1;
      }
    close ALIASES;

    $me;
  }

sub DESTROY
  {
    my $self = shift;

    foreach my $file (keys %{$self->{_tmpfiles}})
      {
	#unlink $file;
      }

    my $dir = $self->caDir();
    if (-d $dir)
      {
	unlink "$dir/serial.old";
	unlink "$dir/index.txt.old";
      }
  }

sub setCA
  {
    my $on = $_[0]->{name};

    $_[0]->{name}= $_[1];
    return $on;
  }

sub addFile
  {
    my $self = shift;
    my $cf = shift;
    my $fn = shift;

    open IN,$fn
      or die "unable to open $fn for reading";
    while (<IN>)
      {
	next if /^\#/;
	$cf->print($_);
      }
    close IN;
  }

sub _rewrite
  {
    my $vars = shift;
    my $line = shift;

    while ($line =~ s/%{([a-zA-Z0-9_\.]+)}/$vars->{$1}/eg) { }
    $line;
  }

sub mppFile
  {
    my $self = shift;
    my $cf   = shift;
    my $vars = shift;
    my $fn   = shift;
    my $ctx = CSP::Stack->new(1);

    open IN,$fn
      or $self->die("mpp: unable to open $fn for reading");
    my $depth = 0;
    while (<IN>)
      {
	next if /^\#/;
	
      SWITCH:
	{
	  last SWITCH unless /^(%if|%ifdef|%endif)/ or $ctx->doPrint();

	  if (/^%ifdef\s+([A-Za-z0-9_\.]+)/)
	    {
	      $ctx->push(defined $vars->{$1});
	      last SWITCH;
	    }

	  if (/^%ifndef\s+([A-Za-z0-9_\.]+)/)
	    {
	      $ctx->push(not defined $vars->{$1});
	      last SWITCH;
	    }

	  if (/^%if\s+(.+)$/)
	      {
		my $expr = $1;
		
		$expr =~ s/%{([A-Za-z0-9_\.]+)}/"\$vars->{\"$1\"}"/eg;
		
		my $result = eval $expr;
		$self->die("$@") if $@;
		$ctx->push($result);
		last SWITCH;
	      }

	  $ctx->pop(),last SWITCH if /^%endif/;

	  $self->mppFile($cf,$vars,$1),last SWITCH if /^%include\s+(.+)/;

	  $cf->print(&_rewrite($vars,$_));
	}
      }
    close IN;
  }

sub writeConfig
  {
    my $self = shift;
    my $cmd  = shift;
    my $vars = shift;

    my $cadir = "$self->{dir}/csp/$self->{name}";

    $ENV{TMPDIR} = '/tmp' unless exists $ENV{TMPDIR};
    my $cff = $self->tempFile("csp","conf");
    my $cf = IO::File->new();
    eval
      {
	$cf->open(">$cff") 
	  or die "Unable to open $cff for writing";
	
	my $date = localtime();
	$cf->print(<<EOW);

\#\# This file is mashine generated and must not be edited
\#\# by hand. Please see the CSP-documentation for details.
\#\# $date

EOW
	
	## Default section
	$cf->print("\noid_section = oids\n\n[ oids ]\n");
	$self->addFile($cf,"$self->{dir}/etc/oids.conf");
	
	$cf->print("\n[ csp ]\n\n");
	my ($k,$v);
	while (($k,$v) = each %{$vars})
	  {
	    $cf->print("$k\t= $v\n") if ($k ne 'keypass' && $k ne 'capass');
	  }
	$cf->print("home\t= $self->{dir}\n");
	$cf->print("ca\t= $self->{name}\n");
	$cf->print("\n");
	
	## Main sections
	$cf->print(<<EOC);

[ ca ]

default_ca      = $self->{name}
 
[ $self->{name} ]
 
dir                     = \${csp::home}/csp/\${csp::ca}
certs                   = \$dir/certs
database                = \$dir/index.txt
certificate             = \$dir/ca.crt
serial                  = \$dir/serial
private_key             = /CAKeys/\${csp::ca}/ca.key
RANDFILE                = \$dir/private/.rand
x509_extensions         = extensions

default_days            = 365
default_crl_days        = 30
default_md              = sha1
preserve                = no
policy                  = policy

[ req ]
 
default_bits            = \${csp::keysize}
default_keyfile         = privkey.pem
distinguished_name      = req_dn
x509_extensions         = extensions
string_mask             = nombstr
prompt                  = no
default_md              = sha1

EOC
	
	## Extension based on command
	
	my $type = $vars->{type};
        my $name = $self->{name};
	if ($cmd eq 'x509' || $cmd eq 'req' || $cmd eq 'ca') 
	  {
	    $self->die("missing \"type\" parameter") 
	      unless $type;

	    $cf->print("[ policy ]\n\n");
	    foreach my $attr (keys %{$vars->{name_attributes}})
	      {
		next unless $attr;
		if ($self->{aname}->{lc($attr)}) 
		  {
		    $cf->print("$self->{aname}->{lc($attr)} = optional\n")
		  }
		else 
		  {
		    $cf->print("$attr = optional\n");
		  }
	      }
	    
	    ## Define a few CPP/MPP-style variables and run the prototype file
	    $vars->{uc("type_$type")}++;
	    foreach my $x (qw(email url ip dns)) 
	      {
		$vars->{uc($x)} = $vars->{$x};
	      }
	    $cf->print("\n\n");
	    if ($name) 
	      {
		my $econf = "$self->{dir}/csp/$name/extensions.conf";
		$econf = "$self->{dir}/etc/extensions.conf" unless -f $econf;
		
		$self->mppFile($cf,$vars,$econf);
	      }
	    $cf->print("\n\n");
	    if ($name) 
	      {
		my $econf = "$self->{dir}/csp/$name/crl_extensions.conf";
		$econf = "$self->{dir}/etc/crl_extensions.conf" unless -f $econf;
		
		$self->mppFile($cf,$vars,$econf);
	      }
	    $cf->print("\n");
	  }

	my $dn = $vars->{dn};
	if ($dn) 
	  {
	    my %acount;
	    
	    $cf->print("[ req_dn ]\n\n");
	    foreach my $rdn (split /\s*,\s*/,$dn)
	      {
		next unless $rdn =~ /^([^=]+)\s*=\s*([^=]+)$/;
		my $n = exists $self->{aname}->{lc($1)} ? $self->{aname}->{lc($1)} : $1;
		$vars->{_nrdn}++; ## At the end of the run _nrdn contains the
		                  ## number of newlines to send to openssl.
		my $pos = $acount{$n}++;
		$cf->print($pos.".${n}\t\t= $2\n");
	      }
	    $cf->print("\n");
	  }
	
	$cf->close;
      };
    if ($@) 
      {
	$cf->close;
	#unlink $cff; ## uncomment when debugging
	$self->die($@);
      }
    
    return $cff;
  }

sub createFiles
  {
    my $self = shift;
    my $dir = $self->caDir();
    my $keysdir = $self->caKeysDir();
    
    mkdir $dir,00755;
    mkdir "$dir/certs",00755;
    open SERIAL,">$dir/serial";
    print SERIAL "01\n";
    close SERIAL;
    mkdir "$dir/tmp",00700;
    system('touch',"$dir/index.txt");
    
    mkdir "$keysdir",00700;
    mkdir "$dir/private",00700;
    mkdir "$dir/private/keys",00700;
    system('cp','-p',"$self->{dir}/etc/extensions.conf","$dir/extensions.conf");
    system('cp','-p',"$self->{dir}/etc/crl_extensions.conf","$dir/crl_extensions.conf");
    system('cp','-rp',"$self->{dir}/etc/public_html","$dir/");
  }

sub caDir 
  {
    my $self = shift;
    my $name = $self->{name};
    $self->die("CA Name not set") unless $name;
    
    "$self->{dir}/csp/$self->{name}";
  }
  
sub caKeysDir 
  {
    my $self = shift;
    my $name = $self->{name};
    $self->die("CA Name not set") unless $name;
    
    "/CAKeys/$self->{name}";
  }

sub confirm
  {
    my $self = shift;
    my $comment = shift;
    my $fail = shift;

    $self->die($fail) unless Term::Prompt::prompt("y",$comment,"","n");
  }

sub getPassword
  {
    my $self = shift;
    my $comment = shift;
    my $reenter = shift;
    
    my ($pw,$pwr);
    
    system("stty -echo") &&
      $self->die("Unable to configure tty for password entry");
	
    print STDERR $self->message("$comment: ");
    chop($pw = <STDIN>);
    print STDERR "\n";

    if ($reenter) 
      {
	$pwr = $self->getPassword("Re-enter $comment");
      }
    else 
      {
	$pwr = $pw;
      }
    
    system("stty echo") &&
      $self->die("Unable to configure tty for password entry");
    
    $self->die("Passwords do not match")
      unless $pw eq $pwr;

    $self->die("Zero-length password")
      if length($pw) == 0;

    $pw;
  }

sub genkey
  {
    my $self = shift;
    my $args = shift;

    $self->die("Required parameter keyfile missing")
      unless $args->{keyfile};
    
    $args->{keysize} = 1024 unless $args->{keysize} > 0;
    $args->{keypass} = $self->getPassword("Private key password",1);
    
    my $process =
      CSP::OpenSSL->new($self,
			'genrsa',
			"-des3 -passout stdin -out $args->{keyfile} $args->{keysize}",$args);
    
    $process->print($args->{keypass});
    $process->closeok();
  }

sub create
  {
    my $self = shift;
    my $args = shift;

    $self->createFiles();
    $self->warn("Successfully created CA $self->{name}") 
      unless $args->{verobse} > 1;
  }

sub delete
  {
    my $self = shift;
    my $args = shift;
    
    my $dir = $self->caDir();

    system('rm','-rf',$dir);
    $self->warn("Successfully deleted CA $self->{name}") 
      unless $args->{verbose} > 1;
  }

sub init
  {
    my $self = shift;
    my $args = shift;
    
    my $dir = $self->caDir();
    my $keysdir = $self->caKeysDir();
    $self->create($args) unless -d $dir;
    
    if ($args->{crtfile})
      {
	system('cp',$args->{crtfile},"$dir/ca.crt");
	$self->warn("Successfully initialized CA $self->{name}") 
	  unless $args->{verbose} > 1;
      }
    else
      {
	$self->die("Required parameter dn missing")
	  unless $args->{dn};
	
	$args->{type} = 'root' unless $args->{type};
	$args->{days} = 3 * 365 unless $args->{days};
	
	my $cakey = "$keysdir/ca.key";
	my $cacert = "$dir/ca.crt";
	
	## Generate the CA key
	$self->warn("Generating CA key")
	  unless $args->{verbose} > 1;
	$args->{keyfile} = $cakey;
	$self->genkey($args) or
	  $self->die("Unable to generate CA key in $cakey");
	
	$args->{capass} = $args->{keypass};
	
	## Generate and optionally self-sign the request
	my $process;
	my $what;
	my $common_args = "-$args->{digest} -days $args->{days} -key $cakey -set_serial 0 -passin stdin";
	if ($args->{csrfile})
	  {
	    $process = 
	      $self->req("-new $common_args -out $args->{csrfile}",$args);
	    $process->print("$args->{keypass}\n");
	    $process->closeok();
	    $what = "generated CA request for";
	  }
	else 
	  {
	    $process = 
	      $self->req("-x509 $common_args -new -out $cacert",$args);
	    $process->print("$args->{keypass}\n");
	    $process->closeok();
	    $what = "initialized self-signed";
	  }
	
	$self->warn("Successfully $what CA $self->{name}") 
	  unless $args->{verbose} > 1;
      }
  }

sub checkCA
  {
    my $self = shift;
    my $dir = $self->caDir();
    my $keysdir = $self->caKeysDir();
    
    $self->die("Uninitialized CA: missing or unreadable ca certificate")
      unless -r "$dir/ca.crt";

    $self->die("Uninitialized CA: missing or unreadable ca private key")
      unless -r "$keysdir/ca.key";
    
    $dir;
  }

sub tempFile
  {
    my $self = shift;
    my $dir = $self->caDir();
    my $base = shift;
    my $ext = shift;

    my $tmp = $ENV{TMPFILE} || "$dir/tmp";

    my $file = "$dir/tmp/$base-$$.$ext";
    $self->{_tmpfiles}->{$file}++;
    
    $file;
  }

sub unTempFile
  {
    my $self = shift;
    my $file = shift;
    
    delete $self->{_tmpfiles}->{$file};
  }

sub keyFile
  {
    my $self = shift;
    my $dir = $self->caDir();
    
    my $serial = shift;
    "$dir/private/keys/$serial.key";
  }

sub certFile
  {
    my $self = shift;
    my $dir = $self->caDir();
    
    my $serial = shift;
    "$dir/certs/$serial.pem";
  }

sub request
  {
    my $self = shift;
    my $args = shift;
    
    $self->die("Required parameter dn missing") 
      unless $args->{'dn'};
    
    my $dir = $self->checkCA();
    
    $args->{type} = 'user' unless $args->{type};
    $args->{csrfile} = $self->tempFile("request","csr") unless $args->{csrfile};
    $args->{keyfile} = $self->tempFile("request","key") unless $args->{keyfile};

    ## Generate a key unless one already exists
    unless (-r $args->{keyfile}) 
      {
	$self->warn("Generating new key") unless $args->{verbose} > 1;
	$self->genkey($args)
	  or $self->die("Unable to generate key in $args->{keyfile}");
      }

    ## Generate a certificate request
    $self->warn("Create certificate request for $args->{dn}") 
      unless $args->{verbose} > 1;
    my $process = $self->req("-new -$args->{digest} -key $args->{keyfile} -out $args->{csrfile} -passin stdin",$args);
    $process->print("$args->{keypass}\n");
    $process->closedie();
  }

sub gencrl
  {
    my $self = shift;
    my $args = shift;

    my $dir = $self->checkCA();

    $args->{capass} = $self->getPassword("CA Private key password")
      unless $args->{capass};
    my $days = $args->{crldays} || 30;
    my $hours = $args->{crlhours};
	my $reason = $args->{reason} ;

    my $time;

	if ($reason eq "") {
		$reason = "unspecified" ;
	}
    if ($hours)
      {
	$time = "-crlhours $hours"
      }
    else
      {
	$time = "-crldays $days";
      }
    my $common = "-batch -passin stdin -md sha1 -gencrl $time";

    ## Generate both version 1 and version 2 (with extensions) CRLs
    ## and convert from PEM to DER format

    my $p1 =
      $self->ca("$common -out $dir/crl-v1.pem",$args);
    $p1->print("$args->{capass}\n");
    $p1->closedie();

    CSP::OpenSSL->new()->
	sopen($self,'dummy',"crl -outform DER -out $dir/crl-v1.crl -in $dir/crl-v1.pem")->closeok();

    my $p2 =
      $self->ca("$common -crlexts crl_extensions -crl_reason $reason -out $dir/crl-v2.pem",$args);
    $p2->print("$args->{capass}\n");
    $p2->closedie();

    CSP::OpenSSL->new()->
	sopen($self,'dummy',"crl -outform DER -out $dir/crl-v2.crl -in $dir/crl-v2.pem")->closedie();
  }

sub list
  {
    my $self = shift;
    my $args = shift;
    my $eclass = shift;

    my $dir = $self->checkCA();

    my $db = "$dir/index.txt";
    open DB,$db;
    my @out;
    while (<DB>) 
      {
	chomp;
	my @row = split /\t/;
	
	next if ($row[0] ne 'V' && !$args->{all});

	next if ($args->{serial} && $row[3] ne $args->{serial});
	
	my $entity = $eclass->new($self,\@row,$args->{xinfo},$args->{contents});
	push(@out,$entity) if ref $entity;
      }
    close DB;
    @out;
  }

sub _isodateandtime
  {
    my $date = shift;
    my @parts = split /\s+/,$date;
    warn "$parts[0] $parts[1] $parts[3]";
    my ($y,$m,$d) = Date::Calc::Parse_Date("$parts[0] $parts[1] $parts[3]");
    my $t = $parts[2];
    $t =~ s/://og;
    "$y$m$d$t";
  }

sub genPublic
  {
    my $self = shift;
    my $args = shift;

    $args->{all} = 1;
    $args->{xinfo} = 1;
    my $dir = $self->checkCA();

    $args->{export} = "/mnt/floppy"
      unless $args->{export};

    $self->die("Not a directory: $args->{export}")
      unless -d $args->{export};

    my $odir = $args->{export};
    mkdir $odir,00755;
    mkdir "$odir/certs",00755;

    my $expired_count = 0;
    my $revoked_count = 0;
    my $valid_count = 0;
    my $valid_html = "<table border=\"1\" class=\"CERTS\">\n";
    my $revoked_html = "<table border=\"1\" class=\"CERTS\">\n";
    my $expired_html = "<table border=\"1\" class=\"CERTS\">\n";
    my $date = localtime(time);
    my $cinfo = $self->certinfo("$dir/ca.crt");

    open XML,">$odir/certdb.xml";

    print XML <<EOXML;
<?xml version="1.0" encoding="ISO-8859-1"?>
<csp:db xmlns:csp='http://devel.it.su.se/CSP'>
EOXML

    foreach my $e ($self->list($args,'CSP::Entity'))
      {
	my $html = $self->getCertHTMLOutFile($e,$odir);
	my $vars = {
		    DATE=>$date,
		    SUBJECT_SERIAL => $e->{serial},
		    SUBJECT_DN => $e->{subject},
		    ISSUER_DN => $cinfo->{subject},
		    SUBJECT_SHA1 => $e->{info}->{fingerprint_sha1},
		    SUBJECT_MD5 => $e->{info}->{fingerprint_md5},
		    SUBJECT_NOTBEFORE => $e->{info}->{notbefore},
		    SUBJECT_NOTAFTER => $e->{info}->{notafter}
		   };
	
	my $serial = $e->{serial};
	
	my $from = _isodateandtime($e->{info}->{notbefore});
	my $to = _isodateandtime($e->{info}->{notafter});
	print XML <<EOXML;
   <csp:entity serial="$e->{serial}" status="$e->{status}">
     <csp:subjectdn>$e->{subject}</csp:subjectdn>
     <csp:issuerdn>$cinfo->{subject}</csp:issuerdn>
     <csp:fingerprint type="sha1">$e->{info}->{fingerprint_sha1}</csp:fingerprint>
     <csp:fingerprint type="md5">$e->{info}->{fingerprint_md5}</csp:fingerprint>
     <csp:validity>
       <csp:notbefore dateandtime="$from">$e->{info}->{notbefore}</csp:notbefore>
       <csp:notafter dateandtime="$to">$e->{info}->{notbefore}</csp:notbefore>
     </csp:validity>
   </csp:entity>
EOXML

	if (-f "$dir/p12/$serial.p12")
	  {
	    $vars->{SUBJECT_PKCS12} = "$serial.p12";
	    system('cp',"$dir/p12/$serial.p12","$odir/certs/$serial.p12");
	  }
	
	my $file = $self->certFile($serial);
	CSP::OpenSSL->new()->
	  ropen($self,'dummy',"x509 -in $file -outform DER -out $odir/certs/$serial.crt")->closeok();
	
	system('cp',$file,"$odir/certs/$serial.pem");

	$self->mppFile($html,$vars,"$dir/public_html/certs/cert.html.mpp");
	if ($e->{status} eq 'V')
	  {
	    $valid_html .= $self->genHTMLTableRow($args,$e);
	    $valid_count++;
	  }
	elsif ($e->{status} eq 'R')
	  {
	    $revoked_html .= $self->genHTMLTableRow($args,$e);
	    $revoked_count++;
	  }
	elsif ($e->{status} eq 'E')
	  {
	    $expired_html .= $self->genHTMLTableRow($args,$e);
	    $expired_count++;
	  }
      }

    print XML <<EOXML;
</csp:db>
EOXML
    close XML;
    $valid_html .= "</table>\n";
    $revoked_html .= "</table>\n";
    $expired_html .= "</table>\n";

    my $pp = CSP::OpenSSL->new()->
      sopen($self,'dummy',"x509 -inform PEM -in $dir/ca.crt -outform PEM -out $odir/ca.crt")->closeok();
    #system('cp',"$dir/ca.crt","$odir/ca.crt");
    system('cp',"$dir/crl-v1.crl","$odir/crl-v1.crl");
    system('cp',"$dir/crl-v2.crl","$odir/crl-v2.crl");

    my $vars = {
		DATE=>$date,
		VALID=>$valid_html,
		VALID_COUNT=>$valid_count,
		REVOKED=>$revoked_html,
		REVOKED_COUNT=>$revoked_count,
		EXPIRED=>$expired_html,
		EXPIRED_COUNT=>$expired_count,
		SUBJECT_SERIAL=>$cinfo->{serial},
		SUBJECT_NOTAFTER=>$cinfo->{notafter},
		SUBJECT_NOTBEFORE=>$cinfo->{notbefore},
		SUBJECT_DN=>$cinfo->{subject},
		SUBJECT_MD5=>$cinfo->{fingerprint_md5},
		SUBJECT_SHA1=>$cinfo->{fingerprint_sha1}
	       };

    for my $infile ($self->getTemplates("$dir/public_html/certs",".html.mpp"))
      {
	next if $infile eq 'cert.html.mpp'; ## The generic certificate template
	my $html = $self->getHTMLOutFile("$odir/certs/$infile");
	$self->mppFile($html,$vars,"$dir/public_html/certs/$infile");
	$html->close();
      }

    for my $infile ($self->getTemplates("$dir/public_html",".html.mpp"))
      {
	my $html = $self->getHTMLOutFile("$odir/$infile");
	$self->mppFile($html,$vars,"$dir/public_html/$infile");
	$html->close();
      }
  }

sub genHTMLTableRow
  {
    my $self = shift;
    my $args = shift;
    my $e = shift;

    my $ser = $e->{serial};
    my $pem = $ser.'.html';

    "<tr><td><strong><a href=\"$pem\">$ser</a></strong></td><td><strong>$e->{subject}</strong></td></tr>\n";
  }

sub getTemplates
  {
    my $self = shift;
    my $dir = shift;
    my $ext = shift;
    opendir(TD,$dir)
      or $self->die("Unable to open $dir");
    my @dirs = readdir(TD);
    closedir TD;
    grep { /$ext$/ } @dirs;
  }

sub getCertHTMLOutFile
  {
    my $self = shift;
    my $e = shift;
    my $dir = $self->checkCA();
    my $odir = shift;

    my $serial = $e->{serial};
    my $html = IO::File->new();
    $html->open(">$odir/certs/$serial.html")
      or $self->die("Unable to open $odir/certs/$serial.html for writing: $!");
    $html;
  }

sub getHTMLOutFile
  {
    my $self = shift;
    my $fn = shift;
    
    my $html = IO::File->new();
    my ($base) = $fn =~ /(.+)\.html\.mpp$/;
    $self->die("Filename missing .html.mpp extension: $fn")
      unless $base;
    $html->open(">$base.html")
      or $self->die("Unable to open $base.html for writing: $!");
    $html;
  }

sub dump
  {
    my $self = shift;
    my $args = shift;
     
    my $dir = $self->checkCA();
    
    my $process = CSP::OpenSSL->new()->
      ropen($self,'dummy',"x509 -noout -text -in $dir/ca.crt");
    my $fh = $process->handle();
    while (<$fh>) 
      {
	print $_;
      }
  }

sub caBundle
  {
    my $self = shift;
    my $args = shift;

    open BUNDLE,">$args->{bundle}";
    my $date = localtime();
    print BUNDLE "##\n";
    print BUNDLE "## Certificate bundle for use with OpenSSL\n";
    print BUNDLE "## Generated by CSP ($date)\n";
    print BUNDLE "##\n";
    foreach my $certfile (@_)
      {
	my $info = $self->certinfo($certfile);
	print BUNDLE "\n$info->{subject}\n";
	print BUNDLE "=========================================\n";
	print BUNDLE "MD5 Fingerprint: $info->{fingerprint_md5}\n";
	print BUNDLE "PEM Data:\n";
	open CERT,$certfile;
	while (<CERT>) 
	  {
	    print BUNDLE $_;
	  }
	close CERT;
	my $process = CSP::OpenSSL->new()->
	  ropen($self,'dummy',"x509 -noout -text -in $certfile");
	my $fh = $process->handle();
	while (<$fh>) 
	  {
	    print BUNDLE $_;
	  }
	$process->closeok();
      }
    close BUNDLE;
  }

sub revoke
  {
    my $self = shift;
    my $args = shift;
    
    my $dir = $self->checkCA();

    my $serial = $args->{serial};
    my $file = $self->certFile($serial);
	my $reason = $args->{reason} ;
   
   if ($reason eq "") {
	   $reason = "unspecified" ;
   }
   print "$reason for $file\n" ;
    $self->die("Serial $serial not issued by this CA") unless -f $file;
    
    if ($args->{confirm})
      {
	 $self->dumpcert($file);
	 $self->confirm("Really revoke this?","Bye...");
      }
    
    $args->{capass} = $self->getPassword("CA Private key password")
      unless $args->{capass};

    my $process = 
      $self->ca("-passin stdin -batch -crl_reason $reason -revoke $file",$args);
    $process->print("$args->{capass}\n");
    $process->closeok();
  }

sub issue
  {
    my $self = shift;
    my $args = shift;

    my $dir = $self->checkCA();
    
    $args->{type} = 'user' unless $args->{type};

    unless ($args->{csrfile}) 
      {
	$args->{csrfile} = $self->tempFile("request","csr");
	eval 
	  {
	    $self->request($args);
	    $args->{p12pass} = $args->{keypass};
	  };
	if ($@) 
	  {
	    $self->die("Unable to generate request: ".$self->exm($@));
	  }
      }
    
    $self->die("No csr file $args->{csrfile}")
      unless -f $args->{csrfile};
    
    eval
      {
	if ($args->{confirm})
	  {
	    $self->dumpreq($args->{csrfile});
	    $self->confirm("Really sign this?","Bye...");
	  }
	
	$self->warn("Signing request") unless $args->{verbose} > 1;
	
	my $serial;
	open SERIAL,"$dir/serial";
	chomp($serial = <SERIAL>);
	close SERIAL;
	
	$args->{capass} = $self->getPassword("CA Private key password")
	  unless $args->{capass};
  
        $args->{days} = 365 unless $args->{days};
	
	my $process = 
	  $self->ca("-batch -md $args->{digest} -days $args->{days} -passin stdin -preserveDN -outdir $dir/certs -in $args->{csrfile}",$args);
	$process->print("$args->{capass}\n");
	$process->closeok();
	rename $args->{keyfile},"$dir/private/keys/$serial.key";
	$self->unTempFile($args->{keyfile});
	$args->{serial} = $serial;
      };
    if ($@) 
      {
	$self->die("Unable to sign request: ".$self->exm($@));
      }
  }

sub export_pkcs12
  {
    my $self = shift;
    my $args = shift;

    my $dir = $self->checkCA();
    
    my $serial = $args->{serial};
    $self->die("Missing serial number") unless $serial;
    
    $args->{keypass} = $self->getPassword("Private key password")
      unless $args->{keypass};
    
    $args->{p12pass} = $self->getPassword("PKCS12 export password")
      unless $args->{p12pass};

    my $othercerts;
    if (-f "$dir/certpath.crt") 
      {
	$othercerts = "-certfile $dir/certpath.crt";
      }
    else 
      {
	$othercerts = "-certfile $dir/ca.crt";
      }
    
    my $certFile = $self->certFile($serial);
    my $keyFile = $self->keyFile($serial);
    $self->die("The private key of $serial is not on-line")
      unless -f $keyFile;
    $self->die("The certificate of $serial is not on-line")
      unless -f $certFile;

    eval 
      {
	mkdir "$dir/p12",00755 unless -d "$dir/p12";
	my $p12File = "$dir/p12/$serial.p12";
	my $process = 
	  $self->pkcs12("-export -des3 $othercerts -inkey $keyFile -in $certFile -out $p12File -passout stdin -passin stdin",$args);
	$process->print("$args->{keypass}\n");
	$process->print("$args->{p12pass}\n");
	$process->closeok();
      };
    if ($@)
      {
	$self->die("Unable to create pkcs12 object: ".$self->exm($@));
      }
  }

sub ppSubject
  {
    my $self = shift;
    my $dn = shift;
    
    my @rdns = split /\//,$dn;
    shift @rdns;
    foreach my $aname (keys %{$self->{alias}}) 
      {
	map { s/$aname/$self->{alias}->{$aname}/ig; } @rdns;
      }
    join(',',@rdns);
  }

sub getDN
  {
    my $self = shift;
    my $x = shift;
    my $args = shift;

    my $dn;
    
  SWITCH: 
    {
      $dn = $x,last SWITCH 
	if $x =~ /=/; ## probably a distinguished name
      
      $dn = $self->email2DN($1,$2,$args),last SWITCH 
	if $x =~ /([^@]+)\@([^@]+)/; ## probably an email address
      
      $dn = $self->domainName2DN($x,$args),last SWITCH 
	if $x =~/\./; ## probably a DNS domain name

      $self->die("Unknown name form: $x");
    }
    
    foreach my $av (split /\s*[,\/]\s*/,$dn)
      {
	$self->die("Bad X.501 name $dn") unless $av =~ /([a-zA-Z]+)\s*=\s*([^=]+)/;
	my $tmp = $1;
	$tmp =~ s/^\s+//og;
	$tmp =~ s/\s+$//og;
	next unless $tmp;
	$args->{name_attributes}->{$tmp}++;
      }

    $dn;
  }

sub email2DN
  {
    my $self = shift;
    my ($lp,$dp,$args) = @_;
    
    #my $attr = 'uid';
    #$attr = 'CN' if $lp =~ /[-\.\_]/;
    my $attr = 'CN';
    
    $args->{email} = "$lp\@$dp";

    return "$attr=$lp,".$self->domainName2DN($dp);
  }

sub domainName2DN
  {
    my $self = shift;
    my $dns = shift;
    my $args = shift;

    $dns =~ s/\.$//o;
    $args->{ip} = $dns;
    my @dn = split /\./,$dns;
    @dn = map { "dc=$_" } @dn;
    join(',',@dn);
  }

sub req
  {
    my $self = shift;
    
    CSP::OpenSSL->new($self,'req',@_);
  }

sub ca
  {
    my $self = shift;
    
    CSP::OpenSSL->new($self,'ca',@_);
  }

sub pkcs12
  {
    my $self = shift;
    
    CSP::OpenSSL->new($self,'pkcs12',@_);
  }

sub x509
  {
    my $self = shift;
    
    CSP::OpenSSL->new($self,'x509',@_);
  }

sub dumpcert
  {
    my $self = shift;
    my $certfile = shift;
    
    CSP::OpenSSL->new()->
      sopen($self,
	    'x509',
	    "-text -in $certfile -noout -nameopt RFC2253",
	    {noconfig=>1,verbose=>1})->closeok();
  }

sub dumpreq
  {
    my $self = shift;
    my $reqfile = shift;
    
    CSP::OpenSSL->new()->
      sopen($self,
	    'req',
	    "-text -in $reqfile -noout",
	    {noconfig=>1,verbose=>1})->closeok();
  }

sub exm
  {
    my $self = shift;
    my $ex = shift;

    $ex =~ s/\[CSP\]\[.+\]//og;
    $ex;
  }

sub certinfo
  {
    my $self = shift;
    my $certfile = shift;
    
    my (%info,$fh,$process);
    
    $process = CSP::OpenSSL->new()->ropen($self,'dummy',"x509 -noout -hash -in $certfile");
    $fh = $process->handle();
    $info{hash} = <$fh>;
    chomp $info{hash};
    $process->closedie;
    
    $process = 
      CSP::OpenSSL->new()->ropen($self,'dummy',"x509 -noout -serial -dates -subject -issuer -in $certfile");
    $fh = $process->handle();
    while (<$fh>)
      {
	chomp;
	if (/^subject=\s*(.+)/)
	  {
	    $info{subject}=$1;
	    $info{subject} =~ s/\//,/og;
	    $info{subject} =~ s/^,//og;
	    next;
	  }
	elsif (/^issuer=\s*(.+)/)
	  {
	    $info{issuer}=$1;
	    $info{issuer} =~ s/\//,/og;
	    $info{issuer} =~ s/^,//og;
	    next;
	  }
	elsif (/^notBefore=\s*(.+)/)
	  {
	    $info{notbefore}=$1;
	    next;
	  }
	elsif (/^notAfter=\s*(.+)/)
	  {
	    $info{notafter}=$1;
	    next;
	  }
	elsif (/^serial=\s*(.+)/) 
	  {
	    $info{serial}=$1;
	    next;
	  }
      }
    
    $process->closedie;
    
    $process =
      CSP::OpenSSL->new()->ropen($self,'dummy',"x509 -noout -md5 -fingerprint -in $certfile");
    $fh = $process->handle();
    while (<$fh>) 
      {
	chomp;
	$info{fingerprint_md5}=$1,next if /MD5 Fingerprint=(.+)/;
      }
    $process->closedie;

    $process = 
      CSP::OpenSSL->new()->ropen($self,'dummy',"x509 -noout -sha1 -fingerprint -in $certfile");
    $fh = $process->handle();
    while (<$fh>) 
      {
	chomp;
	$info{fingerprint_sha1}=$1,next if /SHA1 Fingerprint=(.+)/;
      }
    $process->closedie;
    
    \%info;
  }

package CSP::Stack; # just a context stack

sub new
  {
    my $self = shift;
    my $class = ref $self || $self;
    
    my @stack = @_;
    bless \@stack,$class;
  }

sub push
  {
    push @{$_[0]},$_[1];
  }

sub pop
  {
    pop @{$_[0]};
  }

sub doPrint
  {
    my @s = @{$_[0]};
    $_[0]->[$#s];
  }

package CSP::Entity; # Just a db object
@CSP::Entity::ISA = qw(CSP);

use Date::Calc qw(Day_of_Week);
use POSIX qw(strftime);

sub parse_date
  {
    my $str = shift;
    
    my ($y,$mon,$mday,$h,$m,$s) = $str =~ /([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$/;
    
    $y += 100;
    my $wday = Day_of_Week($y+1999,$mon,$mday);
    my @date = ($s,$m,$h,$mday,$mon,$y,$wday,0);
    \@date;
  }

sub new
  {
    my $self = shift;
    my $class = ref $self || $self;
    
    my $csp = shift;
    my $row = shift;
    my $getinfo = shift;
    my $getcontents = shift;
    
    my $serial = $row->[3];
    my $file = ($row->[4] && $row->[4] ne 'unknown' ? $row->[4] : $csp->certFile($serial));

    bless {
	   csp => $csp,
	   status => $row->[0],
	   expires => parse_date($row->[1]),
	   revoked => ($row->[2] ? parse_date($row->[2]) : undef),
	   serial => $serial,
	   file => $file,
	   subject => $csp->ppSubject($row->[5]),
	   info => ($getinfo ? $csp->certinfo($file) : {}),
	   getcontents => $getcontents
	  },$class;
  }

my %_status = ('V' => 'Valid','R' => 'Revoked');

sub info
  {
    $_[0]->{info}->{$_[1]};
  }

sub dump
  {
    my $self = shift;
    
    printf "%-8s: %s\n",'Serial',$self->{serial};
    my $status = $self->{status};
    printf "%-8s: %s\n",'Status',exists $_status{$status} ? $_status{$status} : "Unknown";
    printf "%-8s: %s\n",'Subject',$self->{subject};
    printf "%-8s: %s\n",'Expires',strftime("%a %b %e %H:%M:%S %Y",@{$self->{expires}});
    printf "%-8s: %s\n",'Revoked',strftime("%a %b %e %H:%M:%S %Y",@{$self->{revoked}}) if $self->{revoked};
    printf "%-8s: %s\n",'SHA1',$self->info('fingerprint_sha1') if $self->info('fingerprint_sha1');
    printf "%-8s: %s\n",'MD5',$self->info('fingerprint_md5') if $self->info('fingerprint_md5');
    if ($self->{getcontents}) 
      {
	$self->dumpcert($self->{file});
      }
    print "\n";
  }

package CSP::OpenSSL;
@CSP::OpenSSL::ISA = qw(CSP);

my $_unset=<<EOTXT;
***
The environment variable OPENSSL is not set. This
variable must contain the absolute path to the 
OpenSSL binary in order for CSP::OpenSSL to work
***
EOTXT

sub new
  {
    my $self = shift;
    my $class = ref $self || $self;

    local *FH;
    my $me = bless 
      { 
       fh=>*FH,
       openssl=>$ENV{OPENSSL} || die $_unset
      },$class;
    @_ > 0 ? $me->wopen(@_) : $me;
  }

sub DESTROY
  {
    $_[0]->closeok();
  }

sub ropen
  {
    my $self = shift;
    $self->rws_open('r',@_);
  }

sub wopen
  {
    my $self = shift;
    $self->rws_open('w',@_);
  }

sub sopen
  {
    my $self = shift;
    $self->rws_open('s',@_);
  }

sub handle
  {
    $_[0]->{fh};
  }

sub rws_open
  {
    my $self = shift;
    my $rw   = shift;
    my $scp  = shift;
    my $cmd  = shift;
    my $cmdline = shift;
    my $args = shift;

    my ($lp,$rp);
    if ($rw eq 'r')
      {
	$lp = '';
	$rp = '|';
      }
    elsif ($rw eq 'w')
      {
	$lp = '|';
	$rp = '';
      }

    my $cfgcmd;
    if ( (grep $_ eq $cmd,qw(req ca)) && !$args->{noconfig})
      {
	$self->{conf}  = $scp->writeConfig($cmd,$args);
	$scp->die("Unable to write configuration file") unless -f $self->{conf};
	$cfgcmd = " -config $self->{conf} ";
      }
    elsif ($cmd eq 'x509' && !$args->{noconfig}) 
      {
	$self->{conf}  = $scp->writeConfig($cmd,$args);
	$scp->die("Unable to write configuration file") unless -f $self->{conf};
	$cfgcmd = " -extfile $self->{conf} -extensions extensions ";
      }
    $self->{csp} = $scp;

    $cmd = '' if $cmd eq 'dummy';

    my $redirect = ($args->{verbose} == 0 && $rw ne 'r' ? ">/dev/null 2>&1" : "");
    warn "${lp}$self->{openssl} $cmd $cfgcmd $cmdline ${redirect}${rp}"
      if $ENV{CSPDEBUG};
    if ($rw eq 's')
      {
	$self->{rc} = system("$self->{openssl} $cmd $cfgcmd $cmdline ${redirect}");
      }
    else
      {
	open $self->{fh},"${lp}$self->{openssl} $cmd $cfgcmd $cmdline ${redirect}${rp}" or
	  $scp->die("Unable to execute: $!");
      }

    $self;
  }

sub close
  {
    my $self = shift;

    close $self->{fh} if defined $self->{fh};
    unless ($ENV{CSPDEBUG}) 
      {
	unlink $self->{conf} if $self->{conf};
      }
    (defined $_[0]->{rc} ? $_[0]->{rc} : $?);
  }

sub closedie
  {
    $_[0]->close() == 0 or $_[0]->{csp}->die("$!");
  }

sub closeok
  {
    $_[0]->close() == 0;
  }

sub print
  {
    my $self = shift;
    print {$self->{fh}} @_;
  }

package CSP;

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

CSP - A wrapper around OpenSSL for maintaining multiple Certificate Authorities.

=head1 SYNOPSIS

  # csp help

=head1 DESCRIPTION

CSP is a perl module which uses openssl (openssl version 0.9.6 or later is required). 
Features include

=over 4

=item o

CSP leaves subject naming policy to the user. No checks are made on the attribute
names in the subject. This is good if you don't like being asked a lot of questions
when issuing certificates.

=item o

Configuration is reduced to specification of extensions. This is simplified
using a simple CPP/MPP-type macro interpreter in CSP.

=item o

CSP is designed to easily handle multiple distinct Certificate Authorities.
Hence the name which stands for Certificate Service Provider.

= item o

CSP can be used to produce a web site (certificate repository, CRLs etc etc)
without the need for cgi-scripts.

= item o
 
CSP tries to be as PKIX-compliant as OpenSSL allows.

=back

=head1 CSP IN PRACTICE

The typical application for CSP is a small CA (which may or may not be part
of a larger pki) issuing mainly server and object signing certificates and only
few if any user certificates. The distinction between user and other certificates
may seem arbitrary but experience shows that managing a large set of user 
certificates typically requires a more sofisticated system for managing and
tracking requests.

When setting up CSP for production use the author strongly recommends using a
non network connected host for the CA operations. This computer will not use
much CPU or disk resources and any old PC with Linux or *BSD should work
admirably. An old laptop might be a very good choice since it can be locked
away when not in use. It might be a good idea to equip the computer with a cd 
writer or some other means for making backups of the certificate directory. 
Day to day operations include the following tasks.

= over 4

= item 1

Issuing certificates based on pkcs10 or out-of-band (non pkcs10) requests.

= item 2

Backing up the csp main directory (see below) to read-only medium.

= item 3

Producing the public web site and exporting it (typically using floppy or
zip-drive) to your web server.

= back

=head1 CONFIGURATION

First set the environment variable OPENSSL to contain the absolute path of your
OpenSSL binary. This is a requirement for everything that follows. Next create a
directory where you will keep your CAs. This can be any directory anywhere in your
file system owned by anyone. A sample directory "ca" in the distribution is included 
as a reference. A good way to get started is to copy this directory somewhere. Set
$CSPHOME to point to this directory. The layout of this directory is as follows:

 .
 |-- csp                  Certificate Authorities directory
 `-- etc                        
     |-- aliases.txt          Alternative names for DN attributes
     |-- extensions.conf      Default certificate extensions file
     |-- crl_extensions.conf  Default crl extensions
     |-- oids.conf            Extra OIDs (eg attribute types).
     |-- public_html          Default web site template files
     `-- types.txt            List of certificate types to support

Most of these files are defaults that are copied to each new CA when created. This
means that if you need defaults used by all CAs you create you must make those edits
first of all.

The oids.conf and aliases.txt should be edited to include support for any extra
attribute types your CA systems must support. The format of these files should be
obvious. The oids.conf includes support for the DC attribute.

Next edit extensions.conf. This file is a default file which is copied to each new
CA. Before you create your first CA edit this file to reflect extensions and defaults
for all CAs created in this directory. The format of this file is explained in the
EXTENSIONS section. Also edit the crl_extensions.conf to include support for any crl
extensions you might need. Remember that after you create a CA you must edit the local
copy of these files to reflect the requirements of that particular CA.

Finally edit the files in public_html. The structure of this directory is explained in
more detail in the section WEBSITE below.

You are now ready to create your first CA. If this is a self-signed CA creation is done
in two steps: First create the directories and copy the configuration files. The first
argument "PCA" is a name of the CA in our example. Creation of the CA "PCA" is done using
the command "csp create".

 [leifj@njal CSP]$ ./csp PCA create

Next initialize "PCA". The last argument is the distinguished name of the CA. CSP does
not impose any limit on names which means that you can get away with any DN as long as
your oids.conf and aliases.txt include aliases and oids for the attribute types.

 [leifj@njal CSP]$ ./csp PCA init --keysize=2048 \
                   --days=2190 'CN=CA,dc=example,dc=com'
 [CSP][PCA     ] Generating CA key
 [CSP][PCA     ] Private key password: <...>
 [CSP][PCA     ] Re-enter Private key password: <...>
 [CSP][PCA     ] Successfully created CA PCA

List the contents of this certificate provider:

 [leifj@njal CSP]$ ./csp --list
 PCA

Use openssl to dump the contents of the CA certificate:

 [leifj@njal CSP]$ csp PCA dump

 ... stuff deleted ...

Now issue a new server certificate signed by PCA:

 [leifj@njal CSP]$ ./csp PCA issue \
                     --keysize=1024 \
                     --noconfirm \
                     'CN=www.example.com,dc=example,dc=com'
 [CSP][PCA     ] Generating new key
 [CSP][PCA     ] Private key password: <...>
 [CSP][PCA     ] Re-enter Private key password: <...>
 [CSP][PCA     ] Create certificate request for CN=CA,dc=su,dc=se
 [CSP][PCA     ] Signing request

Check the contents of PCA database (the --xinfo arg gives you 
the sha1 and md5 fingerprints)

 [leifj@njal CSP]$ ./csp PCA list --xinfo
 Serial  : 01
 Status  : Valid
 Subject : CN=www.example.com,dc=example,dc=com
 Expires : Wed Oct 10 10:28:32 2001
 SHA1    : A3:53:D7:DF:AE:A2:44:0A:0F:B8:29:31:E7:96:16:62:1F:52:DF:62
 MD5     : 04:2A:3A:1B:BB:B9:1E:08:4D:C3:14:CE:71:72:CC:86

Finally generate the public web site

 [leifj@njal CSP]$ mkdir /tmp/export
 [leifj@njal CSP]$ ./csp PCA genpublic --export=/tmp/export

Now move /tmp/export to a removable medium and transport it to your web server.

=head1 EXTENSIONS

Configuration of extensions is done in the etc/<ca name>extensions.conf. The
format of this file is equivalent to the openssl extensions format. Read more
about this in the openssl documentation.
This file also supports a simple macro format similar to transarc mpp which in 
turn is essentially CPP with '%' as the magic character. The following macros 
are supported:

 %ifdef/%endif
 %if/%endif
 %include

The predicate in the %if macro can be almost any perl expression where macro
%-expansion replaces perl variable expansion.

=head1 WEB SITE

The directory public_html in each CA directory contains template files (MPP macro
expansion is applied to these files) for a public web site. The included example
has the following organization

  public_html
  |-- certs
  |   |-- cert.html.mpp
  |   |-- expired.html.mpp
  |   |-- index.html.mpp
  |   |-- revoked.html.mpp
  |   |-- valid.html.mpp
  `-- index.html.mpp

The csp command "csp genpublic" will produce a directory in the
export directory (specified by --export) which looks like this:

  <export>
  |-- ca.crt
  |-- certs
  |   |-- 01.crt
  |   |-- 01.html
  |   |-- 01.pem
  |   |-- expired.html
  |   |-- index.html
  |   |-- revoked.html
  |   `-- valid.html
  |-- crl-v1.crl
  |-- crl-v2.crl
  `-- index.html

The ca.crt, crl-v1.crl and crl-v2.crl are copies of the corresponding 
files from the master repository. Each certificate in the repository
is stored in <export>/certs as DER, PEM and as an HTML page derived
from public_html/certs/cert.html.mpp by macro expansion. All other 
pages are simply produced by macro expansion of the corresponding 
.mpp-files and apart from certs/cert.html.mpp none of these files need
exist or have the names they have in the example above.

When performing macro expansion on public_html/certs/cert.html.mpp 
the following variables are available:

  DATE              The date (using localtime(time)) of 
                    the export operation.
  SUBJECT_SERIAL    The serial number of the certificate.
  SUBJECT_DN        The distinguished name (DN) of the 
                    certificate.
  ISSUER_DN         The distinguished name (DN) of the 
                    CA certificate.
  SUBJECT_SHA1      The SHA1-fingerprint of the 
                    certificate.
  SUBJECT_MD5       The MD5-fingerprint of the 
                    certificate.
  SUBJECT_NOTBEFORE The date when this certificate 
                    becomes valid.
  SUBJECT_NOTAFTER  The date when this certificate 
                    expires.

When all other files in the directories (public_html and public_html/certs)
are run through the macro preprocessor to produce HTML files the
following variables are available:

  DATE               The date (using localtime(time)) of 
                     the export operation.
  VALID              An HTML table of valid certificates.
  VALID_COUNT        The number of valid certificates.
  REVOKED            An HTML table of revoked certificates.
  REVOKED_COUNT      The number of revoked certificates.
  EXPIRED            An HTML table of expired certificates.
  EXPIRED_COUNT      The number of expired certificates.
  SUBJECT_SERIAL     The serial number of the CA certificate.
  SUBJECT_NOTAFTER   The date when the CA certificate 
                     expires.
  SUBJECT_NOTBEFORE  The date when the CA certificate 
                     became valid.
  SUBJECT_DN         The distinguished name (DN) of the 
                     CA certificate.
  SUBJECT_MD5        The MD5-fingerprint of the CA 
                     certificate.
  SUBJECT_SHA1       The SHA1-fingerprint of the CA 
                     certificate.

=head1 AUTHOR

Leif Johansson <leifj@it.su.se>
Stockholm University

=head1 ACKNOWLEDGEMENTS

The web site generation was inspired by work by 
Heinar Hillbom <Einar.Hillbom@umdac.umu.se> UMDAC, Ume? Universitet

=head1 SEE ALSO

perl(1), openssl(1).

=cut
