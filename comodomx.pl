#!/usr/bin/perl
# Comodo.pl
# Content-filter for the Postfix MTA which submit attached documents to a
# Comodo instance for automatic analysis.
#
# Copyright (C) 2012 Xavier Mertens <xavier(at)rootshell(dot)be>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# 3. Neither the name of copyright holders nor the names of its
# contributors may be used to endorse or promote products derived
# from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL COPYRIGHT HOLDERS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# History
# -------
# 2012/06/20	First release
# 2012/07/03	Added processing of URLs inside the body
# 2012/07/04	Added libmagic support for better detection of files
#

use Term::ReadLine;
use Shell::Perl;
use Text::Template;
use Text::CSV qw( csv );
use File::chmod;
use IO::File;
use File::umask;
use File::Path;
use CPAN::Mini::Inject;
use Archive::Extract;
use Archive::Any;
#use Archive::Rar;
#use HTML::Base:Header:
#use Mail::ClamAV;
#use Mail::Message::Attachment::Stripper;
use Regexp::Common;
use Perl::PrereqScanner;
use Email::MIME::Attachment::Stripper;
use Email::Store::Attachment;
use Finance::Quote;
use Comodo::DCV;
use Archive::SevenZip;
use DBI;
use Digest::MD5;
use File::LibMagic;
use File::Path qw(make_path remove_tree);
use File::Temp;
use MIME::Parser;
use Sys::Syslog;
use URI::Find;
use XML::XPath;
use XML::XPath::XMLParser;
use strict;
use warnings;
#use Parse::YARA;

# Postfix must receive one of the following code in case
# of problems. We do NOT use die() here!
use constant EX_TEMPFAIL	=> 75;  # Mail sent to the deferred queue (retry)
use constant EX_UNAVAILABLE	=> 69;	# Mail bounced to the sender (undeliverable)

# ----------------------------------------------------------
# Default Configuration (to be configured via comodomx.conf)
# ----------------------------------------------------------
my $user            = "comodo";
my $syslogProgram	= "comodo";
my $configFile		= "/opt/COMODO/CCS/etc/comodomx.conf";
my $sendmailPath	= "/usr/sbin/sendmail";
my $syslogFacility	= "mail";
#my $cuckooDB		= "/opt/COMODO/CCS/db/";
my $cuckooDir		= "/opt/COMODO/CCS/";
#my $cuckooVM		= "comodo";
my $outputDir		= "/opt/COMODO/CCS/tmp/"; # Temporary directory based on our PID
my $notifyEmail		= "postmaster\@medinova.com.tr";
my $processZip		= 1;
my $processRar		= 1;
my $processUrl		= 0;
my $processArchive	= 1;
my $me              = 1;
my $file            = 1;
my $scanner         = "/opt/COMODO/CCS/cmdscan";
my $virustotal      = "/tmp/clamtotal/multi-scan.sh";

# turns on the execute bit for all users on those two files
$File::chmod::UMASK = 0;
chmod(0777, owner=>'comodo', group=>'comodo', $outputDir);


# Define the file types to ignore
# By default, we don't care about plain text, HTML files and images.
my @suspiciousFiles;
my @suspiciousURLs;
my @ignoreMimes;
my @ignoreURLs;

# Read running parameters
#if (!readConfigFile($configFile)) {
#	syslogOutput("Cannot load configuration from $configFile");
#	exit EX_TEMPFAIL;
#}

# Create our working directory
$outputDir = $outputDir . '/' . $$;
use strict 'subs';
sub slurp {
    my $outputDir = IO::File->new("params.inc","<") or die $!;
    restore_parameters("$outputDir" , { mode => 0777 } , { owner => 'comodo' } , { group => 'comodo' });
    $outputDir->close();
}
if (! -w $outputDir && !make_path("$outputDir" , { mode => 0777 })) {
	syslogOutput("mkdir +rw ($outputDir) failed: $!");
	exit EX_TEMPFAIL;
}

# Save the mail from STDIN
if (!open(OUT, ">$outputDir/content.tmp")) {
	syslogOutput("+rw \"$outputDir/content.tmp\" failed: $!");
	exit EX_TEMPFAIL;
}
while(<STDIN>) {
	print OUT $_;
}
close(OUT);

# Save the sender & recipients passed by Postfix
if (!open(OUT, ">$outputDir/args.tmp")) {
	syslogOutput("+rw \"$outputDir/args.tmp\" failed: $!");
	exit EX_TEMPFAIL;
}
foreach my $arg (@ARGV) {
	print OUT $arg . " ";
}
close(OUT);

# Extract MIME types from the message
my $parser = new MIME::Parser;
my $archive = new Archive::Any;
$parser->output_dir($outputDir);
my $entity = $parser->parse_open("$outputDir/content.tmp");

### build an Archive::Extract object ###
use Archive::Extract;
use File::Spec::Functions;
#my $processArchive = Archive::Extract->new( archive => '$outputDir/quarantine/' . '/unzipped-by-Archive-Extract' ); /sonra  bakarız

###
sub dump_entity {
  my ($entity) = @_;
  my $IO;
  my $not_first_part = 0;
  
  # Print the header, converting accents if any
  my $head = $entity->head->original_text;
  $head =~ s/^(Subject:.*)/no_iso_markup($1)/me
    if $head =~ /^Subject:.*=\?iso-8859-1\?Q\?/mi;
  print $head, "\n";
  
  # Output the body:
  my @parts = $entity->parts;
  if (@parts) {            # multipart...
    my $i;
    foreach $i (0 .. $#parts) { # dump each part...
      dump_entity($parts[$i]);
    }
  } else {            # single part...
    # Get MIME type, and display accordingly...
    my ($type, $subtype) = split('/', $entity->head->mime_type);
    #print STDERR "type - $type\n";
    
    my $body = $entity->bodyhandle;
    my $path = $body->path;
    if ($type =~ /^(text|message)$/ || -T $path) {     # text: display it...
      if ($IO = $body->open("r")) {
    print "\n" if $not_first_part++;
    print to_ascii($_) while (defined($_ = $IO->getline));
    $IO->close;
    
    # If message is text/message, chances that we did the right
    # thing are extremely high. So unlink the message if lying on
    # the disk... -- RAM, 19/11/96

    #unlink($path) or warn "$me: can't unlink $path: $!\n"
    #  if defined $path && -f $path;
    
      } else {            # d'oh!
    die "$me: couldn't find/open '$file': $!";
      }
    } else {            # binary: just summarize it...
      my $size = ($path ? (-s $path) : '???');
      print ">>> This is a non-text message, $size bytes long.\n";
      print ">>> It is stored in ", ($path ? "'$path'" : 'core'),".\n\n";
    }
  }
  print "\n";
  
  1;
}

#------------------------------------------------------------
# smart_pack
#------------------------------------------------------------
sub smart_pack {
  my ($hexa) = @_;
  my $val = hex($hexa);
  return "=$hexa" if $val >= 128; # We're smart right there!
  return pack('C', $val);
}

#------------------------------------------------------------
# no_accent
#------------------------------------------------------------
sub no_accent {
  local ($_) = @_;
  tr/\xab\xbb\xe0\xe2\xe7\xe8\xe9\xea\xee\xef\xf4\xf9\xfb/""aaceeeiiouu/;
  return $_;
}

#------------------------------------------------------------
# to_txt -- combines =xx packing with no_accent()
#------------------------------------------------------------
sub to_txt {
  my ($l) = @_;
  $l =~ s/=([\da-fA-F]{2})/pack('C', hex($1))/ge;
  return no_accent($l);
}

#------------------------------------------------------------
# no_iso_markup -- removes ugly ?iso-8859-1?Q escapes
#------------------------------------------------------------
sub no_iso_markup {
  local ($_) = @_;
  s/^(.*?)=\?iso-8859-1\?Q\?(.*)\?=/$1 . to_txt($2)/ie;
  s/_/ /g;
  return $_;
}

#------------------------------------------------------------
# unquote_stdin
#------------------------------------------------------------
sub unquote_stdin {
  local $_;
  my $encoded = 0;
  my $in_header = 1;
  while (<STDIN>) {
    $in_header = 0 if /^\s*$/;
    
    # All Subject: line with accents to be "un-mimed" as well.
    s/^(Subject:.*)/no_iso_markup($1)/e
      if $in_header && /^Subject:.*=\?iso-8859-1\?Q\?/i;
    
    # Avoid decoding inlined uuencoded/btoa stuff... since they might
    # accidentally bear valid =xx escapes... The leading \w character
    # is there in case the thing is shar'ed...
    # Likewise, all the lines longer than 60 chars and with no space
    # in them are treated as being encoded iff they begin with M.

    $encoded = 1 if /^\w?begin\s+\d+\s+\S+\s*$/ || /^\w?xbtoa Begin\s*$/;
    $encoded = 0 if /^\w?end\s*$/ || /^\w?xbtoa End/;
    
    if ($encoded || (length > 60 && !/ / && /^M/)) {
      print $_;
    } else {
      # Can't use decode_qp from MIME::QuotedPrint because we might not
      # face a real quoted-printable message...
      # Inline an alternate  version.
      
      s/\s+(\r?\n)/$1/g;    # Trailing white spaces
      s/^=\r?\n//;        # Soft line breaks
      s/([^=])=\r?\n/$1/;    # Soft line breaks, but not for trailing ==
      s/=([\da-fA-F]{2})/smart_pack($1)/ge;    # Hehe
      print to_ascii($_);
    }
  }
  return 1;    # OK
}

# Us only the Perl5 scanner:
#my $vt = Shell::Perl->run_with_args;

#------------------------------------------------------------
# main
#------------------------------------------------------------

sub main {
  return &unquote_stdin;
  # Create a new MIME parser:
  my $parser = new MIME::Parser;
  
  # Create and set the output directory:
  $parser->output_dir($outputDir);
  
  # Read the MIME message:
  $entity = $parser->read(\*STDIN) or
    die "$me: couldn't parse MIME stream";
  
  # Dump it out:
  dump_entity($entity);
  unlink<$outputDir/msg-*.txt> or warn "can't unlink: $!\n";
}

deliverMail();
exit 0;
 
#The following acts on a DER-formatted (i.e., binary) CSR only.
$parser->output_dir($outputDir);
my ($filename, $contents) = Comodo::DCV::get_filename_and_contents( "$outputDir/comodo.txt" );

#The following acts on a Finance::Quote.
#$parser->output_dir($outputDir);
#my ($filename, $contents) = Finance::Quote::get_filename_and_contents( "$outputDir/$filename" );

# Extract sender and recipient(s)
my $headers = $entity->head;
my $from = $headers->get('From');
my $subject = $headers->get('Subject');
chomp($from);
chomp($subject);

# Step 1 : Extract URLs from content (optional)
($processUrl) && processURLs("$outputDir/content.tmp");

	deliverMail();
exit 0;

#
# getPackage	Use File::LigMagic to guess the file type
#		and return the right analysis package
#
# Input:	$f - Path of file to analyze
# Output:	Package name or empty string if not supported
#
sub getPackage {
	my $f = shift || return("");
	my $flm = File::LibMagic->new();
	my $b = $flm->describe_filename("$f");
	if ( $b =~ /Microsoft [Office ]*PowerPoint/i ) {
		return("ppt");
	}
	elsif ( $b =~ /Microsoft [Office ]*Excel/i ) {
		return("xls");
	}
	elsif ($b =~ /Microsoft [Office ]*Word/i ||
	    $b =~ /Composite Document File V\d Document/i	 ||
	    $b =~ /Rich Text Format/i) {
		return("doc");
	}
	elsif ( $b =~ /PDF Document/i) {
		return("pdf");
	}
	elsif ( $b =~ /HTML document/i) {
		return("firefox");
	}
	elsif ( $b =~ /PHP script/i) {
		return("php");
	}
	elsif ( $b =~ /diff output/i) {
		return("");
	}
	else {
		# Default package
		return("exe");
	}
}


# processMIMEParts
# 

sub processMIMEParts
{
	my $entity = shift || return;
	for my $part ($entity->parts) {
		if($part->mime_type eq 'multipart/alternative' ||
		   $part->mime_type eq 'multipart/related' ||
		   $part->mime_type eq 'multipart/mixed' ||
		   $part->mime_type eq 'multipart/signed' ||
		   $part->mime_type eq 'multipart/report' ||
		   $part->mime_type eq 'message/rfc822' ) {
			# Recursively process the message
			processMIMEParts($part);
		}
		else {
			my $type = lc  $part->mime_type;
			my $bh = $part->bodyhandle;
			syslogOutput("Dumped: \"" . $bh->{MB_Path} . "\" (" . $type . ")");
			# Ignore our trusted MIME-types
			if (!grep {$_ eq $type} @ignoreMimes) {
				# Uncompress ZIP archives
				if ($type eq "application/zip" && $processZip) { 
					my $ae = Archive::Extract->new( archive => $bh->{MB_Path});
					my $zip = $ae->extract(to => $outputDir);
					if (!$zip) {
						syslogOutput("Cannot extract files from \"" . $bh->{MB_Path} . "\": $!");
						exit EX_TEMPFAIL; 
					}
					foreach my $f ($ae->files) {
						push(@suspiciousFiles, $outputDir . "/" . $f->[0]);
					}
				}
				# *** TODO ***
				# elsif ($type eq "application/x-rar" && $processRar)) {
				# 	my $rar = new Archive::Rar();
				# 	$rar->Extract(-archive => $bh->{MB_Path}
				# }
				# else {
				else {
					push(@suspiciousFiles, $bh->{MB_Path});
				}
			}
		}
	}
	return;
}

#
# processURLs
#

sub processURLs {
	my $content = shift || return;
	syslogOutput("DEBUG: processURLs($content)");
	my $buffer;
	if (! open(IN, "<$content")) {
		syslogOutput("processURLs: Cannot read $content: $!");
		exit EX_UNAVAILABLE;
	}
	while(<IN>) { $buffer = $buffer . $_; }
	close(IN);

	# Reformat text 
	$buffer =~ s/=\n//g;    # Remove trailing "="

	my $finder = URI::Find->new(
			sub {
				my $u = shift;
				my $matchExclude = 0;
				if ($u =~ /^http[s]*:\/\//) { # Process only HTTP(S) URI
					if (!($u =~ /\.(jpg|jpeg|png|gif)$/i)) { # Ignore common pictures & files
						foreach my $iu (@ignoreURLs) {
							($u =~ /$iu/i) && $matchExclude++;
						}
						if (!$matchExclude && 
						    !(grep /$u/, @suspiciousURLs)) {
							# URLs not excluded and not already found -> save it
							push(@suspiciousURLs, $u);
						}
						#else {
						#	syslogOutput("DEBUG: Exclude: $u");
						#}
					}
				}
				#else {
				#	syslogOutput("DEBUG: Ignoring URI: $u");
				#}
			}
		     );
	$finder->find(\$buffer);
	return; 
}

#

#
# submitFile
#
sub submitFile {
	my $file = shift || return;
	my $dbh  = shift || return;

	# Compute MD5 hash
	if (!open(FILE, "$file")) {
		syslogOutput("Open \"$file\" failed: $!");
		exit EX_TEMPFAIL;
	}
	binmode(FILE);
	my $md5Digest = Digest::MD5->new->addfile(*FILE)->hexdigest;
	close(FILE);
	return; 
}

#
# submitURL
#
sub submitURL {
	my $url = shift || return;
	my $dbh = shift || return;

	my $buffer = "[InternetShortcut]\r\nURL=$url\r\n";
	# Generate the MD5 hash and search the database to avoid
	# duplicate URLs
	my $md5Digest  = Digest::MD5->new->add($buffer)->hexdigest;
	my $row = $dbh->selectrow_arrayref("SELECT md5 FROM tasks where md5=\"$md5Digest\"");
	if (!$row) { # MD5 not found, submit the URL
		$url =~ /http[s]*:\/\/((\w|\.)+)/;
		my $prefix = $1;
		$prefix =~ tr/\./\-/;
		my $tmpFile = File::Temp->new( TEMPLATE => $prefix .'_XXXXXXXXXXXXXXXX',
					       DIR => "$outputDir",
					       SUFFIX => '.url',
					       UNLINK => '0' );
		syslogOutput("DEBUG: Creating tempfile $tmpFile");
		if (!open(TF, ">$tmpFile")) {
			syslogOutput("Cannot create file $tmpFile: $!");
			exit EX_TEMPFAIL;
		}
		print TF $buffer;
		close(TF);

		syslogOutput("DEBUG: Submit URL: \"$url\"");
		#$dbh->do("INSERT INTO tasks \
		#	(file_path, md5, timeout, package, priority, custom, machine) \
		#	VALUES (\"$tmpFile\", \"$md5Digest\", NULL, \"firefox\", NULL, \
		#	NULL, \"$cuckooVM\")");
		if ($DBI::errstr) {
			syslogOutput("Cannot submit URL: " . $DBI::errstr);
			exit EX_TEMPFAIL;
		}
	}
	else {
		syslogOutput("\"$url\" already submitted (MD5: $md5Digest)");
	}
}



#
# deliverMail - Send the mail back
#
sub deliverMail {
	# Read saved arguments
	if (! open(IN, "<$outputDir/args.tmp")) {
		syslogOutput("deliverMail: Cannot read $outputDir/args.tmp: $!");
		exit EX_UNAVAILABLE;
	}
	my $sendmailArgs = <IN>;
	close(IN);
	
	# Read mail content
	if (! open(IN, "<$outputDir/content.tmp")) {
		syslogOutput("deliverMail: Cannot read $outputDir/content.txt: $!");
		exit EX_UNAVAILABLE;
	}
	
	# Spawn a sendmail process
	if (! open(SENDMAIL, "|$sendmailPath -G -i $sendmailArgs")) {
		syslogOutput("deliverMail: Cannot spawn: $sendmailPath $sendmailArgs: $!");
		exit EX_TEMPFAIL;
	}
	while(<IN>) {
		print SENDMAIL $_;
	}
	close(IN);
	close(SENDMAIL);
	return 1;
}

