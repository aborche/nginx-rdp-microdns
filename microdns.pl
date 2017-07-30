#!/usr/local/bin/perl -w
# 
# !!!!!!!!!!!!!!!!!!!!!!!!!!! Unstable !!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
# Aborche (C) 2017. Email: zhecka@gmail.com

#use POSIX ":sys_wait_h";
use IO::Multiplex;
use strict;
use IO::Socket;
#use Digest::HMAC_SHA1 qw(hmac_sha1);
use Sys::Syslog;
use Cache::Memcached;

use vars qw/
  $config $sock $sockres $PORTNO $PORTNOres
  $HEADERLEN $PACKETSZ $MAXLEN $QR_MASK $OP_MASK $AA_MASK $TC_MASK $NOTIMP $NOERROR $FORMERR $NOSUCHNAME $RCODE
  %conf $sesslog $delim $loopcount $errorcode $countrec $memd
/;
#  $errorcode $countrec %ttlh %count $white $black $zonemap $delim $wlmtime %hr_types %conf
#  $sessionmap $greylistmap $statusmap $commonmap $loopcount %pfban %pfsock $banip %banaction $domaincontrol
#  $PFTBLVERSION $PFTBLCOMMAND $PFTBLMASK $PFTBLNAME $PFTBLPORT $banned $sesslog $lastqueue $queuelist
#  %Kid_Status %white %trust $timelimit $countlimit $wlmtime 

%conf = { 'daemon' => 0, 'debug' => 1, };
$sesslog = "/var/log/microdns.log";

$delim = ':';
$loopcount = 0;
openlog("fastbl","ndelay");

#$SIG{INT} = $SIG{QUIT} = $SIG{TERM} = $SIG{STOP} = \&quit;

$memd = new Cache::Memcached {
        'servers' => [ "localhost:11211" ],
        'debug' => 0,
      };

#$memd->set("127.1.1.5", "5.1.1.127");
#$memd->set("127.1.1.6", "6.1.1.127");

$SIG{HUP} = sub {
  close SESSLOG;
  open SESSLOG,">$sesslog" or die "cannot open logfine $!";
  SESSLOG->autoflush(1);
};

$HEADERLEN = 12;
$PACKETSZ = 512;
$MAXLEN = 1024;
$PORTNO = 531;
$PORTNOres = 554;
$QR_MASK = 0x8000;
$OP_MASK = 0x7800;
$AA_MASK = 0x0400;
$TC_MASK = 0x0200;
$NOTIMP = 4;
$NOERROR = 0;
$NOSUCHNAME = 3;
$FORMERR = 1;

print "Awaiting UDP messages on port $PORTNO and $PORTNOres\n";

$sock = IO::Socket::INET->new(LocalPort => $PORTNO, Proto => 'udp')
    or die "socket: $@";

if(!$conf{daemon})
{
  my $mux = new IO::Multiplex;
  $mux->add($sock);
  $mux->set_timeout($sock, 10);
  $mux->set_callback_object(__PACKAGE__);
  $mux->loop;
  exit(0);
  closelog();
}
else
{
  if(fork)
    {
      exit(0);
    }
  else
    {
      open FH,">/var/run/microdns.pid";
      print FH $$;
      close FH;
#      if($conf{sessionlog})
#      {
        open SESSLOG,">$sesslog";
        SESSLOG->autoflush(1);
#      }
      my $mux = new IO::Multiplex;
      $mux->add($sock);
      $mux->add($sockres);
      #$mux->listen($sock);
      #$mux->add(\*STDIN);
      #$mux->add(\*STDOUT);

      $mux->set_timeout($sock, 10);
      $mux->set_callback_object(__PACKAGE__);
      $mux->loop;
#      if($conf{sessionlog})
#      {
        close SESSLOG;
#      }
      exit(0);
      closelog();
    }
}
exit(0);

sub mux_input {
  my $package = shift;
  my $mux = shift;
  my $fh = shift;
  my $input = shift;
  
  if($fh == $sock)
  {
  my $reply = &depack_packet($$input);
    if ($reply)
        {
        my $saddr = $mux->{_fhs}{$sock}{udp_peer};
        send($sock, $reply, 0, $saddr) or die "handle_udp_req: send: $!";
        }
  }
  else
  {
   die "$$: Not my fh?";
  }
  $$input = '';
}

sub mux_close
{
  print STDERR "Connection Closed\n";
  exit;
}

sub mux_timeout
{
  my $self    = shift;
  my $mux     = shift;
  my $fh      = shift;
  $mux->set_timeout($fh,20);
  $loopcount++;
  if($loopcount >= 90)
  {
    $loopcount = 0;
    &slog('-------Flushing all expired data');
  }
}

#$SIG{CHLD} = \&REAPER;

sub ipvalid
{
  my $ip=shift;
  if($ip !~ /[^0-9\.]/)
  {
   return 1 if(inet_aton($ip));
  }
  return undef;
}

sub make_expire_time
{
  my $expire_time = shift || '';
  my %Times = ('' => 1, s => 1, m => 60, h => 60*60, d => 24*60*60, w => 7*24*60*60);
  return $expire_time =~ /^(\d+)\s*([mhdws]?)/i ? $1 * $Times{$2} : 0;
}

sub check_rdp_zone
{
  my $residual = shift;
  my $reslen = length($residual);
  $residual =~ s/.rdp.local$//;
  my $ip = '';

  ($ip,$residual) = split (/$delim/o,$residual,2);

  if(!ipvalid($ip))
    {
#        &slog("SQL::ERROR::IP::$ip::HST::$residual");
        $errorcode = 0x7f0000FF;
        $countrec+=1;
        return 0;
    }

  my $lookup = $memd->get($ip)//'127.0.0.1';

  $errorcode = hex(unpack('H*',inet_aton($lookup)));
  $countrec+=1;
  &log("request ip $ip $errorcode\n");
  return 0;
}

sub create_answer
{
  my($ttl,$retcode) = @_;
  my $rdata = pack('N',$retcode);
  return pack('n', 0xc00c) . pack('nnNna*', 1, 1, $ttl, length $rdata, $rdata);
}

sub log
{
  my $data = shift;
  syslog("info|local6",$data);
}

sub slog
{
  return 0 if(!$conf{sessionlog});
  my $data = shift;
  print SESSLOG $data,"\n";
}


# deaggreate int range block to cidr
sub deaggregate
{
  my $start = shift;
  my $end   = shift;
  my $base = $start;
  my $step = 0;
  my $thirtytwobits = 4294967295;
  while (($base | (1 << $step))  != $base)
    {
      if (($base | (((~0) & $thirtytwobits) >> (31-$step))) > $end)
      {
        last;
      }
      $step++;
    }
  return IntToIP($base)."/" .(32-$step);
}

# transcoding Integer value to IP
sub IntToIP
{
    return join ".",unpack("CCCC",pack("N",shift));
}

sub dn_expand {
# Expand dns message
    my ($msg, $offset) = @_;

    my $cp       = $offset;
    my $result   = '';
    my $comp_len = -1;
    my $checked  = 0;

    while (my $n = ord(substr($$msg, $cp++, 1))) {
        if (($n & 0xc0) == 0) {
            $checked += $n + 1;
            $result .= '.' if $result;
            while (--$n >= 0) {
                my $c = substr($$msg, $cp++, 1);
                $result .= ($c ne '.') ? $c : '\\';
            }
        } elsif (($n & 0xc0) == 0xc0) {  # pointer, follow it
            $checked += 2;
            return (undef, undef) if $checked >= length $$msg;
            $comp_len = $cp - $offset if $comp_len == -1;
            $cp = ($n & 0x3f) << 8 + ord(substr($$msg, $cp, 1));
        } else {  # unknown (or extended) type
            return (undef, undef);
        }
    }
    $comp_len = $cp - $offset if $comp_len == -1;
    return ($result, $offset + $comp_len);
}

sub depack_packet
{
    my $buff = shift;
    my ($header, $question, $ptr);
    my $buff_len = length $buff;

    return '' if $buff_len <= $HEADERLEN;  # short packet, ignore it.

    $header   = substr($buff, 0, $HEADERLEN);
    $question = substr($buff, $HEADERLEN);
    $ptr      = $HEADERLEN;

    my ($id, $flags, $qdcount, $ancount, $aucount, $adcount) = unpack('n6C*', $header);

#    print "id=$id flags=$flags qdcount=$qdcount ancount=$ancount aucount=$aucount adcount=$adcount\n";

    my $opcode  = ($flags & $OP_MASK) >> 11;
    my $qr      = ($flags & $QR_MASK) >> 15;  # query/response
    return '' if $qr;  # should not be set on a query, ignore packet

    if ($opcode != 0) {
        $flags |= $QR_MASK | $AA_MASK | $NOTIMP;
        return pack('n6', $id, $flags, 1, 0, 0, 0) . $question;
    }

    my $qname;
    ($qname, $ptr) = dn_expand(\$buff, $ptr);
    #print "Qname = $qname\n";
    if (not defined $qname) {
        $flags |= $QR_MASK | $AA_MASK | $FORMERR;
        return pack('n6', $id, $flags, 1, 0, 0, 0) . $question;
    }
    
    my ($qtype, $qclass) = unpack('nn', substr($buff, $ptr, 4));
    $ptr += 4;
#    print "Qtype=$qtype QClass=$qclass\n";

    if ($ptr != $buff_len) {  # we are not at end of packet (we should be :-) )
        $flags |= $QR_MASK | $AA_MASK | $FORMERR;
        return pack('n6', $id, $flags, 1, 0, 0, 0) . $question;
    }

    if($qtype != 1 || $qclass != 1 || $qname !~ /rdp.local$/)
    {
      return pack('n6', $id, $flags, 1, 0, 0, 0) . $question;
    }

    $errorcode = "";
    $countrec = 0;

    &check_rdp_zone($qname) if ($qname =~ /.rdp.local$/);

    if($errorcode)
    {
      my $errorip = inet_ntoa( pack 'N', $errorcode ) if($conf{debug});
      &log("BLOCKR: Result for $qname has errorcode $errorip\n") if($conf{debug});
      
    }
    else
    {
      &log("BLOCKR: Result for $qname has no errorcode. Passing connection.\n") if($conf{debug});
    }

    $RCODE = ($countrec) ? $NOERROR : $NOSUCHNAME;

    $qname = lc($qname);
    my %dnsmsg = (
                  rcode   => $RCODE,
                  qdcount => $qdcount,
                  ancount => 0,
                  aucount => 0,
                  adcount => 0,
                  answer  => '',  # response sections
                  auth    => '',
                  add     => ''
                 );
    my $from = $sock->peerhost();

    my $FOUND = 1;

    if ($countrec)
    {
        $dnsmsg{ancount}=1;
        $dnsmsg{answer} = &create_answer(15,$errorcode);
        $flags |= $QR_MASK | $AA_MASK | $dnsmsg{rcode};
    } else {
        $flags |= $QR_MASK | $dnsmsg{rcode};
    }

# build the response packet, truncating if necessary
    my $reply = $question . $dnsmsg{answer} . $dnsmsg{auth} . $dnsmsg{add};

    if (length $reply > ($PACKETSZ - $HEADERLEN)) {
        $flags |= $TC_MASK;
        $reply = substr($reply, 0, ($PACKETSZ - $HEADERLEN));
    }

    return pack('n6', $id, $flags, $qdcount, $dnsmsg{ancount},
                $dnsmsg{aucount}, $dnsmsg{adcount}) . $reply;
#}

}
