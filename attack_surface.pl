#!/usr/bin/perl


# a good testing site is: 
# http://www.wright.edu:80/ctl/dl/getelluminate.html
# http://10.10.10.254:88/foshizzle.html

use Socket;

# where we store all inputs and their default values
%MASTER = ();
# each of the variables of the form
@VARIABLES = ();
# each of the variables that we will test
@var_array = ();
# Cookie
$cookie = "";
# the app.  exampe, /cgi-bin/foo.cgi
$app = "";
# the value for "Host:" field 
$host = "";
# the remote host to test 
$remote = "";
# the hostname of the first site that is hosting the form
$referer = "";
# the port number
$port = "";
# an array of injectable chars
@injectable = ();
# an array of non-injectable chars
@noninjectable = ();
# bad characters
@bad_chars = ();
# the path.  for instance, if the form is at /a/b/c/order.php then the path is "/a/b/c/";
$path = "";
# set this to 1 if you wish to debug a form
$DEBUG = 0;
# display banner
$mybanner = "\n\nScript Injection Toolkit - by John Lampe\n\nThis script takes a form and walks through each of the form values, attempting to injection special characters into the HTML which is displayed after the form is submitted.  For example, if a form asks for a user name and you can inject angle brackets, right-leaning toothpicks, and quotation marks, then you can inject something like '<script>alert('hi')</script>'.  The characters which this script checks for are defined in as.conf.  Enjoy!\n\n\n";
# binary characters array
@binary_chars = ();
# hash where charcter is key to decimal value
%bchars = ();

system ("clear");
print "$mybanner";

$seed_url = shift;

if ($seed_url =~ /http:\/\/([^\:]+):([0-9]{1,5})(\/.*)/i)
{
	$remote = $1;
	$port = $2;
	$app = $3;
	if ($app =~ /^(\/.*\/)[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+/i)
	{
		$path = $1;
	}
	else
	{
		$path = "/";
	}
	$referer = $remote . $app;
}
else
{
  while ($seed_url eq "")
  {
	# www.foo.com:80/a/order.php
	print "Enter the URL to the form\n";
	chop($seed_url=<STDIN>);
	if ($seed_url =~ /http:\/\/([^\:]+):([0-9]{1,5})(\/.*)/i)
	{
		$remote = $1;
		$port = $2;
		$app = $3;
		if ($app =~ /^(\/.*\/)[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+/i)
		{
			$path = $1;
		}
		$referer = $remote . $app;
	}
	else
	{
		print "Enter url in the form http://<hostname>:<port>/<full path to form>\n";
		print "Exampe: ./attack_surface.pl http://www.mydomain.com:80/cgi-bin/foo.cgi\n";
		$seed_url = "";
	}
  }
}

print "Testing $app on $remote port $port\n";

if ($DEBUG)
{
	print_vars();
}

open (DEBUG,">DEBUG.txt");

#0) define an array of characters that you want to check, bad_chars()
open (IN, "as.conf") || die "What have you done with as.conf?\n";
while (<IN>)
{
	if ($_ =~ /^bad_chars:(.*)$/)
	{
		@bad_chars = split(//,$1);
	}
	if ($_ =~ /user_agent:(.*)$/)
	{
		$user_agent = $1;
		$user_agent =~ s/\r|\n//;
	}
	# binary_chars:0x00
	if ($_ =~ /^binary_chars:(.*)$/)
	{
		@tchars = split(/\,/,$1);
		foreach $t (@tchars)
		{
			if ($t =~ /0x([0-9A-F]+)/)
			{
				$uni = "\%" . $1;
				push (@binary_chars,$uni);
			}
		}
	}
}
close (IN);

if (length($user_agent) <= 0)
{
	$user_agent = "User-Agent: AS.pl 1.0";
}

#1) read the form and get all the inputs.  Store any cookie info
$query = "GET $app HTTP/1.0\r\nHost: $remote\r\n$user_agent\r\nAccept: */*\r\nAccept-Ranges: bytes\r\n\r\n";
$ret = http_get($query);


if ($DEBUG)
{
        print_vars();
}



#2) get default values for each input
@def_values = get_inputs($ret);
$method = uc($def_values[0]);
$action = $def_values[1];

if ($DEBUG)
{
        print_vars();
}



# if action is to some other site, adjust host and action here
if ($action =~ /http:\/\/([^\/:]+)(\/.*)/i)
{
	$host = $1;
	$app =	$2;
	$remote = $host;
	print "Changing \$remote to $remote and \$app to $app\n";
	print "Is the following host and app within scope of this scan (y or n)?\n";
	chop ($ans=<STDIN>);
	if ($ans eq "n")
	{
		exit(0);
	}
}
elsif ($action =~ /http:\/\/([^\/]+):([0-9]{1,5})(\/.*)/i)
{
	$host = $1;
	$port = $2;
	$app = $3;
	$remote = $host;
	print "Changing \$remote to $remote and \$port to $port and \$app to $app\n";
        print "Is the following host and app within scope of this scan (y or n)?\n";
        chop ($ans=<STDIN>);
        if ($ans eq "n")
        {
                exit(0);
        }
}
else
{
	$app = $action;
	print "Getting ready to test $remote on port $port at the following path $app\n";
}

if ($DEBUG)
{
        print_vars();
}


# determine what type of query string we are creating
if ($method eq "POST")
{
	$query = "";
}
elsif ($method eq "GET")
{
	$query = "GET $app?";
}
else
{
	print "Error with method : $method\n";
	exit(0);
}


#3) one input at a time, inject a 'f00' (or similar string)
#       - submit the form

$variable_count = keys %MASTER;
$counter=1;
$live=0;

for ($i=0; defined($VARIABLES[$i]) ; $i++)
{ 
  foreach $value (@VARIABLES)
  {
	if ($DEBUG)
	{
		print "DEBUG - Evaluating $value\n";
	}
	if ($value eq $VARIABLES[$i])
	{
		$query = $query . "$value=fl00z3y" . $counter . "ey";
        	if ($counter < $variable_count)
        	{
                    $query .= "&";
        	}
	}
	else
	{
		$query = $query . $value . "=" . $MASTER{$value};
		if ($counter < $variable_count)
		{
		     $query .= "&";
		}
	}
	$counter++;
  }
  if ($method eq "POST")
  {
	$query = finalize_query($query);
  }
  elsif ($method eq "GET")
  {
	$query = prep_query($query);
  }

  $ret = http_get($query);

  if ($DEBUG)
  {
	print_vars();
  }

  # look for 'fl00z3y' in the return
  if ($ret =~ /fl00z3y([0-9]+)ey/)
  {
	$num = $1;
	push ( @var_array, $VARIABLES[$i] );
	$live++;
  }
  if ($method eq "POST")
  {
        $query = "";
  }
  elsif ($method eq "GET")
  {
        $query = "GET $app?";
  }
  $counter = 1;
  $ret = "";
}





if ($live == 0)
{
	print "None of our injected variables is present in the submitted form\n";
  	if ($DEBUG)
  	{
        	print_vars();
  	}
	exit(0);
}

if ($DEBUG == 0)
{
	system("clear");
}

print "\n\nProceeding with injection checks ...\n\n\n";


#4) foreach value in check_array
#	- foreach value in bad_chars
#		- submit the form with only the inspected value changing to something like f00<bad_char>f00
#		- parse the return looking for f00<bad_char>f00
#		- if f00<bad_char>f00 add character to @injectable
#		- if not f00<bad_char>f00 add character to @noninjectable = (); 


$counter=1;

for ($z=0; defined($bad_chars[$z]); $z++)
{
  $mybadchar = $bad_chars[$z]; 
  for ($i=0; defined($var_array[$i]) ; $i++)
  {
    foreach $value (@VARIABLES)
    {
        if ($value eq $var_array[$i])
        {
                $query = $query . "$value=fl00" . $mybadchar . "zey";
                if ($counter < $variable_count)
                {
                    $query .= "&";
                }
        }
        else
        {
                $query = $query . $value . "=" . $MASTER{$value};
                if ($counter < $variable_count)
                {
                     $query .= "&";
                }
        }
        $counter++;
    }
    if ($method eq "POST")
    {
        $query = finalize_query($query);
    }
    elsif ($method eq "GET")
    {
        $query = prep_query($query);
    }

    $ret = http_get($query);
    if ($DEBUG)
    {
        print_vars();
    }

    # look for 'fl00zey' in the return
    if ($mybadchar =~ /\@|\$|\%|\^|\&|\*|\(|\)|\+|\-|\\|\{|\}|\[|\]|\;|\?|\.|\//)
    {
	$regex = "fl00(" . "\\" . $mybadchar . ")zey";
    }
    else
    {
	$regex = "fl00(" . $mybadchar . ")zey"; 
    }

    if ($ret =~ /$regex/)
    {
        $num = $1;
	$tstring = "$var_array[$i]" . ":" . $num;
        push ( @injectable, $tstring );
	$tstring = "";
    }
    else
    {
	$tstring = "$var_array[$i]" . ":" . $mybadchar;
	push (@noninjectable, $tstring);
    }

    if ($ret =~ /(sql|odbc)/i)
    {
	print DEBUG "DEBUG : \$ret is $ret\n\n";				#remove remove remove
	$tstring = "$var_array[$i]" . ":" . $num;
	push (@SQL,$tstring);
	$tstring = "";
    }

    if ($method eq "POST")
    {
        $query = "";
    }
    elsif ($method eq "GET")
    {
        $query = "GET $app?";
    }
    $counter = 1;
    $ret = "";
  }
}






# now do the same for binary_chars

$counter=1;

for ($z=0; defined($binary_chars[$z]); $z++)
{
  $mybadchar = $binary_chars[$z] ;
  for ($i=0; defined($var_array[$i]) ; $i++)
  {
    foreach $value (@VARIABLES)
    {
        if ($value eq $var_array[$i])
        {
                $query = $query . "$value=fl00" . $mybadchar . "zey";
                if ($counter < $variable_count)
                {
                    $query .= "&";
                }
        }
        else
        {
                $query = $query . $value . "=" . $MASTER{$value};
                if ($counter < $variable_count)
                {
                     $query .= "&";
                }
        }
        $counter++;
    }
    if ($method eq "POST")
    {
        $query = finalize_query($query);
    }
    elsif ($method eq "GET")
    {
        $query = prep_query($query);
    }

    $ret = http_get($query);
    if ($DEBUG)
    {
        print_vars();
    }

    # look for 'fl00zey' in the return

    $regex = "fl00\(\\" . "$mybadchar" . "\)zey";
    if ($ret =~ /$regex/)
    {
        $num = $1;
        $tstring = "$var_array[$i]" . ":" . $mybadchar;
        push ( @injectable, $tstring );
        $tstring = "";
    }
    elsif ($ret =~ /fl00(.+)zey/)
    {
	$num = $1;
	$tstring = "We sent $mybadchar and it was replaced with a character of size " . length($num) . "\n";
	push (@INCIDENTAL,$tstring);
	$tstring = "";
    }
    elsif ($ret =~ /fl00zey/)
    {
	$tstring = "We sent $mybadchar and it was replaced with NULL\n";
	push (@INCIDENTAL,$tstring);
        $tstring = "";
    }


    if ($ret =~ /(sql|odbc)/i)
    {
        $tstring = "$var_array[$i]" . ":" . $num;
        push (@SQL,$tstring);
        $tstring = "";
    }

    if ($method eq "POST")
    {
        $query = "";
    }
    elsif ($method eq "GET")
    {
        $query = "GET $app?";
    }
    $counter = 1;
    $ret = "";
  }
}






#5) report on attack surface 

open (OUT, ">REPORT.txt");
select(OUT);

print "REPORT for $seed_url:\n\nGenerated by the Attack surface detection tool (ASDT) - http://www.aceryder.com/ASDT.html\n\n\n";
print "Injectable chars:\n";
foreach $k (@var_array)
{
	print "$k : ";
	foreach $v (@injectable)
	{
		if ($v =~ /$k:(\%[A-F0-9]{2})/)
		{
			print $1 . " ";
		}
		elsif ($v =~ /$k:(.)/)
		{
			print $1 . " ";
		}
	}
	print "\n";
}

print "\n\nNon-injectable chars:\n";
foreach $k (@var_array)
{
        print "$k : ";
        foreach $v (@noninjectable)
        {
                if ($v =~ /$k:(.)/)
                {
                        print $1 . " ";
                }
        }
	print "\n";
}

print "\n\nVariables which were not at all vulnerable to replay injection attacks:\n";
foreach $k (@VARIABLES)
{
	$found = 0;
	foreach $v (@var_array)
	{
		if ($v eq $k)
		{
			$found++;
		}
	}
	if ($found == 0)
	{
		print "$k, ";
	}
}


print "\n\nVaraibles which seemed to generate some sort of SQL error:\n";
foreach $k (@var_array)
{
	print "$k : ";
	foreach $v (@SQL)
	{
		if ($v =~ /$k:(.)/)
		{
			print $1 . " ";
		}
	}
	print "\n";
}

print "\n\n\n\n";



print "\n\nIncidental messages\n";
foreach $k (@INCIDENTAL)
{
	print "$k";
}

close (DEBUG);
close(OUT);
select(STDOUT);
print "Report is in REPORT.txt\n";











# Subs



sub print_vars
{
        print "DEBUG: \@MASTER\n";
        foreach $m (@MASTER) {print "$m\n";}
        print "\n\n";
        print "DEBUG: \@VARIABLES\n";
        foreach $m (@VARIABLES) {print "$m\n";}
        print "\n\n";
        print "DEBUG: \@var_array\n";
        foreach $m (@var_array) {print "$m\n";}
        print "\n\n";
        print "DEBUG: \$cookie : '$cookie'\n";
        print "DEBUG: \$app : '$app'\n";
        print "DEBUG: \$host : '$host'\n";
        print "DEBUG: \$remote : '$remote'\n";
        print "DEBUG: \$referer : '$referer'\n";
        print "DEBUG: \$port : '$port'\n";
        print "DEBUG: \@injectable\n";
        foreach $m (@injectable) {print "$m\n";}
        print "\n\n";
        print "DEBUG: \@noninjectable\n";
        foreach $m (@noninjectable) {print "$m\n";}
        print "\n\n";
        print "DEBUG: \@bad_chars\n";
        foreach $m (@bad_chars) {print "$m\n";}
        print "\n\n";
        print "DEBUG: \$path : '$path'\n";
        print "DEBUG: \$query : '$query'\n";
        print "DEBUG: \$ret : '$ret'\n";
        print "DEBUG: \$method : '$method'\n";
        print "DEBUG: \$action : '$action'\n";
}



sub prep_query
{
	# handles GET queries
	my $temp_query = shift;
        $temp_query .= " HTTP/1.0\r\nHost: $remote\r\n$user_agent\r\nAccept-Ranges: bytes\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip,deflate\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\nContent-Type: text/plain\r\n";
        if (length($cookie) > 0)
        {
                $temp_query .= "Cookie: $cookie\r\n\r\n";
        }
        else
        {
                $temp_query .= "\r\n";
        }
	return ($temp_query);
} 


sub finalize_query
{
	# handles POST queries
	my $temp_query = shift;
	my $plen = length($temp_query);
	my $ret = "POST $app HTTP/1.0\r\nHost: $remote\r\n$user_agent\r\nAccept: */*\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Ranges: bytes\r\nAccept-Encoding: gzip,deflate\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\nKeep-Alive: 300\r\nConnection: keep-alive\r\nReferer: $referer\r\n";
	if (length($cookie) > 0)
        {
                $ret .= "Cookie: $cookie\r\n";
        }
	$ret .= "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: $plen\r\n\r\n$temp_query";	
}



sub http_get
{
	alarm(30);
	my $req = shift;
        my ($return, $tmp, $p, $bytes_read, $iaddr, $piaddr, $proto);
	$p = $port;
        if ($p =~ /\D/) 
	{ 
		$p = getservbyname($port, 'tcp'); 
	}
        die "No port" unless $p;
        $iaddr   = inet_aton($remote)  || die "Error with remote:$remote. $!\n";
        $piaddr   = sockaddr_in($p, $iaddr);
        $proto   = getprotobyname('tcp');
        socket(SOCK, PF_INET, SOCK_STREAM, $proto)  || die "socket: $!";
        connect(SOCK, $piaddr) || die "connect: $!";
        select (SOCK);
        $|=1;
        print "$req";
        while (($bytes_read = read(SOCK, $tmp, 1024)) > 0)
        {
                $return .= $tmp;
                $tmp = "";
        }
        select(STDOUT);
        close (SOCK) || die "close: $!";
	alarm(0);

	# save out the cookie
	$cookie_temp = check_cookie($return);
	if (length($cookie_temp) > 0)
	{
        	$cookie = $cookie_temp;
		if ($DEBUG)
		{
        		print "Set Cookie to $cookie\n";
		}
	}

        return ($return);
} 




sub get_inputs
{
   my $total_ret = shift;
   my ($form,$method,$action,$t,$defaultvalue);
   my @trray = ();
   my @tformz = ();
   my $form_count, $qq, $ans;

   #@trray = split(/\r|\n/,$total_ret);
   #foreach $qq (@trray)
   #{
   #	if ($qq =~ /<\s*form/i)
#	{
#		print "f00 - \$1 is $1\n";
#		push (@tformz,$1);
#		$form_count++;
#	}
 #  }

   #my $tcount = 0;
   #if ($form_count > 1)
   #{
#	foreach $qq (@tformz)
 #  	{
  #      	print "$tcount : $qq\n\n";
#	}
#	print "Enter which form you want to test\n";
#	chop ($ans=<STDIN>);
 #  }

   $total_ret =~ s/\r|\n/ /g;
   print "f00 - in get_inputs()\n";

   if ($total_ret =~ /.*(<\s*form[^>]+(method\s*=\s*[\'\"](get|post)[\'\"]|action\s*=\s*[\'\"]([^\'\"]+)[\'\"]).*<\s*\/\s*form\s*>).*/i)
   {
	$form = $1;
	print "f00 - setting \$form to $form\n\n";
   }

   # <FORM method=post action=order.php value1=foo value2=3>
   # <form action="checkout.php" method=post name=form onsubmit="return frmcheck();">
   if ($form =~ /method\s*=\s*[\'\"]?(get|post)/i)
   {
       $method = $1;
       push (@trray,$method);
       print "f00 - setting \$method to $method\n";
   }
   if ($form =~ /action\s*=\s*[\'\"]?([^\'\">\s]+)/i)
   {
	$action = $1;
	if ($action !~ /^\//)
	{
		$action = $path . $action; 
		print "f00 - setting \$action to $action\n";
	}
	push (@trray,$action);
   }

   if ( ($method eq "") || ($action="") )
   {
  	print "Error with method or action\n";
	exit(0);
   }

   my @tmprray = split(/</,$form);
   foreach $t (@tmprray)
   {
       # <input name="bill_first_name" type="text" id="bill_first_name" style="WIDT
       # <select name="bill_state" title="This field refers to the state in which you live.">
       if ($t =~ /.*input.*name=\s*[\'\"]?([^\'\">\s]+)/i)
       {
          $in = $1;
	  print "f00 - setting \$in to $in\n";

	  $defaultvalue = "";
	  if ($t =~ /value\s*=\s*[\'\"]?([^\'\">\s]+)/i)
	  {
		$defaultvalue = $1;
	  }

	  if (! $MASTER{$in} )
	  {
	  	print "Enter a default value for $in as defined in:\n$t\n";
		print "Note: Enter '{NULL}' if you do not wish to use the value.  Enter 'dd' to use the default\n";
	  	chop ($ans=<STDIN>);
		if ($ans !~ /\{NULL\}/)
		{
			if ( ($ans eq "dd") && (length($defaultvalue) > 0) )
			{
				$MASTER{$in} = $defaultvalue;
				push (@VARIABLES,$in);
			}
			else
			{
     	  			$MASTER{$in} = $ans;
				push (@VARIABLES,$in);
			}
		}
	  }
       }
       if ($t =~ /.*select.*name=\s*[\'\"]?([^\'\">\s]+)/i)
       {
          $in = $1;

	  $defaultvalue = "";
          if ($t =~ /value\s*=\s*[\'\"]?([^\'\">\s]+)/i)
          {
                $defaultvalue = $1;
          }

          if (! $MASTER{$in} )
          {
                print "Enter a default value for $in as defined in:\n$t\n";
                print "Note: Enter '{NULL}' if you do not wish to use the value.  Enter 'dd' to use the default\n";
                chop ($ans=<STDIN>);
                if ($ans !~ /\{NULL\}/)
                {
			if ( ($ans eq "dd") && (length($defaultvalue) > 0) )
                        {
				$MASTER{$in} = $defaultvalue;
				push (@VARIABLES,$in);
                        }
			else
			{
                        	$MASTER{$in} = $ans;
                        	push (@VARIABLES,$in);
			}
                }
          }
       }

   }
   return (@trray); 
}



sub check_cookie
{
	# Set-Cookie: DOM=www.entertalk.com:3491291802; path=/
	# Set-Cookie: AFF=1689806621; path=/
	# Set-Cookie: PAGE=1426447528; path=/
	my $headers = shift;
	my %cookie_hash = ();
	my ($t,$u,$v, $returncookie,$cntr);
	my @cookie_vals = ();
	
	my @terray = split(/\;/,$cookie);
	foreach $t (@terray)
	{
		if ($t =~ /^\s*([^\s]+)/)
		{
			$t = $1;
		}
		($u,$v) = split(/=/,$t);
		if (! defined($cookie_hash{$u}) )
		{
			push (@cookie_vals , $u);
			$cookie_hash{$u} = $v;
		}
	}

	@cookie_temp_rray = split(/\n/,$headers);
	foreach $c (@cookie_temp_rray)
	{
		if ($c =~ /^Set-Cookie: (.*)/)
		{
			$retval = $1;
			if (length($retval) > 0)
			{
				my @terray = split(/\;/,$retval);
				foreach $t (@terray)
				{
					if ($t =~ /^\s*([^\s]+)/)
					{
						$t = $1;
					}
					($u,$v) = split(/=/,$t);
					if (! defined($cookie_hash{$u}) )
					{
						push (@cookie_vals , $u);
					}
					$cookie_hash{$u} = $v;
				}
			}
		}
	}
	$cntr = 0;
	foreach $t (@cookie_vals)
	{
		$returncookie = $returncookie . "$t" . "=" . $cookie_hash{$t} ;	
		if (defined($cookie_vals[$cntr + 1]) )
		{
			$returncookie .= "\; "
		}
		$cntr++;
	}
	return ($returncookie);
}




sub decimal
{
	my $d = shift;
	my %convert = qw(0 0 1 1 2 2 3 3 4 4 5 5 6 6 7 7 8 8 9 9 A 10 B 11 C 12 D 13 E 14 F 15);
	if ($d =~ /^0x([0-9A-F])([0-9A-F])$/)
	{
		my $h = $1;
		my $l = $2;
		my $dec = ($convert{$h} * 16) + $convert{$l};
		return($dec);
	}
	else
	{
		print "Error with format\nCheck your binary_chars array\n";
		exit(0);
	}
}



