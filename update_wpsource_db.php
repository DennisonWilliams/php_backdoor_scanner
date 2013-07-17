<?php
$config['source_directory'] = '/home/wordpress-base/source/wordpress-plugins.svn';
$config['source_directory_tarball'] = '/home/wordpress-base/source/wordpress-plugins.svn.tgz';

// Check to see if the source directory exists
// If not check to see if the tar ball of it exists
if (!is_dir($config['source_directory']) && file_exists($config['source_directory_tarball'])) {
  print "The source directory ". $config['source_directory'] ."was not found, but a tarball ".
    "of it was (". $config['source_directory_tarball'] .").\n";
  $sdir = dirname($config['source_directory']);

  if (!is_dir($sdir)) {
    print "Creating directory $dir.\n";
    system('/bin/mkdir -p '. $dir);
  }

  // if so unpack it
  print "Unpacking the tarball (". $config['source_directory_tarball'] .").\n";
  system('cd '. $dir .';/usr/bin/tar -zxvf '. $config['source_directory_tarball']);
  if (!is_dir($config['source_directory'])) {
    print "We found the source tarbal, and extracted it, but it did not ".
      "end up in ". $config['source_directory'] ."\n";
    exit;
  } else if (!is_dir($config['source_directory'])) {
    print "There was no backup of the wordpress source and no directory to work from.\n";
    print "Making the working directory (". $config['source_directory'] .").\n";
    if (!mkdir($config['source_directory'])) {
      print "There was a problem creating the source directory: ". 
        $config['source_directory'] ."\n";
      exit;
    }
  }
}

// Get a list of all wordpress plugins
$sdir = dirname($config['source_directory']);

print "Getting a list of all wordpress plugins from svn.\n";
//system('/usr/local/bin/svn ls http://plugins.svn.wordpress.org/ > '. $sdir .'/plugins.txt');
$handle = fopen($sdir .'/plugins.txt', 'r');
if ($handle === false) {
  print "Could not opt plugins file $dir/plugins.txt\n";
  exit;
}

chdir($config['source_directory']);
// For each plugin check to see if it exists in the source directory
$firstletter = '';
while ($line = fgets($handle)) {
  print "line: $line\n";
  $line = rtrim($line);

  // We organize sub directories by first character
  $fc = substr($line, 0, 1);
  if (!is_dir($config['source_directory'] .'/'. $fc) &&
    !mkdir($config['source_directory'] .'/'. $fc)) {
    print "There was a problem creating the source directory: ". 
      $config['source_directory'] ."/$fc\n";
    exit;
    }
  chdir($config['source_directory'] .'/'. $fc);

  // if not check it out
  if (!is_dir($config['source_directory'] .'/'. $fc .'/'. $line)) {
    print "$line does not exist, checking it out.\n";
    system('/usr/local/bin/svn --ignore-externals co http://plugins.svn.wordpress.org/'. $line);
  } else {
    print "Updating $line.\n";
    // if so cd into the directory and then svn up
    chdir($config['source_directory'] ."/$fc/". $line);
    $result = shell_exec('/usr/local/bin/svn cleanup 2>&1');
    print "\$result: $result\n";
    if (preg_match('/is not a working copy directory/', $result)) {
      system("rm -rf ". $config['source_directory'] .'/'. $line);
      chdir($config['source_directory'] ."/$fc/");
      system('/usr/local/bin/svn --ignore-externals co http://plugins.svn.wordpress.org/'. $line);
    } else {
      system('/usr/local/bin/svn --ignore-externals up');
    }
    chdir($config['source_directory']);
  }
}

// run the script to update the sha1sums
print "TODO: update the sha1sums.\n";
