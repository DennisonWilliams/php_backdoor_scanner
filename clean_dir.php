<?php
$config['source_directory'] = '/home/wordpress-base/source/wordpress-plugins.svn';

/*
$DIR = opendir($config['source_directory']);
if ($DIR === false) {
  print "wuh?\n";
  exit;
}

while (false !== ($entry = readdir($DIR))) {
  if (!is_dir($entry) || $entry == '.' || $entry == '..') {
    continue;
  }
  $fc = substr($entry, 0, 1);
  if (!is_dir($config['source_directory'] ."/$fc") &&
    !mkdir($config['source_directory'] ."/$fc")
  ) {
    print "Mo wah?\n";
    exit;
  }


  print "rename($entry, ". $config['source_directory'] ."/$fc/". basename($entry) .");\n";
  //rename($entry, $config['source_directory'] ."/$fc/". basename($entry));
}

closedir($DIR);
 */

$contents = scandir($config['source_directory']);
foreach($contents as $entry) {
  if (!is_dir($config['source_directory'] .'/'. $entry) || 
    $entry == '.' || 
    $entry == '..' ||
    strlen($entry) == 1) {
    continue;
  }

  $fc = substr($entry, 0, 1);
  if (!is_dir($config['source_directory'] ."/$fc") &&
    !mkdir($config['source_directory'] ."/$fc")
  ) {
    print "Mo wah?\n";
    exit;
  }


  print "rename(". $config['source_directory'] ."/$entry, ". $config['source_directory'] ."/$fc/". basename($entry) .");\n";
  rename($config['source_directory'] ."/$entry", $config['source_directory'] ."/$fc/". basename($entry));
}
