<?php
/**
 * @Author: Lock
 * @Date:   2015-08-09 14:42:58
 * @Last Modified time: 2015-08-09 14:44:21
 */

echo 'Test one , PHP bug';
var_dump([0 => 0] === [0x100000000 => 0]); 

echo 'Test two , Coder Ignore Question';
echo "<br/>";
$var="20070601";
if (intval($var))
echo "it's safe";
echo '$var='.$var;
echo "<br>";
$var1="1 union select 1,1,1 from admin";
if (intval($var1))
echo "it's safe too";
echo '$var1='.$var1;