xquery version "1.0-ml";
module namespace security-util = "security-util";

declare function security-util:createNewUser($markLogicUsername as xs:string, 
                                          $userPassword as xs:string,
                                          $userDescription as xs:string,
                                          $role as xs:string,
                                          $providerName as xs:string, 
                                          $providerUserId as xs:string,
                                          $securityDatabaseName as xs:string) 
{
    let $existingUsers := security-util:getExistingUsers()              
    return 
        if($markLogicUsername = $existingUsers) then 
            fn:concat("User ", $markLogicUsername, " already exists")
        else
            try {
                xdmp:eval(
                    fn:concat(
                    "xquery version '1.0-ml'; 
                    import module namespace sec='http://marklogic.com/xdmp/security' at '/MarkLogic/security.xqy';
                    sec:create-user('", $markLogicUsername, "', '", $userDescription, "', '", $userPassword, "', '", $role, "', (), ())"), (),
                    <options xmlns="xdmp:eval">
                        <database>{xdmp:database($securityDatabaseName)}</database> 
                    </options>)  
            } catch($e) {
                let $log := xdmp:log(fn:concat("FAILED TO CREATE USER. Error: ", $e/*:message[1]/text()))
                return "User could not be created!!"
            } 
                                      
};

declare function security-util:createNewUser($markLogicUsername as xs:string, 
                                          $userPassword as xs:string,
                                          $userDescription as xs:string,
                                          $role as xs:string,
                                          $providerName as xs:string, 
                                          $providerUserId as xs:string) 
{
    security-util:createNewUser($markLogicUsername, $userPassword, $userDescription, $role, $providerName, $providerUserId, "Security")   
};

(:~ 
 : Create a new role in the Security database for the given database
 : @param $roleName 
 : @param $description the role description
 : @param $securityDatabaseName
 :)
declare function security-util:createRole($roleName, $description, $securityDatabaseName as xs:string) 
{
    let $existingRoles := security-util:getExistingRoles()
               
    (: create the role :)    
    return 
        if($roleName = $existingRoles) then 
            fn:concat("Role ", $roleName, " already exists")
        else
            xdmp:eval(
                fn:concat(
                "xquery version '1.0-ml'; 
                import module namespace sec='http://marklogic.com/xdmp/security' at '/MarkLogic/security.xqy';
                sec:create-role('", $roleName, "', '", $description, "', (), (), ())"), (),
                <options xmlns="xdmp:eval"><database>{xdmp:database($securityDatabaseName)}</database> </options>)        
};

declare function security-util:createRole($roleName, $description)
{
    security-util:createRole($roleName, $description, "Security") 
};

(:~
 : Return the existing roles in the Security database
 :)
declare function security-util:getExistingRoles($securityDatabaseName as xs:string) 
{
    xdmp:eval(
        "xquery version '1.0-ml'; fn:data(/sec:role/sec:role-name)", (),
        <options xmlns="xdmp:eval"><database>{xdmp:database($securityDatabaseName)}</database> </options>)
};

declare function security-util:getExistingRoles() 
{
    security-util:getExistingRoles("Security") 
};



(:~
 : Return the existing users in the Security database
 :)
declare function security-util:getExistingUsers($securityDatabaseName as xs:string) 
{
    xdmp:eval(
        "xquery version '1.0-ml'; fn:data(/sec:user/sec:user-name)", (),
        <options xmlns="xdmp:eval"><database>{xdmp:database($securityDatabaseName)}</database> </options>)
};

declare function security-util:getExistingUsers() 
{
    security-util:getExistingUsers("Security")
};

declare function security-util:addRoleToRole($roleName, $roleToAdd, $securityDatabaseName as xs:string) 
{
    let $existingRoles := security-util:getRolesOfRole($roleName)
               
    return 
        if($roleName = $existingRoles) then 
            fn:concat("Role ", $roleName, " already has ", $roleToAdd, " role")
        else
            xdmp:eval(
                fn:concat(
                "xquery version '1.0-ml'; 
                import module namespace sec='http://marklogic.com/xdmp/security' at '/MarkLogic/security.xqy';
                sec:role-add-roles('", $roleName, "', '", $roleToAdd, "')"), (),
                <options xmlns="xdmp:eval"><database>{xdmp:database($securityDatabaseName)}</database> </options>)        
};

declare function security-util:addRoleToRole($roleName, $roleToAdd) 
{
    security-util:addRoleToRole($roleName, $roleToAdd, "Security") 
};

(:~
 : Return the existing roles in the Security database
 :)
declare function security-util:getRolesOfRole($roleName as xs:string, $securityDatabaseName as xs:string) 
{
    try {
    xdmp:eval(
        fn:concat(
        "xquery version '1.0-ml'; 
        import module namespace sec='http://marklogic.com/xdmp/security' at '/MarkLogic/security.xqy';
        sec:role-get-roles('", $roleName, "')"
        ), (),
        <options xmlns="xdmp:eval"><database>{xdmp:database($securityDatabaseName)}</database> </options>)
    } catch($err) {
        let $log := xdmp:log(fn:concat("Couldn't getRolesOfRole because Role ", $roleName, " doesn't exist! ", $err/*:message/text()))
        return ()
    }    
};

declare function security-util:getRolesOfRole($roleName as xs:string) 
{
    security-util:getRolesOfRole($roleName, "Security") 
};

(:~ 
 : Add a sequence of privileges to a role
 : @param $role the name of the role
 : @param $privs a sequence of privileges
 :)
declare function security-util:addPrivileges($role, $privs as item(), $securityDatabaseName as xs:string) 
{
    for $priv in $privs
    return xdmp:eval(
        fn:concat(
        "xquery version '1.0-ml'; 
        import module namespace sec='http://marklogic.com/xdmp/security' at '/MarkLogic/security.xqy';
        sec:privilege-add-roles( '", $priv, "', 'execute', ('", $role, "'))"
        ), (),
        <options xmlns="xdmp:eval"><database>{xdmp:database($securityDatabaseName)}</database> </options>)
};

declare function security-util:addPrivileges($role, $privs as item()) 
{
    security-util:addPrivileges($role, $privs, "Security") 
};
