xquery version "1.0-ml";
let $split := fn:tokenize( xdmp:get-request-url(), "\?")
let $queryString := $split[2]
return xdmp:redirect-response( fn:concat("oauth2.xqy?provider=github&amp;", $queryString))