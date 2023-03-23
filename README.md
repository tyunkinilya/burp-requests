Copy as (json-formatted) requests plugin for Burp Suite
======================================

Copies selected request(s) as Python [requests][1] invocation.

Building
--------

 - Download the [burp-extender-api.jar][2] and put it to the `burp-requests` folder.
 - Execute `ant`, and you'll have the plugin ready in `burp-requests.jar`

Dependencies
------------

 - JDK 1.7+ (tested on OpenJDK `1.7.0_85`, Debian/Ubuntu package: `openjdk-7-jdk`)
 - Apache ANT (Debian/Ubuntu package: `ant`)

License
-------

The whole project is available under MIT license, see `LICENSE.txt`,
except for the [Mjson library][3], where

> The source code is a single Java file. [...] Some of it was ripped
> off from other projects and credit and licensing notices are included
> in the appropriate places. The license is Apache 2.0.

  [1]: http://docs.python-requests.org/
  [2]: https://mvnrepository.com/artifact/net.portswigger.burp.extender/burp-extender-api
  [3]: https://bolerio.github.io/mjson/
  [4]: https://stackoverflow.com/questions/13592236/parse-a-uri-string-into-name-value-collection/58017826#58017826
